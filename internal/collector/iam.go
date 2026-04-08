package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

type mfaDeviceLister interface {
	ListMFADevices(ctx context.Context, userName string) ([]aws.MFADevice, error)
}

// collectIAMMetrics collects IAM-related security metrics.
func (c *Collector) collectIAMMetrics(ctx context.Context, client *aws.AWSClient, accountID string) (*IAMMetrics, error) {
	metrics := &IAMMetrics{}

	// Get credential report
	report, err := client.GetCredentialReport(ctx)
	if err != nil {
		return metrics, fmt.Errorf("getting credential report: %w", err)
	}

	// Process credential report
	c.processCredentialReport(report, metrics)
	metrics.HardwareMFAEnabled = c.collectHardwareMFAMetrics(ctx, client, report, accountID)

	return metrics, nil
}

// processCredentialReport analyzes the credential report and populates user metrics.
func (c *Collector) processCredentialReport(report *aws.CredentialReport, metrics *IAMMetrics) {
	now := time.Now()
	keyRotationThreshold := now.AddDate(0, 0, -AccessKeyAgeThreshold)

	var stats userStats

	for _, user := range report.Users {
		if user.IsRootUser() {
			c.processRootUser(user, metrics)
			continue
		}
		c.processIAMUser(user, keyRotationThreshold, &stats)
	}

	// Calculate percentages
	metrics.IAMUsersPresent = stats.totalUsers > 0
	metrics.MFAEnabled = mfaEnabledPercent(stats.mfaEnabled, stats.totalUsers)
	metrics.AccessKeysRotated = accessKeyRotationPercent(stats.keysRotated, stats.usersWithKeys)
}

// collectHardwareMFAMetrics checks each IAM user's MFA device type.
// Hardware MFA includes physical OTP devices and FIDO/U2F security keys.
func (c *Collector) collectHardwareMFAMetrics(ctx context.Context, client mfaDeviceLister, report *aws.CredentialReport, accountID string) int {
	totalUsers := 0
	hardwareMFAUsers := 0

	for _, user := range report.Users {
		if user.IsRootUser() {
			continue
		}

		totalUsers++
		if !user.MFAActive {
			continue
		}

		devices, err := client.ListMFADevices(ctx, user.User)
		if err != nil {
			c.warn("account %s: failed to list MFA devices for IAM user %s: %v", accountID, user.User, err)
			continue
		}

		if hasHardwareMFADevice(devices) {
			hardwareMFAUsers++
		}
	}

	return hardwareMFAEnabledPercent(hardwareMFAUsers, totalUsers)
}

// userStats tracks counts during credential report processing.
type userStats struct {
	totalUsers    int
	mfaEnabled    int
	keysRotated   int
	usersWithKeys int
}

// processRootUser extracts root account metrics.
func (c *Collector) processRootUser(user aws.CredentialReportUser, metrics *IAMMetrics) {
	metrics.RootMFAEnabled = user.MFAActive
	metrics.RootAccessKeysExist = user.HasAccessKeys()
}

// processIAMUser analyzes a single IAM user and updates stats.
func (c *Collector) processIAMUser(user aws.CredentialReportUser, keyRotationThreshold time.Time, stats *userStats) {
	stats.totalUsers++

	if user.MFAActive {
		stats.mfaEnabled++
	}

	if user.AccessKey1Active || user.AccessKey2Active {
		stats.usersWithKeys++
		if hasRotatedKeys(user, keyRotationThreshold) {
			stats.keysRotated++
		}
	}
}

// hasRotatedKeys checks if all active access keys have been rotated within the threshold.
func hasRotatedKeys(user aws.CredentialReportUser, threshold time.Time) bool {
	if user.AccessKey1Active {
		if user.AccessKey1LastRotated == nil || user.AccessKey1LastRotated.Before(threshold) {
			return false
		}
	}
	if user.AccessKey2Active {
		if user.AccessKey2LastRotated == nil || user.AccessKey2LastRotated.Before(threshold) {
			return false
		}
	}
	return true
}

// mfaEnabledPercent treats accounts with no IAM users as fully compliant.
// MFA requirements only apply when console users exist.
func mfaEnabledPercent(mfaEnabled, totalUsers int) int {
	if totalUsers == 0 {
		return MaxPercentage
	}
	return percent(mfaEnabled, totalUsers)
}

// accessKeyRotationPercent treats accounts with no active access keys as fully compliant.
// Rotation requirements only apply when keys exist.
func accessKeyRotationPercent(keysRotated, usersWithKeys int) int {
	if usersWithKeys == 0 {
		return MaxPercentage
	}
	return percent(keysRotated, usersWithKeys)
}

// hardwareMFAEnabledPercent treats accounts with no IAM users as fully compliant.
func hardwareMFAEnabledPercent(hardwareMFAUsers, totalUsers int) int {
	if totalUsers == 0 {
		return MaxPercentage
	}
	return percent(hardwareMFAUsers, totalUsers)
}

// hasHardwareMFADevice returns true if any assigned device is a hardware MFA device.
func hasHardwareMFADevice(devices []aws.MFADevice) bool {
	for _, device := range devices {
		if isHardwareMFASerial(device.SerialNumber) {
			return true
		}
	}
	return false
}

// isHardwareMFASerial classifies IAM MFA device serials.
// Virtual MFA devices use the IAM :mfa/ ARN prefix; hardware OTP devices use
// vendor serials, and FIDO/U2F devices use the IAM :u2f/ ARN prefix.
func isHardwareMFASerial(serial string) bool {
	if serial == "" {
		return false
	}
	return !strings.Contains(serial, ":mfa/")
}

// hasExternalTrust checks if a role's trust policy allows external accounts.
func hasExternalTrust(policyDoc string, currentAccount string) bool {
	if policyDoc == "" {
		return false
	}

	decoded, err := url.QueryUnescape(policyDoc)
	if err != nil {
		return false
	}

	var policy trustPolicy
	if err := json.Unmarshal([]byte(decoded), &policy); err != nil {
		return false
	}

	for _, stmt := range policy.Statement {
		if stmt.Effect != TrustPolicyEffectAllow {
			continue
		}
		if hasExternalPrincipal(stmt.Principal, currentAccount) {
			return true
		}
	}

	return false
}

// trustPolicy represents an IAM trust policy document.
type trustPolicy struct {
	Statement []trustStatement `json:"Statement"`
}

// trustStatement represents a single statement in a trust policy.
type trustStatement struct {
	Effect    string `json:"Effect"`
	Principal any    `json:"Principal"`
}

// hasExternalPrincipal checks if the principal field contains external accounts.
func hasExternalPrincipal(principal any, currentAccount string) bool {
	for _, p := range extractPrincipals(principal) {
		if p == TrustPolicyPrincipalAll {
			return true
		}
		if strings.HasPrefix(p, TrustPolicyARNPrefix) {
			parts := strings.Split(p, ":")
			if len(parts) >= 5 && parts[4] != currentAccount {
				return true
			}
		}
	}
	return false
}

// extractPrincipals extracts principal strings from the Principal field.
func extractPrincipals(principal any) []string {
	switch p := principal.(type) {
	case string:
		return []string{p}
	case map[string]any:
		var result []string
		for _, v := range p {
			switch val := v.(type) {
			case string:
				result = append(result, val)
			case []any:
				for _, item := range val {
					if s, ok := item.(string); ok {
						result = append(result, s)
					}
				}
			}
		}
		return result
	}
	return nil
}
