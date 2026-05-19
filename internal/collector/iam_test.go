package collector

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

type fakeMFADeviceLister struct {
	devices map[string][]aws.MFADevice
	errs    map[string]error
}

func (f fakeMFADeviceLister) ListMFADevices(_ context.Context, userName string) ([]aws.MFADevice, error) {
	if err, ok := f.errs[userName]; ok {
		return nil, err
	}
	return f.devices[userName], nil
}

func TestHasRotatedKeys(t *testing.T) {
	now := time.Now()
	threshold := now.AddDate(0, 0, -AccessKeyAgeThreshold)
	recent := now.AddDate(0, 0, -30)
	old := now.AddDate(0, 0, -120)

	if hasRotatedKeys(aws.CredentialReportUser{
		AccessKey1Active:      true,
		AccessKey1LastRotated: &recent,
	}, threshold) != true {
		t.Fatalf("expected recent active key to be considered rotated")
	}

	if hasRotatedKeys(aws.CredentialReportUser{
		AccessKey1Active:      true,
		AccessKey1LastRotated: &old,
	}, threshold) != false {
		t.Fatalf("expected old active key to be considered unrotated")
	}

	if hasRotatedKeys(aws.CredentialReportUser{
		AccessKey1Active: true,
	}, threshold) != false {
		t.Fatalf("expected nil key rotation timestamp to be unrotated")
	}
}

func TestProcessCredentialReport(t *testing.T) {
	now := time.Now()
	recent := now.AddDate(0, 0, -30)
	old := now.AddDate(0, 0, -120)

	report := &aws.CredentialReport{
		Users: []aws.CredentialReportUser{
			{
				User:             "<root_account>",
				MFAActive:        true,
				AccessKey1Active: false,
				AccessKey2Active: false,
			},
			{
				User:                  "alice",
				MFAActive:             true,
				AccessKey1Active:      true,
				AccessKey1LastRotated: &recent,
			},
			{
				User:                  "bob",
				MFAActive:             false,
				AccessKey1Active:      true,
				AccessKey1LastRotated: &old,
			},
		},
	}

	c := &Collector{}
	metrics := &IAMMetrics{}
	c.processCredentialReport(report, metrics)

	if !metrics.IAMUsersPresent {
		t.Fatalf("expected IAMUsersPresent=true")
	}
	if metrics.MFAEnabled != 50 {
		t.Fatalf("expected MFAEnabled=50, got %d", metrics.MFAEnabled)
	}
	if metrics.AccessKeysRotated != 50 {
		t.Fatalf("expected AccessKeysRotated=50, got %d", metrics.AccessKeysRotated)
	}
	if !metrics.RootMFAEnabled {
		t.Fatalf("expected RootMFAEnabled=true")
	}
	if metrics.RootAccessKeysExist {
		t.Fatalf("expected RootAccessKeysExist=false")
	}
}

func TestProcessCredentialReport_NoActiveAccessKeys(t *testing.T) {
	report := &aws.CredentialReport{
		Users: []aws.CredentialReportUser{
			{
				User:             "<root_account>",
				MFAActive:        true,
				AccessKey1Active: false,
				AccessKey2Active: false,
			},
			{
				User:            "alice",
				MFAActive:       true,
				PasswordEnabled: true,
			},
			{
				User:      "bob",
				MFAActive: false,
			},
		},
	}

	c := &Collector{}
	metrics := &IAMMetrics{}
	c.processCredentialReport(report, metrics)

	if metrics.AccessKeysRotated != 100 {
		t.Fatalf("expected AccessKeysRotated=100 when no active access keys exist, got %d", metrics.AccessKeysRotated)
	}
}

func TestMFAEnabledPercent(t *testing.T) {
	// No users = 100% (vacuously compliant)
	if got := mfaEnabledPercent(0, 0); got != 100 {
		t.Fatalf("expected 100%% for no users, got %d", got)
	}

	// All users have MFA
	if got := mfaEnabledPercent(5, 5); got != 100 {
		t.Fatalf("expected 100%% when all users have MFA, got %d", got)
	}

	// Half users have MFA
	if got := mfaEnabledPercent(2, 4); got != 50 {
		t.Fatalf("expected 50%% when half users have MFA, got %d", got)
	}

	// No users have MFA
	if got := mfaEnabledPercent(0, 5); got != 0 {
		t.Fatalf("expected 0%% when no users have MFA, got %d", got)
	}
}

func TestHardwareMFAEnabledPercent(t *testing.T) {
	if got := hardwareMFAEnabledPercent(0, 0); got != 100 {
		t.Fatalf("expected 100%% for no users, got %d", got)
	}

	if got := hardwareMFAEnabledPercent(4, 4); got != 100 {
		t.Fatalf("expected 100%% when all users have hardware MFA, got %d", got)
	}

	if got := hardwareMFAEnabledPercent(1, 4); got != 25 {
		t.Fatalf("expected 25%% when one of four users has hardware MFA, got %d", got)
	}

	if got := hardwareMFAEnabledPercent(0, 4); got != 0 {
		t.Fatalf("expected 0%% when no users have hardware MFA, got %d", got)
	}
}

func TestIsHardwareMFASerial(t *testing.T) {
	testCases := []struct {
		name   string
		serial string
		want   bool
	}{
		{
			name:   "virtual MFA arn",
			serial: "arn:aws:iam::123456789012:mfa/alice",
			want:   false,
		},
		{
			name:   "hardware OTP serial",
			serial: "GAKT12345678",
			want:   true,
		},
		{
			name:   "fido security key arn",
			serial: "arn:aws:iam::123456789012:u2f/user/alice/fidosecuritykey1-EXAMPLE",
			want:   true,
		},
		{
			name:   "empty serial",
			serial: "",
			want:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isHardwareMFASerial(tc.serial); got != tc.want {
				t.Fatalf("isHardwareMFASerial(%q) = %v, want %v", tc.serial, got, tc.want)
			}
		})
	}
}

func TestCollectHardwareMFAMetrics(t *testing.T) {
	report := &aws.CredentialReport{
		Users: []aws.CredentialReportUser{
			{User: "<root_account>", MFAActive: true},
			{User: "alice", MFAActive: true},
			{User: "bob", MFAActive: true},
			{User: "carol", MFAActive: false},
		},
	}

	lister := fakeMFADeviceLister{
		devices: map[string][]aws.MFADevice{
			"alice": {
				{UserName: "alice", SerialNumber: "arn:aws:iam::123456789012:mfa/alice"},
			},
			"bob": {
				{UserName: "bob", SerialNumber: "arn:aws:iam::123456789012:u2f/user/bob/security-key"},
			},
		},
	}

	c := &Collector{}
	got := c.collectHardwareMFAMetrics(context.Background(), lister, report, "123456789012")

	if got != 33 {
		t.Fatalf("expected HardwareMFAEnabled=33, got %d", got)
	}
}

func TestCollectHardwareMFAMetricsWarnsOnDeviceLookupFailure(t *testing.T) {
	report := &aws.CredentialReport{
		Users: []aws.CredentialReportUser{
			{User: "alice", MFAActive: true},
		},
	}

	lister := fakeMFADeviceLister{
		errs: map[string]error{
			"alice": errors.New("permission denied"),
		},
	}

	c := &Collector{}
	got := c.collectHardwareMFAMetrics(context.Background(), lister, report, "123456789012")

	if got != 0 {
		t.Fatalf("expected HardwareMFAEnabled=0 on lookup failure, got %d", got)
	}
	if len(c.warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(c.warnings))
	}
}

func TestProcessCredentialReportNoUsers(t *testing.T) {
	// Root-only account (no IAM users)
	report := &aws.CredentialReport{
		Users: []aws.CredentialReportUser{
			{
				User:             "<root_account>",
				MFAActive:        true,
				AccessKey1Active: false,
				AccessKey2Active: false,
			},
		},
	}

	c := &Collector{}
	metrics := &IAMMetrics{}
	c.processCredentialReport(report, metrics)

	if metrics.IAMUsersPresent {
		t.Fatalf("expected IAMUsersPresent=false for root-only account")
	}
	if metrics.MFAEnabled != 100 {
		t.Fatalf("expected MFAEnabled=100 when no IAM users exist, got %d", metrics.MFAEnabled)
	}
	if metrics.AccessKeysRotated != 100 {
		t.Fatalf("expected AccessKeysRotated=100 when no IAM users with keys exist, got %d", metrics.AccessKeysRotated)
	}
}

func TestHasExternalTrust(t *testing.T) {
	current := "203984714075"

	sameAccountPolicy := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::203984714075:root"}}]}`
	encodedSame := url.QueryEscape(sameAccountPolicy)
	if hasExternalTrust(encodedSame, current) {
		t.Fatalf("expected same-account trust to be non-external")
	}

	externalPolicy := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"}}]}`
	encodedExternal := url.QueryEscape(externalPolicy)
	if !hasExternalTrust(encodedExternal, current) {
		t.Fatalf("expected external-account trust to be detected")
	}

	wildcardPolicy := `{"Statement":[{"Effect":"Allow","Principal":"*"}]}`
	encodedWildcard := url.QueryEscape(wildcardPolicy)
	if !hasExternalTrust(encodedWildcard, current) {
		t.Fatalf("expected wildcard trust to be detected as external")
	}
}

func TestExtractPrincipals(t *testing.T) {
	if got := extractPrincipals("arn:aws:iam::111111111111:root"); len(got) != 1 {
		t.Fatalf("expected 1 principal from string, got %v", got)
	}

	principalMap := map[string]any{
		"AWS": []any{
			"arn:aws:iam::111111111111:root",
			"arn:aws:iam::222222222222:root",
		},
	}

	got := extractPrincipals(principalMap)
	if len(got) != 2 {
		t.Fatalf("expected 2 principals from map, got %v", got)
	}

	if out := extractPrincipals(123); out != nil {
		t.Fatalf("expected nil for unsupported principal type, got %v", out)
	}
}

func TestHasExternalPrincipal(t *testing.T) {
	current := "203984714075"

	if hasExternalPrincipal("arn:aws:iam::203984714075:root", current) {
		t.Fatalf("expected same-account principal to be non-external")
	}
	if !hasExternalPrincipal("arn:aws:iam::111111111111:root", current) {
		t.Fatalf("expected external principal to be detected")
	}
	if !hasExternalPrincipal("*", current) {
		t.Fatalf("expected wildcard principal to be treated as external")
	}
}

// fakeRoleLister is a minimal in-memory roleLister for collector tests.
type fakeRoleLister struct {
	roles []aws.Role
	err   error
}

func (f fakeRoleLister) ListRoles(_ context.Context, callback func([]aws.Role) error) error {
	if f.err != nil {
		return f.err
	}
	return callback(f.roles)
}

func TestIAMUsersFromReport_ExcludesRoot(t *testing.T) {
	report := &aws.CredentialReport{
		Users: []aws.CredentialReportUser{
			{
				User:             "<root_account>",
				MFAActive:        true,
				AccessKey1Active: false,
			},
			{
				User:             "alice",
				ARN:              "arn:aws:iam::123:user/alice",
				MFAActive:        true,
				PasswordEnabled:  true,
				AccessKey1Active: false,
			},
			{
				User:             "bob",
				ARN:              "arn:aws:iam::123:user/bob",
				MFAActive:        false,
				PasswordEnabled:  false,
				AccessKey1Active: true,
			},
		},
	}

	c := &Collector{}
	users := c.iamUsersFromReport(report)

	if len(users) != 2 {
		t.Fatalf("expected 2 users (root excluded), got %d", len(users))
	}
	if users[0].UserName != "alice" {
		t.Errorf("expected first user alice, got %q", users[0].UserName)
	}
	if !users[0].MFAActive || !users[0].HasConsoleAccess || users[0].HasAccessKeys {
		t.Errorf("alice: unexpected per-user flags %+v", users[0])
	}
	if users[1].UserName != "bob" {
		t.Errorf("expected second user bob, got %q", users[1].UserName)
	}
	if users[1].MFAActive || users[1].HasConsoleAccess || !users[1].HasAccessKeys {
		t.Errorf("bob: unexpected per-user flags %+v", users[1])
	}
}

func TestCollectIAMRoles_PopulatesRolesWithTrustFlag(t *testing.T) {
	const accountID = "111111111111"
	const externalTrust = `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"}}]}`
	const internalTrust = `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"}}]}`

	client := fakeRoleLister{roles: []aws.Role{
		{RoleName: "external-role", ARN: "arn:aws:iam::111111111111:role/external-role", AssumeRolePolicyDocument: url.QueryEscape(externalTrust)},
		{RoleName: "internal-role", ARN: "arn:aws:iam::111111111111:role/internal-role", AssumeRolePolicyDocument: url.QueryEscape(internalTrust)},
	}}

	c := &Collector{}
	roles := c.collectIAMRoles(context.Background(), client, accountID)

	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(roles))
	}
	if !roles[0].HasExternalTrust {
		t.Errorf("external-role: expected HasExternalTrust=true")
	}
	if roles[1].HasExternalTrust {
		t.Errorf("internal-role: expected HasExternalTrust=false")
	}
}

func TestCollectIAMRoles_AccessDeniedEmitsDiagnostic(t *testing.T) {
	const accountID = "111111111111"

	// smithy.APIError isn't trivial to construct without importing a service package;
	// fall back to a substring-match path covered by isAccessDeniedErr.
	client := fakeRoleLister{err: errors.New("operation error IAM: ListRoles, https response error: AccessDenied: User is not authorized")}

	c := &Collector{}
	roles := c.collectIAMRoles(context.Background(), client, accountID)

	if roles != nil {
		t.Errorf("expected nil roles on AccessDenied, got %v", roles)
	}
	if len(c.warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d (%v)", len(c.warnings), c.warnings)
	}
	if !strings.Contains(c.warnings[0], "iam_roles") || !strings.Contains(c.warnings[0], "iam:ListRoles") {
		t.Errorf("warning text missing structured fields: %q", c.warnings[0])
	}
}

func TestCollectIAMRoles_OtherErrorEmitsGenericWarning(t *testing.T) {
	const accountID = "111111111111"
	client := fakeRoleLister{err: errors.New("connection refused")}

	c := &Collector{}
	roles := c.collectIAMRoles(context.Background(), client, accountID)

	if roles != nil {
		t.Errorf("expected nil roles on error, got %v", roles)
	}
	if len(c.warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d (%v)", len(c.warnings), c.warnings)
	}
	if strings.Contains(c.warnings[0], "access denied") {
		t.Errorf("non-AccessDenied error should not produce access-denied warning text: %q", c.warnings[0])
	}
}

func TestCredentialReportToInternal_OmitsNilTimestamps(t *testing.T) {
	used := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	report := &aws.CredentialReport{
		Users: []aws.CredentialReportUser{
			{
				User:                   "alice",
				UserCreationTime:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				PasswordEnabled:        true,
				PasswordLastUsed:       &used,
				MFAActive:              true,
				AccessKey1Active:       true,
				AccessKey1LastUsedDate: &used,
				// PasswordLastChanged, AccessKey1LastRotated, AccessKey2* all nil.
			},
		},
	}

	out := credentialReportToInternal(report)
	if len(out.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(out.Users))
	}
	u := out.Users[0]
	if u.PasswordLastUsed != used.Format(time.RFC3339) {
		t.Errorf("PasswordLastUsed=%q, want %q", u.PasswordLastUsed, used.Format(time.RFC3339))
	}
	if u.PasswordLastChanged != "" {
		t.Errorf("PasswordLastChanged should be empty when nil, got %q", u.PasswordLastChanged)
	}
	if u.AccessKey1LastRotated != "" {
		t.Errorf("AccessKey1LastRotated should be empty when nil, got %q", u.AccessKey1LastRotated)
	}
	if u.AccessKey2Active {
		t.Errorf("AccessKey2Active should be false")
	}
}

func TestCredentialReportToInternal_NormalizesNASentinel(t *testing.T) {
	// AWS credential-report CSV uses "N/A" for region/service of keys that
	// have never been used. The projection must drop these so omitempty keeps
	// the artifact clean (no "N/A" literals leaking out).
	report := &aws.CredentialReport{
		Users: []aws.CredentialReportUser{
			{
				User:                      "alice",
				AccessKey1Active:          false,
				AccessKey1LastUsedRegion:  "N/A",
				AccessKey1LastUsedService: "N/A",
				AccessKey2Active:          true,
				AccessKey2LastUsedRegion:  "us-east-1",
				AccessKey2LastUsedService: "s3",
			},
		},
	}
	out := credentialReportToInternal(report)
	u := out.Users[0]
	if u.AccessKey1LastUsedRegion != "" {
		t.Errorf("expected empty region for unused key (was 'N/A' from CSV), got %q", u.AccessKey1LastUsedRegion)
	}
	if u.AccessKey1LastUsedService != "" {
		t.Errorf("expected empty service for unused key, got %q", u.AccessKey1LastUsedService)
	}
	if u.AccessKey2LastUsedRegion != "us-east-1" {
		t.Errorf("real value should pass through, got %q", u.AccessKey2LastUsedRegion)
	}
	if u.AccessKey2LastUsedService != "s3" {
		t.Errorf("real value should pass through, got %q", u.AccessKey2LastUsedService)
	}
}

func TestCredentialReportToInternal_PreservesRootRow(t *testing.T) {
	report := &aws.CredentialReport{
		Users: []aws.CredentialReportUser{
			{User: "<root_account>", MFAActive: true},
			{User: "alice"},
		},
	}
	out := credentialReportToInternal(report)
	if len(out.Users) != 2 {
		t.Fatalf("expected 2 users (root included for internal-level forensic value), got %d", len(out.Users))
	}
	if out.Users[0].UserName != "<root_account>" {
		t.Errorf("root account should be first (preserves credential-report ordering), got %q", out.Users[0].UserName)
	}
}
