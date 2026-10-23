package collector

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

type mfaDeviceLister interface {
	ListMFADevices(ctx context.Context, userName string) ([]aws.MFADevice, error)
}

type roleLister interface {
	ListRoles(ctx context.Context, pathPrefix string, callback func([]aws.Role) error) error
}

// iamClient is the slice of the AWS client used by collectIAMMetrics,
// extracted so the failure paths can be tested without AWS.
type iamClient interface {
	GetCredentialReport(ctx context.Context) (*aws.CredentialReport, error)
	GetAccountSummary(ctx context.Context) (*aws.AccountSummary, error)
	GetPasswordPolicy(ctx context.Context) (*aws.PasswordPolicy, error)
	ListOrganizationsFeatures(ctx context.Context) (*aws.OrganizationFeatures, error)
	ListOrganizationAccountIDs(ctx context.Context) ([]string, error)
	ListSAMLProviders(ctx context.Context) ([]aws.SAMLProvider, error)
	mfaDeviceLister
	roleLister
}

// IAM Identity Center creates a role under identityCenterRolePath, named with
// identityCenterRolePrefix, for each permission set assigned in an account,
// and a SAML provider named with identityCenterSAMLProviderPrefix.
const (
	identityCenterRolePath           = "/aws-reserved/sso.amazonaws.com/"
	identityCenterRolePrefix         = "AWSReservedSSO_"
	identityCenterSAMLProviderPrefix = "AWSSSO_"
)

// collectIAMMetrics collects IAM-related security metrics.
//
// At trust, only aggregates and root-account flags are populated.
// At audit, per-user and per-role inventory rows are populated from the same
// credential report (no extra API calls for users) plus ListRoles for the role
// inventory.
//
// Failures never abort the surface: each source degrades independently, and
// every value a failed read leaves unknown is left out with a gap, so a
// consumer never mistakes an uncollected aggregate for a genuine zero.
func (c *Collector) collectIAMMetrics(ctx context.Context, client iamClient, accountID string, at at, level componentsdk.Level) *IAMMetrics {
	iamAt := at.sub("iam")
	metrics := &IAMMetrics{}

	report, reportErr := client.GetCredentialReport(ctx)
	if reportErr != nil {
		metrics.CredentialReportErrorCode = credentialReportErrorCode(reportErr)
		c.warn("account %s: failed to collect IAM credential report: %v", accountID, reportErr)
		c.gaps.leaveOut(reportErr, iamAt.p("iam_users_present"), iamAt.p("iam_user_count"), iamAt.p("access_key_user_count"),
			iamAt.p("mfa_enabled"), iamAt.p("mfa_enabled_user_count"), iamAt.p("hardware_mfa_enabled"), iamAt.p("hardware_mfa_enabled_user_count"),
			iamAt.p("access_keys_rotated"), iamAt.p("access_keys_rotated_user_count"))
		if level.AtLeast(componentsdk.LevelAudit) {
			c.gaps.leaveOut(reportErr, iamAt.p("users"))
		}
		if level.AtLeast(componentsdk.LevelInternal) {
			c.gaps.leaveOut(reportErr, iamAt.p("credential_report"))
		}
	} else {
		c.processCredentialReport(report, metrics)
		metrics.CredentialReportEvaluated = true
	}

	summary, summaryErr := client.GetAccountSummary(ctx)
	if summaryErr != nil {
		c.warn("account %s: failed to collect IAM account summary: %v", accountID, summaryErr)
	}
	c.resolveRootState(metrics, report, summary, summaryErr, reportErr, iamAt)

	policy, policyErr := client.GetPasswordPolicy(ctx)
	if policyErr != nil {
		metrics.PasswordPolicyErrorCode = apiErrorCode(policyErr)
		c.warn("account %s: failed to collect IAM account password policy: %v", accountID, policyErr)
		c.gaps.leaveOut(policyErr, iamAt.p("password_policy"))
	} else {
		// A nil policy with no error is AWS reporting that none is configured,
		// which is an answer rather than a gap.
		metrics.PasswordPolicyEvaluated = true
		metrics.PasswordPolicy = passwordPolicyToMetrics(policy)
	}

	features, err := client.ListOrganizationsFeatures(ctx)
	if err != nil {
		processRootOrganizationsFeatures(nil, err, metrics)
		if shouldWarnRootOrganizationsFeaturesError(metrics.RootOrganizationsFeaturesErrorCode) {
			c.warn("account %s: failed to collect IAM organizations root features: %v", accountID, err)
		}
		c.gaps.leaveOut(rootOrganizationsFeaturesGap(err), iamAt.p("root_organization_id"),
			iamAt.p("root_credentials_management_feature_enabled"), iamAt.p("root_sessions_feature_enabled"))
	} else {
		processRootOrganizationsFeatures(features, nil, metrics)
	}
	if report != nil {
		hardware, unmeasured, err := c.collectHardwareMFAMetrics(ctx, client, report, accountID)
		if hardware != nil {
			metrics.HardwareMFAEnabledUserCount = &hardware.users
			metrics.HardwareMFAEnabled = hardwareMFAEnabledPercent(hardware.users, hardware.of)
		}
		c.gaps.partial(unmeasured, err, iamAt.p("hardware_mfa_enabled"), iamAt.p("hardware_mfa_enabled_user_count"))
	}

	c.collectSignInPaths(ctx, client, accountID, iamAt, metrics)

	if level.AtLeast(componentsdk.LevelAudit) {
		if report != nil {
			metrics.Users = c.iamUsersFromReport(report)
		}
		orgAccounts, rosterErr := c.collectOrganizationAccounts(ctx, client, accountID, metrics)
		roles, err := c.collectIAMRoles(ctx, client, accountID, level, orgAccounts)
		if err != nil {
			c.gaps.leaveOut(err, iamAt.p("roles"))
		}
		metrics.Roles = roles
		for i, role := range roles {
			if role.ExternalTrustInOrg == nil && len(role.ExternalTrustAccountIDs) > 0 {
				c.gaps.leaveOut(rosterErr, iamAt.p("roles", i, "external_trust_in_org"))
			}
		}
	}

	if level.AtLeast(componentsdk.LevelInternal) && report != nil {
		metrics.CredentialReport = credentialReportToInternal(report)
	}

	return metrics
}

// collectSignInPaths counts the ways people sign in to the account other than
// as IAM users: the SAML providers it trusts, and the roles and SAML provider
// IAM Identity Center creates in an account it gives people access to. A
// count whose listing failed is left out with a gap.
func (c *Collector) collectSignInPaths(ctx context.Context, client iamClient, accountID string, iamAt at, metrics *IAMMetrics) {
	providers, err := client.ListSAMLProviders(ctx)
	if err != nil {
		if isAccessDeniedErr(err) {
			c.warnAccessDenied(accountID, "iam_saml_providers", "iam:ListSAMLProviders")
		} else {
			c.warn("account %s: failed to list SAML providers: %v", accountID, err)
		}
		c.gaps.leaveOut(err, iamAt.p("saml_provider_count"), iamAt.p("identity_center_saml_provider_count"))
	} else {
		direct, identityCenter := 0, 0
		for _, p := range providers {
			if strings.HasPrefix(p.Name, identityCenterSAMLProviderPrefix) {
				identityCenter++
			} else {
				direct++
			}
		}
		metrics.SAMLProviderCount = &direct
		metrics.IdentityCenterSAMLProviderCount = &identityCenter
	}

	roles := 0
	err = client.ListRoles(ctx, identityCenterRolePath, func(batch []aws.Role) error {
		for _, r := range batch {
			if strings.HasPrefix(r.RoleName, identityCenterRolePrefix) {
				roles++
			}
		}
		return nil
	})
	if err != nil {
		if isAccessDeniedErr(err) {
			c.warnAccessDenied(accountID, "iam_identity_center_roles", "iam:ListRoles")
		} else {
			c.warn("account %s: failed to list IAM Identity Center roles: %v", accountID, err)
		}
		c.gaps.leaveOut(err, iamAt.p("identity_center_role_count"))
		return
	}
	metrics.IdentityCenterRoleCount = &roles
}

// rootStateFlags are the root user's credential flags, by JSON name.
var rootStateFlags = []string{
	"root_mfa_enabled", "root_credentials_present", "root_password_present",
	"root_access_keys_exist", "root_signing_certificates_present", "root_access_protected",
}

// resolveRootState sets the root user's credential state from the account
// summary, or failing that from the credential report's root row. The report
// cannot say whether the root password exists, so a flag that depends on it
// is left out when only the report answered.
func (c *Collector) resolveRootState(metrics *IAMMetrics, report *aws.CredentialReport, summary *aws.AccountSummary, summaryErr, reportErr error, iamAt at) {
	if summary != nil {
		processRootAccountSummary(summary, metrics)
		return
	}
	root, ok := rootRow(report)
	if !ok {
		why := summaryErr
		if why == nil {
			why = reportErr
		}
		for _, flag := range rootStateFlags {
			c.gaps.leaveOut(why, iamAt.p(flag))
		}
		return
	}
	metrics.RootCredentialStateEvaluated = true
	metrics.RootMFAEnabled = root.MFAActive
	metrics.RootAccessKeysExist = root.HasAccessKeys()
	metrics.RootSigningCertificatesPresent = root.HasSigningCertificates()
	c.gaps.leaveOut(summaryErr, iamAt.p("root_password_present"))
	metrics.RootCredentialsPresent = metrics.RootAccessKeysExist || metrics.RootSigningCertificatesPresent
	if !metrics.RootCredentialsPresent {
		c.gaps.leaveOut(summaryErr, iamAt.p("root_credentials_present"))
	}
	metrics.RootAccessProtected = metrics.RootMFAEnabled
	if !metrics.RootMFAEnabled && !metrics.RootCredentialsPresent {
		c.gaps.leaveOut(summaryErr, iamAt.p("root_access_protected"))
	}
}

func rootRow(report *aws.CredentialReport) (aws.CredentialReportUser, bool) {
	if report == nil {
		return aws.CredentialReportUser{}, false
	}
	for _, u := range report.Users {
		if u.IsRootUser() {
			return u, true
		}
	}
	return aws.CredentialReportUser{}, false
}

// rootOrganizationsFeaturesGap gives a failed organizations-features read its
// code: a member account cannot read them, and an account outside an
// organization with all features and IAM trusted access has none to read.
func rootOrganizationsFeaturesGap(err error) error {
	switch apiErrorCode(err) {
	case "AccountNotManagementOrDelegatedAdministrator", "AccountNotManagementOrDelegatedAdministratorException":
		return componentsdk.CodeError(componentsdk.CodePermissionDenied, err)
	case "OrganizationNotFound", "OrganizationNotFoundException",
		"OrganizationNotInAllFeaturesMode", "OrganizationNotInAllFeaturesModeException",
		"ServiceAccessNotEnabled", "ServiceAccessNotEnabledException":
		return componentsdk.CodeError(componentsdk.CodeNotLicensed, err)
	}
	return err
}

// credentialReportErrorCode maps a credential report failure to a stable code
// for the credential_report_error_code field.
func credentialReportErrorCode(err error) string {
	if errors.Is(err, aws.ErrCredentialReportTimeout) {
		return "CredentialReportTimeout"
	}
	return apiErrorCode(err)
}

// credentialReportToInternal projects the credential report onto the
// internal-level per-user inventory. Per-user details (timestamp formatting,
// N/A sentinel handling) live in credentialReportUserToInternal so they can
// be unit-tested directly without iterating the report.
func credentialReportToInternal(report *aws.CredentialReport) *IAMCredentialReport {
	out := &IAMCredentialReport{
		Users: make([]IAMCredentialReportUser, 0, len(report.Users)),
	}
	for _, u := range report.Users {
		out.Users = append(out.Users, credentialReportUserToInternal(u))
	}
	return out
}

// credentialReportUserToInternal projects one user row. Timestamps that are
// nil are omitted via empty strings (omitempty in the struct tag drops them
// from the artifact), preserving the AWS-side semantic "never" for
// keys/passwords that haven't been used. The AWS credential-report CSV uses
// the literal string "N/A" as a sentinel for fields that don't apply (e.g.,
// region/service on a key that has never been used); normalizeNA collapses
// those to empty strings so omitempty drops them from the artifact too,
// leaving the absence semantic clean.
func credentialReportUserToInternal(u aws.CredentialReportUser) IAMCredentialReportUser {
	return IAMCredentialReportUser{
		UserName:                  u.User,
		UserCreationTime:          formatRFC3339(&u.UserCreationTime),
		PasswordEnabled:           u.PasswordEnabled,
		PasswordLastUsed:          formatRFC3339(u.PasswordLastUsed),
		PasswordLastChanged:       formatRFC3339(u.PasswordLastChanged),
		PasswordNextRotation:      formatRFC3339(u.PasswordNextRotation),
		MFAActive:                 u.MFAActive,
		AccessKey1Active:          u.AccessKey1Active,
		AccessKey1LastRotated:     formatRFC3339(u.AccessKey1LastRotated),
		AccessKey1LastUsedDate:    formatRFC3339(u.AccessKey1LastUsedDate),
		AccessKey1LastUsedRegion:  normalizeNA(u.AccessKey1LastUsedRegion),
		AccessKey1LastUsedService: normalizeNA(u.AccessKey1LastUsedService),
		AccessKey2Active:          u.AccessKey2Active,
		AccessKey2LastRotated:     formatRFC3339(u.AccessKey2LastRotated),
		AccessKey2LastUsedDate:    formatRFC3339(u.AccessKey2LastUsedDate),
		AccessKey2LastUsedRegion:  normalizeNA(u.AccessKey2LastUsedRegion),
		AccessKey2LastUsedService: normalizeNA(u.AccessKey2LastUsedService),
	}
}

func formatRFC3339(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// normalizeNA collapses the credential-report "N/A" sentinel to an empty
// string. Paired with omitempty struct tags this drops the field from the
// artifact entirely, so the absence semantic is clean ("this key has never
// been used" reads as "no field" rather than 'field present with value N/A').
func normalizeNA(s string) string {
	if s == "N/A" {
		return ""
	}
	return s
}

// iamUsersFromReport projects the credential report onto audit-level per-user
// rows. The report is already fetched for the trust-level aggregates; no extra
// API calls are needed. The root account is excluded; its state is captured in
// the trust-level Root* fields.
func (c *Collector) iamUsersFromReport(report *aws.CredentialReport) []IAMUser {
	users := make([]IAMUser, 0, len(report.Users))
	for _, u := range report.Users {
		if u.IsRootUser() {
			continue
		}
		users = append(users, IAMUser{
			UserName:         u.User,
			ARN:              u.ARN,
			MFAActive:        u.MFAActive,
			HasConsoleAccess: u.HasConsoleAccess(),
			HasAccessKeys:    u.HasAccessKeys(),
		})
	}
	return users
}

// collectIAMRoles fetches the per-role audit-level inventory. HasExternalTrust
// is derived from each role's trust policy document (cross-account principals
// or wildcards). A failed listing returns nil and the error, which the caller
// records as a gap; the trust-level aggregates are unaffected. Returns an
// empty (non-nil) slice on success-with-no-roles so the audit artifact emits
// `[]` not `null`.
func (c *Collector) collectIAMRoles(ctx context.Context, client roleLister, accountID string, level componentsdk.Level, orgAccounts *organizationAccounts) ([]IAMRole, error) {
	roles := []IAMRole{}
	err := client.ListRoles(ctx, "", func(batch []aws.Role) error {
		for _, r := range batch {
			analysis := analyzeTrustPolicy(r.AssumeRolePolicyDocument, accountID)
			row := IAMRole{
				RoleName:                r.RoleName,
				ARN:                     r.ARN,
				HasExternalTrust:        analysis.hasExternalTrust,
				HasWildcardPrincipal:    analysis.hasWildcardPrincipal,
				ExternalTrustAccountIDs: analysis.externalAccountIDs,
			}
			if len(analysis.externalAccountIDs) > 0 {
				row.ExternalTrustInOrg = orgAccounts.membership(analysis.externalAccountIDs)
			}
			if level.AtLeast(componentsdk.LevelInternal) {
				row.TrustPolicyJSON = analysis.decodedPolicy
			}
			roles = append(roles, row)
		}
		return nil
	})
	if err != nil {
		if isAccessDeniedErr(err) {
			c.warnAccessDenied(accountID, "iam_roles", "iam:ListRoles")
		} else {
			c.warn("account %s: failed to list IAM roles: %v", accountID, err)
		}
		return nil, err
	}
	return roles, nil
}

// organizationAccounts is the in-org membership context for one account run.
// A nil / unevaluated receiver yields absent determinations, never guesses.
// An account outside any organization has no foreign account in its
// organization.
type organizationAccounts struct {
	evaluated bool
	ids       map[string]struct{}
}

// membership returns true when every given account ID belongs to the
// organization, false when at least one does not, and nil when the
// organization roster was not evaluated.
func (o *organizationAccounts) membership(accountIDs []string) *bool {
	if o == nil || !o.evaluated {
		return nil
	}
	for _, id := range accountIDs {
		if _, ok := o.ids[id]; !ok {
			return boolPtr(false)
		}
	}
	return boolPtr(true)
}

// collectOrganizationAccounts fetches the organization account roster used to
// classify cross-account trust, recording the outcome on the sentinels.
// Expected failures from accounts without Organizations visibility record the
// code without a warning. The error it returns is why membership could not be
// determined.
func (c *Collector) collectOrganizationAccounts(ctx context.Context, client iamClient, accountID string, metrics *IAMMetrics) (*organizationAccounts, error) {
	accountIDs, err := client.ListOrganizationAccountIDs(ctx)
	if err != nil {
		metrics.OrganizationAccountsErrorCode = apiErrorCode(err)
		if metrics.OrganizationAccountsErrorCode == "AWSOrganizationsNotInUseException" {
			metrics.OrganizationAccountsEvaluated = true
			return &organizationAccounts{evaluated: true, ids: map[string]struct{}{}}, nil
		}
		if !isAccessDeniedErr(err) && shouldWarnOrganizationAccountsError(metrics.OrganizationAccountsErrorCode) {
			c.warn("account %s: failed to list organization accounts: %v", accountID, err)
		}
		return &organizationAccounts{}, err
	}
	metrics.OrganizationAccountsEvaluated = true
	ids := make(map[string]struct{}, len(accountIDs))
	for _, id := range accountIDs {
		ids[id] = struct{}{}
	}
	return &organizationAccounts{evaluated: true, ids: ids}, nil
}

// shouldWarnOrganizationAccountsError suppresses warnings for error codes
// that simply mean this account has no Organizations visibility (the common
// member-account case) rather than a misconfiguration worth surfacing.
// Access denial is additionally suppressed via isAccessDeniedErr at the call
// site, which also catches untyped errors.
func shouldWarnOrganizationAccountsError(code string) bool {
	return code != "AWSOrganizationsNotInUseException"
}

// processCredentialReport analyzes the credential report and populates user
// metrics. Key ages are measured against the run's clock.
func (c *Collector) processCredentialReport(report *aws.CredentialReport, metrics *IAMMetrics) {
	keyRotationThreshold := c.now().AddDate(0, 0, -AccessKeyAgeThreshold)

	var stats userStats

	for _, user := range report.Users {
		if user.IsRootUser() {
			continue
		}
		c.processIAMUser(user, keyRotationThreshold, &stats)
	}

	// Calculate percentages
	metrics.IAMUsersPresent = stats.totalUsers > 0
	metrics.IAMUserCount = stats.totalUsers
	metrics.AccessKeyUserCount = stats.usersWithKeys
	metrics.MFAEnabled = mfaEnabledPercent(stats.mfaEnabled, stats.totalUsers)
	metrics.MFAEnabledUserCount = stats.mfaEnabled
	metrics.AccessKeysRotated = accessKeyRotationPercent(stats.keysRotated, stats.usersWithKeys)
	metrics.AccessKeysRotatedUserCount = stats.keysRotated
}

// hardwareMFA counts the IAM users with a hardware MFA device among all the
// IAM users.
type hardwareMFA struct {
	users, of int
}

// collectHardwareMFAMetrics checks each IAM user's MFA device type.
// Hardware MFA includes physical OTP devices and FIDO/U2F security keys. A
// user whose devices could not be listed is unmeasured, never counted as
// software MFA: with any unmeasured user the count is nil, and the count of
// unmeasured users and the first failure are returned.
func (c *Collector) collectHardwareMFAMetrics(ctx context.Context, client mfaDeviceLister, report *aws.CredentialReport, accountID string) (*hardwareMFA, int, error) {
	totalUsers := 0
	hardwareMFAUsers := 0
	unmeasured := 0
	var firstErr error

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
			unmeasured++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		if hasHardwareMFADevice(devices) {
			hardwareMFAUsers++
		}
	}

	if unmeasured > 0 {
		return nil, unmeasured, firstErr
	}
	return &hardwareMFA{users: hardwareMFAUsers, of: totalUsers}, 0, nil
}

// userStats tracks counts during credential report processing.
type userStats struct {
	totalUsers    int
	mfaEnabled    int
	keysRotated   int
	usersWithKeys int
}

func processRootAccountSummary(summary *aws.AccountSummary, metrics *IAMMetrics) {
	if summary == nil {
		return
	}
	processRootCredentialState(
		metrics,
		summary.AccountMFAEnabled,
		summary.AccountPasswordPresent,
		summary.AccountAccessKeysPresent,
		summary.AccountSigningCertificatesPresent,
	)
}

func processRootCredentialState(metrics *IAMMetrics, mfaActive, passwordPresent, accessKeysPresent, signingCertificatesPresent bool) {
	credentialsPresent := passwordPresent || accessKeysPresent || signingCertificatesPresent
	metrics.RootCredentialStateEvaluated = true
	metrics.RootPasswordPresent = passwordPresent
	metrics.RootAccessKeysExist = accessKeysPresent
	metrics.RootSigningCertificatesPresent = signingCertificatesPresent
	metrics.RootCredentialsPresent = credentialsPresent
	metrics.RootMFAEnabled = mfaActive
	metrics.RootAccessProtected = mfaActive || !credentialsPresent
}

func processRootOrganizationsFeatures(features *aws.OrganizationFeatures, err error, metrics *IAMMetrics) {
	if err != nil {
		metrics.RootOrganizationsFeaturesErrorCode = apiErrorCode(err)
		return
	}
	if features == nil {
		metrics.RootOrganizationsFeaturesErrorCode = "MissingOrganizationsFeatures"
		return
	}
	metrics.RootOrganizationsFeaturesEvaluated = true
	metrics.RootOrganizationID = features.OrganizationID
	metrics.RootCredentialsManagementFeatureEnabled = features.RootCredentialsManagementFeatureEnabled
	metrics.RootSessionsFeatureEnabled = features.RootSessionsFeatureEnabled
}

func shouldWarnRootOrganizationsFeaturesError(code string) bool {
	switch code {
	case "AccountNotManagementOrDelegatedAdministrator",
		"AccountNotManagementOrDelegatedAdministratorException",
		"OrganizationNotFound",
		"OrganizationNotFoundException",
		"OrganizationNotInAllFeaturesMode",
		"OrganizationNotInAllFeaturesModeException",
		"ServiceAccessNotEnabled",
		"ServiceAccessNotEnabledException":
		return false
	default:
		return code != ""
	}
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

// passwordPolicyToMetrics projects the account password policy onto the
// artifact shape. Returns nil when no policy is configured, which the caller
// distinguishes from a failed lookup via PasswordPolicyEvaluated.
func passwordPolicyToMetrics(policy *aws.PasswordPolicy) *IAMPasswordPolicy {
	if policy == nil {
		return nil
	}

	return &IAMPasswordPolicy{
		MinimumLength:              policy.MinimumPasswordLength,
		RequireSymbols:             policy.RequireSymbols,
		RequireNumbers:             policy.RequireNumbers,
		RequireUppercase:           policy.RequireUppercase,
		RequireLowercase:           policy.RequireLowercase,
		AllowUsersToChangePassword: policy.AllowUsersToChangePassword,
		ExpirePasswords:            policy.ExpirePasswords,
		HardExpiry:                 policy.HardExpiry,
		MaxPasswordAgeDays:         policy.MaxPasswordAge,
		PasswordReusePrevention:    policy.PasswordReusePrevention,
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

// mfaEnabledPercent is the share of IAM users with MFA, nil when there are
// none: an account with no IAM users has no MFA coverage to report, and its
// people may sign in through Identity Center, which this does not measure.
func mfaEnabledPercent(mfaEnabled, totalUsers int) *int {
	return pctOf(mfaEnabled, totalUsers)
}

// accessKeyRotationPercent is the share of users with active keys whose keys
// were all rotated within the threshold, nil when no user has an active key.
func accessKeyRotationPercent(keysRotated, usersWithKeys int) *int {
	return pctOf(keysRotated, usersWithKeys)
}

// hardwareMFAEnabledPercent is the share of IAM users with a hardware MFA
// device, nil when there are none.
func hardwareMFAEnabledPercent(hardwareMFAUsers, totalUsers int) *int {
	return pctOf(hardwareMFAUsers, totalUsers)
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

// trustAnalysis is the parsed external-trust view of one role's trust policy.
// externalAccountIDs is sorted and deduplicated; decodedPolicy is the
// URL-decoded document ("" when the document was absent or undecodable).
type trustAnalysis struct {
	hasExternalTrust     bool
	hasWildcardPrincipal bool
	externalAccountIDs   []string
	decodedPolicy        string
}

// analyzeTrustPolicy extracts the external-trust facts from a role's trust
// policy: which foreign accounts appear as principals in allow statements
// (as full ARNs or bare account IDs) and whether a wildcard principal grants
// to everyone. Service principals are never external.
func analyzeTrustPolicy(policyDoc string, currentAccount string) trustAnalysis {
	analysis := trustAnalysis{}
	if policyDoc == "" {
		return analysis
	}

	decoded, err := url.QueryUnescape(policyDoc)
	if err != nil {
		return analysis
	}
	analysis.decodedPolicy = decoded

	var policy trustPolicy
	if err := json.Unmarshal([]byte(decoded), &policy); err != nil {
		return analysis
	}

	seen := map[string]struct{}{}
	for _, stmt := range policy.Statement {
		if stmt.Effect != TrustPolicyEffectAllow {
			continue
		}
		for _, p := range extractPrincipals(stmt.Principal) {
			switch {
			case p == TrustPolicyPrincipalAll:
				analysis.hasExternalTrust = true
				analysis.hasWildcardPrincipal = true
			case strings.HasPrefix(p, TrustPolicyARNPrefix):
				parts := strings.Split(p, ":")
				if len(parts) >= 5 && parts[4] != "" && parts[4] != currentAccount {
					analysis.hasExternalTrust = true
					seen[parts[4]] = struct{}{}
				}
			case isBareAccountID(p) && p != currentAccount:
				analysis.hasExternalTrust = true
				seen[p] = struct{}{}
			}
		}
	}

	if len(seen) > 0 {
		analysis.externalAccountIDs = make([]string, 0, len(seen))
		for id := range seen {
			analysis.externalAccountIDs = append(analysis.externalAccountIDs, id)
		}
		sort.Strings(analysis.externalAccountIDs)
	}
	return analysis
}

// isBareAccountID reports whether a principal string is a bare 12-digit AWS
// account ID (shorthand for that account's root principal).
func isBareAccountID(p string) bool {
	if len(p) != 12 {
		return false
	}
	for _, r := range p {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
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
