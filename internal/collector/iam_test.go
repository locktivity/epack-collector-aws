package collector

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
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
	if !metrics.RootAccessProtected {
		t.Fatalf("expected RootAccessProtected=true")
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

func TestProcessRootCredentialState(t *testing.T) {
	tests := []struct {
		name                        string
		mfaActive                   bool
		passwordPresent             bool
		accessKeysPresent           bool
		signingCertificatesPresent  bool
		wantRootMFAEnabled          bool
		wantRootCredentialsPresent  bool
		wantRootPasswordPresent     bool
		wantRootAccessKeysExist     bool
		wantRootSigningCertsPresent bool
		wantRootAccessProtected     bool
	}{
		{
			name:                       "mfa active with root password passes",
			mfaActive:                  true,
			passwordPresent:            true,
			wantRootMFAEnabled:         true,
			wantRootCredentialsPresent: true,
			wantRootPasswordPresent:    true,
			wantRootAccessProtected:    true,
		},
		{
			name:                    "no long-term root credentials passes without claiming mfa",
			wantRootMFAEnabled:      false,
			wantRootAccessProtected: true,
		},
		{
			name:                       "password without mfa fails",
			passwordPresent:            true,
			wantRootCredentialsPresent: true,
			wantRootPasswordPresent:    true,
		},
		{
			name:                       "access key without mfa fails",
			accessKeysPresent:          true,
			wantRootCredentialsPresent: true,
			wantRootAccessKeysExist:    true,
		},
		{
			name:                        "signing certificate without mfa fails",
			signingCertificatesPresent:  true,
			wantRootCredentialsPresent:  true,
			wantRootSigningCertsPresent: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			metrics := &IAMMetrics{}
			processRootCredentialState(
				metrics,
				tc.mfaActive,
				tc.passwordPresent,
				tc.accessKeysPresent,
				tc.signingCertificatesPresent,
			)

			if metrics.RootMFAEnabled != tc.wantRootMFAEnabled {
				t.Errorf("RootMFAEnabled = %v, want %v", metrics.RootMFAEnabled, tc.wantRootMFAEnabled)
			}
			if metrics.RootCredentialsPresent != tc.wantRootCredentialsPresent {
				t.Errorf("RootCredentialsPresent = %v, want %v", metrics.RootCredentialsPresent, tc.wantRootCredentialsPresent)
			}
			if metrics.RootPasswordPresent != tc.wantRootPasswordPresent {
				t.Errorf("RootPasswordPresent = %v, want %v", metrics.RootPasswordPresent, tc.wantRootPasswordPresent)
			}
			if metrics.RootAccessKeysExist != tc.wantRootAccessKeysExist {
				t.Errorf("RootAccessKeysExist = %v, want %v", metrics.RootAccessKeysExist, tc.wantRootAccessKeysExist)
			}
			if metrics.RootSigningCertificatesPresent != tc.wantRootSigningCertsPresent {
				t.Errorf("RootSigningCertificatesPresent = %v, want %v", metrics.RootSigningCertificatesPresent, tc.wantRootSigningCertsPresent)
			}
			if metrics.RootAccessProtected != tc.wantRootAccessProtected {
				t.Errorf("RootAccessProtected = %v, want %v", metrics.RootAccessProtected, tc.wantRootAccessProtected)
			}
		})
	}
}

func TestProcessRootOrganizationsFeatures(t *testing.T) {
	metrics := &IAMMetrics{}

	processRootOrganizationsFeatures(&aws.OrganizationFeatures{
		OrganizationID:                          "o-abc1234567",
		RootCredentialsManagementFeatureEnabled: true,
		RootSessionsFeatureEnabled:              true,
	}, nil, metrics)

	if !metrics.RootOrganizationsFeaturesEvaluated {
		t.Fatalf("expected root organizations features to be evaluated")
	}
	if metrics.RootOrganizationID != "o-abc1234567" {
		t.Errorf("RootOrganizationID = %q, want o-abc1234567", metrics.RootOrganizationID)
	}
	if !metrics.RootCredentialsManagementFeatureEnabled {
		t.Errorf("RootCredentialsManagementFeatureEnabled should be true")
	}
	if !metrics.RootSessionsFeatureEnabled {
		t.Errorf("RootSessionsFeatureEnabled should be true")
	}
	if metrics.RootOrganizationsFeaturesErrorCode != "" {
		t.Errorf("RootOrganizationsFeaturesErrorCode = %q, want empty", metrics.RootOrganizationsFeaturesErrorCode)
	}
}

func TestProcessRootOrganizationsFeatures_APIError(t *testing.T) {
	metrics := &IAMMetrics{}

	processRootOrganizationsFeatures(nil, &smithy.GenericAPIError{
		Code: "AccountNotManagementOrDelegatedAdministrator",
	}, metrics)

	if metrics.RootOrganizationsFeaturesEvaluated {
		t.Fatalf("expected failed feature read not to be evaluated")
	}
	if metrics.RootOrganizationsFeaturesErrorCode != "AccountNotManagementOrDelegatedAdministrator" {
		t.Fatalf("RootOrganizationsFeaturesErrorCode = %q", metrics.RootOrganizationsFeaturesErrorCode)
	}
}

func TestProcessRootOrganizationsFeatures_MissingOutput(t *testing.T) {
	metrics := &IAMMetrics{}

	processRootOrganizationsFeatures(nil, nil, metrics)

	if metrics.RootOrganizationsFeaturesEvaluated {
		t.Fatalf("expected missing feature output not to be evaluated")
	}
	if metrics.RootOrganizationsFeaturesErrorCode != "MissingOrganizationsFeatures" {
		t.Fatalf("RootOrganizationsFeaturesErrorCode = %q", metrics.RootOrganizationsFeaturesErrorCode)
	}
}

func TestShouldWarnRootOrganizationsFeaturesError(t *testing.T) {
	tests := []struct {
		code string
		want bool
	}{
		{code: "", want: false},
		{code: "AccountNotManagementOrDelegatedAdministrator", want: false},
		{code: "AccountNotManagementOrDelegatedAdministratorException", want: false},
		{code: "OrganizationNotFound", want: false},
		{code: "OrganizationNotFoundException", want: false},
		{code: "OrganizationNotInAllFeaturesMode", want: false},
		{code: "OrganizationNotInAllFeaturesModeException", want: false},
		{code: "ServiceAccessNotEnabled", want: false},
		{code: "ServiceAccessNotEnabledException", want: false},
		{code: "ThrottlingException", want: true},
		{code: "NonAPIError", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			if got := shouldWarnRootOrganizationsFeaturesError(tt.code); got != tt.want {
				t.Fatalf("shouldWarnRootOrganizationsFeaturesError(%q) = %v, want %v", tt.code, got, tt.want)
			}
		})
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

func TestAnalyzeTrustPolicy(t *testing.T) {
	current := "203984714075"

	sameAccountPolicy := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::203984714075:root"}}]}`
	got := analyzeTrustPolicy(url.QueryEscape(sameAccountPolicy), current)
	if got.hasExternalTrust || len(got.externalAccountIDs) != 0 {
		t.Fatalf("expected same-account trust to be non-external, got %+v", got)
	}
	if got.decodedPolicy != sameAccountPolicy {
		t.Fatalf("expected decoded policy to round-trip, got %q", got.decodedPolicy)
	}

	externalPolicy := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111111111111:root","222222222222","arn:aws:iam::111111111111:role/other"]}}]}`
	got = analyzeTrustPolicy(url.QueryEscape(externalPolicy), current)
	if !got.hasExternalTrust {
		t.Fatalf("expected external-account trust to be detected")
	}
	if len(got.externalAccountIDs) != 2 || got.externalAccountIDs[0] != "111111111111" || got.externalAccountIDs[1] != "222222222222" {
		t.Fatalf("expected sorted deduped external accounts [111111111111 222222222222], got %v", got.externalAccountIDs)
	}
	if got.hasWildcardPrincipal {
		t.Fatalf("expected no wildcard principal")
	}

	wildcardPolicy := `{"Statement":[{"Effect":"Allow","Principal":"*"}]}`
	got = analyzeTrustPolicy(url.QueryEscape(wildcardPolicy), current)
	if !got.hasExternalTrust || !got.hasWildcardPrincipal {
		t.Fatalf("expected wildcard trust to be external with the wildcard flag, got %+v", got)
	}
	if len(got.externalAccountIDs) != 0 {
		t.Fatalf("wildcard is not account-scoped; got %v", got.externalAccountIDs)
	}

	servicePolicy := `{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"}}]}`
	got = analyzeTrustPolicy(url.QueryEscape(servicePolicy), current)
	if got.hasExternalTrust {
		t.Fatalf("service principals must not count as external, got %+v", got)
	}

	denyPolicy := `{"Statement":[{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::111111111111:root"}}]}`
	got = analyzeTrustPolicy(url.QueryEscape(denyPolicy), current)
	if got.hasExternalTrust {
		t.Fatalf("deny statements must not count as external trust, got %+v", got)
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

func TestIsBareAccountID(t *testing.T) {
	cases := map[string]bool{
		"203984714075":      true,
		"20398471407":       false,
		"2039847140755":     false,
		"20398471407a":      false,
		"ec2.amazonaws.com": false,
		"*":                 false,
	}
	for in, want := range cases {
		if got := isBareAccountID(in); got != want {
			t.Errorf("isBareAccountID(%q) = %v, want %v", in, got, want)
		}
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
	roles := c.collectIAMRoles(context.Background(), client, accountID, componentsdk.LevelAudit, nil)

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
	roles := c.collectIAMRoles(context.Background(), client, accountID, componentsdk.LevelAudit, nil)

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
	roles := c.collectIAMRoles(context.Background(), client, accountID, componentsdk.LevelAudit, nil)

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

type fakeIAMClient struct {
	report         *aws.CredentialReport
	reportErr      error
	summary        *aws.AccountSummary
	summaryErr     error
	features       *aws.OrganizationFeatures
	featuresErr    error
	rolesErr       error
	orgAccountIDs  []string
	orgAccountsErr error
	passwordPolicy *aws.PasswordPolicy
	passwordErr    error
}

func (f fakeIAMClient) GetCredentialReport(_ context.Context) (*aws.CredentialReport, error) {
	return f.report, f.reportErr
}

func (f fakeIAMClient) GetAccountSummary(_ context.Context) (*aws.AccountSummary, error) {
	return f.summary, f.summaryErr
}

func (f fakeIAMClient) GetPasswordPolicy(_ context.Context) (*aws.PasswordPolicy, error) {
	return f.passwordPolicy, f.passwordErr
}

func (f fakeIAMClient) ListOrganizationsFeatures(_ context.Context) (*aws.OrganizationFeatures, error) {
	return f.features, f.featuresErr
}

func (f fakeIAMClient) ListOrganizationAccountIDs(_ context.Context) ([]string, error) {
	return f.orgAccountIDs, f.orgAccountsErr
}

func (f fakeIAMClient) ListMFADevices(_ context.Context, _ string) ([]aws.MFADevice, error) {
	return nil, nil
}

func (f fakeIAMClient) ListRoles(_ context.Context, _ func([]aws.Role) error) error {
	return f.rolesErr
}

func TestCollectIAMMetrics_CredentialReportTimeout(t *testing.T) {
	c := &Collector{}
	client := fakeIAMClient{
		reportErr: fmt.Errorf("getting credential report: %w", aws.ErrCredentialReportTimeout),
		summary: &aws.AccountSummary{
			AccountMFAEnabled:      true,
			AccountPasswordPresent: true,
		},
		features: &aws.OrganizationFeatures{OrganizationID: "o-abcdefghij"},
	}

	metrics := c.collectIAMMetrics(context.Background(), client, "123456789012", componentsdk.LevelTrust)

	if metrics.CredentialReportEvaluated {
		t.Error("CredentialReportEvaluated = true, want false")
	}
	if metrics.CredentialReportErrorCode != "CredentialReportTimeout" {
		t.Errorf("CredentialReportErrorCode = %q, want CredentialReportTimeout", metrics.CredentialReportErrorCode)
	}
	if metrics.MFAEnabled != 0 || metrics.AccessKeysRotated != 0 || metrics.IAMUsersPresent {
		t.Errorf("report-derived aggregates should stay zero-valued (labeled unevaluated), got MFAEnabled=%d AccessKeysRotated=%d IAMUsersPresent=%v",
			metrics.MFAEnabled, metrics.AccessKeysRotated, metrics.IAMUsersPresent)
	}
	if !metrics.RootCredentialStateEvaluated {
		t.Error("RootCredentialStateEvaluated = false, want true (account summary succeeded)")
	}
	if !metrics.RootMFAEnabled || !metrics.RootAccessProtected {
		t.Errorf("root state from summary not applied: RootMFAEnabled=%v RootAccessProtected=%v",
			metrics.RootMFAEnabled, metrics.RootAccessProtected)
	}
	if len(c.warnings) == 0 || !strings.Contains(c.warnings[0], "credential report") {
		t.Errorf("expected credential report warning, got %v", c.warnings)
	}
}

func TestCollectIAMMetrics_AllRootSourcesFail(t *testing.T) {
	c := &Collector{}
	client := fakeIAMClient{
		reportErr:  aws.ErrCredentialReportTimeout,
		summaryErr: errors.New("throttled"),
		features:   &aws.OrganizationFeatures{},
	}

	metrics := c.collectIAMMetrics(context.Background(), client, "123456789012", componentsdk.LevelTrust)

	if metrics.RootCredentialStateEvaluated {
		t.Error("RootCredentialStateEvaluated = true, want false (no source succeeded)")
	}
	if metrics.RootAccessProtected {
		t.Error("RootAccessProtected = true, want false zero value")
	}
}

func TestCollectIAMMetrics_ReportFailureAtAudit(t *testing.T) {
	c := &Collector{}
	client := fakeIAMClient{
		reportErr: aws.ErrCredentialReportTimeout,
		summary:   &aws.AccountSummary{AccountMFAEnabled: true},
		features:  &aws.OrganizationFeatures{},
	}

	metrics := c.collectIAMMetrics(context.Background(), client, "123456789012", componentsdk.LevelAudit)

	if metrics.Users != nil {
		t.Errorf("Users = %v, want nil when the credential report was not collected", metrics.Users)
	}
	if metrics.Roles == nil {
		t.Error("Roles = nil, want role inventory collected independently of the report")
	}
}

func TestCollectIAMMetrics_Success(t *testing.T) {
	c := &Collector{}
	client := fakeIAMClient{
		report: &aws.CredentialReport{
			Users: []aws.CredentialReportUser{
				{User: "<root_account>", MFAActive: true},
				{User: "alice", MFAActive: true},
			},
		},
		features: &aws.OrganizationFeatures{},
	}

	metrics := c.collectIAMMetrics(context.Background(), client, "123456789012", componentsdk.LevelTrust)

	if !metrics.CredentialReportEvaluated {
		t.Error("CredentialReportEvaluated = false, want true")
	}
	if metrics.CredentialReportErrorCode != "" {
		t.Errorf("CredentialReportErrorCode = %q, want empty", metrics.CredentialReportErrorCode)
	}
	if !metrics.RootCredentialStateEvaluated {
		t.Error("RootCredentialStateEvaluated = false, want true")
	}
	if metrics.MFAEnabled != 100 {
		t.Errorf("MFAEnabled = %d, want 100", metrics.MFAEnabled)
	}
}

func TestCollectIAMRoles_InOrgDetermination(t *testing.T) {
	current := "203984714075"
	external := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111111111111:root","arn:aws:iam::333333333333:root"]}}]}`
	internalOnly := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"}}]}`
	client := fakeRoleLister{roles: []aws.Role{
		{RoleName: "mixed", ARN: "arn:aws:iam::203984714075:role/mixed", AssumeRolePolicyDocument: url.QueryEscape(external)},
		{RoleName: "in-org", ARN: "arn:aws:iam::203984714075:role/in-org", AssumeRolePolicyDocument: url.QueryEscape(internalOnly)},
		{RoleName: "local", ARN: "arn:aws:iam::203984714075:role/local"},
	}}
	orgAccounts := &organizationAccounts{evaluated: true, ids: map[string]struct{}{
		"203984714075": {}, "111111111111": {},
	}}

	c := &Collector{}
	roles := c.collectIAMRoles(context.Background(), client, current, componentsdk.LevelAudit, orgAccounts)

	if len(roles) != 3 {
		t.Fatalf("expected 3 roles, got %d", len(roles))
	}
	mixed := roles[0]
	if mixed.ExternalTrustInOrg == nil || *mixed.ExternalTrustInOrg {
		t.Errorf("mixed: expected in_org false (333333333333 outside org), got %v", mixed.ExternalTrustInOrg)
	}
	if len(mixed.ExternalTrustAccountIDs) != 2 {
		t.Errorf("mixed: expected 2 external accounts, got %v", mixed.ExternalTrustAccountIDs)
	}
	inOrg := roles[1]
	if inOrg.ExternalTrustInOrg == nil || !*inOrg.ExternalTrustInOrg {
		t.Errorf("in-org: expected in_org true, got %v", inOrg.ExternalTrustInOrg)
	}
	local := roles[2]
	if local.ExternalTrustInOrg != nil {
		t.Errorf("local: expected absent in_org with no external accounts, got %v", *local.ExternalTrustInOrg)
	}
	if local.HasExternalTrust {
		t.Error("local: expected no external trust")
	}
	if mixed.TrustPolicyJSON != "" {
		t.Errorf("audit level must not carry the trust policy document, got %q", mixed.TrustPolicyJSON)
	}
}

func TestCollectIAMRoles_UnknownWithoutOrgVisibility(t *testing.T) {
	current := "203984714075"
	external := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"}}]}`
	client := fakeRoleLister{roles: []aws.Role{
		{RoleName: "xacct", ARN: "arn:aws:iam::203984714075:role/xacct", AssumeRolePolicyDocument: url.QueryEscape(external)},
	}}

	c := &Collector{}
	roles := c.collectIAMRoles(context.Background(), client, current, componentsdk.LevelAudit, &organizationAccounts{})

	if roles[0].ExternalTrustInOrg != nil {
		t.Errorf("expected absent in_org without org visibility, got %v", *roles[0].ExternalTrustInOrg)
	}
	if !roles[0].HasExternalTrust {
		t.Error("expected external trust flag regardless of org visibility")
	}
}

func TestCollectIAMRoles_TrustPolicyAtInternal(t *testing.T) {
	current := "203984714075"
	policy := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"}}]}`
	client := fakeRoleLister{roles: []aws.Role{
		{RoleName: "xacct", ARN: "arn:aws:iam::203984714075:role/xacct", AssumeRolePolicyDocument: url.QueryEscape(policy)},
	}}

	c := &Collector{}
	roles := c.collectIAMRoles(context.Background(), client, current, componentsdk.LevelInternal, nil)

	if roles[0].TrustPolicyJSON != policy {
		t.Errorf("internal level must carry the decoded trust policy, got %q", roles[0].TrustPolicyJSON)
	}
}

func TestCollectOrganizationAccounts_MemberAccountDeniedIsQuiet(t *testing.T) {
	c := &Collector{}
	metrics := &IAMMetrics{}
	client := fakeIAMClient{orgAccountsErr: errors.New("AccessDeniedException: not authorized")}

	orgAccounts := c.collectOrganizationAccounts(context.Background(), client, "203984714075", metrics)

	if metrics.OrganizationAccountsEvaluated {
		t.Error("expected OrganizationAccountsEvaluated false on denial")
	}
	if metrics.OrganizationAccountsErrorCode == "" {
		t.Error("expected OrganizationAccountsErrorCode recorded")
	}
	if len(c.warnings) != 0 {
		t.Errorf("member-account denial must not warn, got %v", c.warnings)
	}
	if got := orgAccounts.membership([]string{"111111111111"}); got != nil {
		t.Errorf("expected nil membership without evaluation, got %v", *got)
	}
}

func TestCollectOrganizationAccounts_UnexpectedErrorWarns(t *testing.T) {
	c := &Collector{}
	metrics := &IAMMetrics{}
	client := fakeIAMClient{orgAccountsErr: errors.New("Throttling: rate exceeded")}

	c.collectOrganizationAccounts(context.Background(), client, "203984714075", metrics)

	if len(c.warnings) != 1 {
		t.Errorf("expected 1 warning for unexpected error, got %v", c.warnings)
	}
}

func TestCollectOrganizationAccounts_Success(t *testing.T) {
	c := &Collector{}
	metrics := &IAMMetrics{}
	client := fakeIAMClient{orgAccountIDs: []string{"203984714075", "111111111111"}}

	orgAccounts := c.collectOrganizationAccounts(context.Background(), client, "203984714075", metrics)

	if !metrics.OrganizationAccountsEvaluated {
		t.Error("expected OrganizationAccountsEvaluated true")
	}
	if got := orgAccounts.membership([]string{"111111111111"}); got == nil || !*got {
		t.Errorf("expected in-org true, got %v", got)
	}
	if got := orgAccounts.membership([]string{"999999999999"}); got == nil || *got {
		t.Errorf("expected in-org false for unknown account, got %v", got)
	}
}

func TestCollectIAMMetricsPasswordPolicyStates(t *testing.T) {
	maxAge := 90
	reuse := 5

	t.Run("configured policy is projected onto the artifact", func(t *testing.T) {
		c := &Collector{}
		metrics := c.collectIAMMetrics(context.Background(), fakeIAMClient{
			report: &aws.CredentialReport{},
			passwordPolicy: &aws.PasswordPolicy{
				MinimumPasswordLength:   14,
				RequireSymbols:          true,
				RequireNumbers:          true,
				RequireUppercase:        true,
				RequireLowercase:        true,
				ExpirePasswords:         true,
				MaxPasswordAge:          &maxAge,
				PasswordReusePrevention: &reuse,
			},
		}, "123456789012", componentsdk.LevelTrust)

		if !metrics.PasswordPolicyEvaluated {
			t.Fatal("PasswordPolicyEvaluated = false, want true")
		}
		if metrics.PasswordPolicy == nil {
			t.Fatal("PasswordPolicy = nil, want the configured policy")
		}
		if metrics.PasswordPolicy.MinimumLength != 14 {
			t.Errorf("MinimumLength = %d, want 14", metrics.PasswordPolicy.MinimumLength)
		}
		if got := metrics.PasswordPolicy.MaxPasswordAgeDays; got == nil || *got != 90 {
			t.Errorf("MaxPasswordAgeDays = %v, want 90", got)
		}
		if got := metrics.PasswordPolicy.PasswordReusePrevention; got == nil || *got != 5 {
			t.Errorf("PasswordReusePrevention = %v, want 5", got)
		}
	})

	// AWS answers "no policy" by succeeding with nothing. That is a finding,
	// not a gap: the account falls back to AWS's own default of eight
	// characters with no complexity requirement.
	t.Run("no policy configured is an answer, not a failure", func(t *testing.T) {
		c := &Collector{}
		metrics := c.collectIAMMetrics(context.Background(), fakeIAMClient{report: &aws.CredentialReport{}}, "123456789012", componentsdk.LevelTrust)

		if !metrics.PasswordPolicyEvaluated {
			t.Fatal("PasswordPolicyEvaluated = false, want true when AWS reports no policy")
		}
		if metrics.PasswordPolicy != nil {
			t.Fatalf("PasswordPolicy = %+v, want nil when none is configured", metrics.PasswordPolicy)
		}
		if metrics.PasswordPolicyErrorCode != "" {
			t.Errorf("PasswordPolicyErrorCode = %q, want empty", metrics.PasswordPolicyErrorCode)
		}
	})

	t.Run("a failed lookup stays distinguishable from no policy", func(t *testing.T) {
		c := &Collector{}
		metrics := c.collectIAMMetrics(context.Background(), fakeIAMClient{
			report:      &aws.CredentialReport{},
			passwordErr: errors.New("AccessDenied: not authorized to perform iam:GetAccountPasswordPolicy"),
		}, "123456789012", componentsdk.LevelTrust)

		if metrics.PasswordPolicyEvaluated {
			t.Fatal("PasswordPolicyEvaluated = true, want false when the lookup failed")
		}
		if metrics.PasswordPolicy != nil {
			t.Fatalf("PasswordPolicy = %+v, want nil", metrics.PasswordPolicy)
		}
		if metrics.PasswordPolicyErrorCode == "" {
			t.Error("PasswordPolicyErrorCode is empty, want the cause recorded")
		}
	})
}
