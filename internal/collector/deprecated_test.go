package collector

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

// The tests in this file cover the deprecated blocks in deprecated.go. They
// are the tests those blocks had in v0.6.0.

func TestToCloudPosture_UncollectedIAMOmitted(t *testing.T) {
	// A credential-report failure (e.g. generation timeout) must not surface as
	// worst-case metrics in the normalized artifact: the IAM fields are omitted
	// entirely rather than emitted as 0% / false.
	output := &Output{
		SchemaVersion: "1.0.0",
		Accounts: []AccountPosture{
			{
				AccountID: "123456789012",
				IAM: IAMMetrics{
					CredentialReportErrorCode: "CredentialReportTimeout",
				},
			},
		},
	}

	cloudPosture := output.ToCloudPosture()

	iam := cloudPosture.Accounts[0].IAM
	if iam.MFACoveragePct != nil {
		t.Errorf("MFACoveragePct = %v, want nil", *iam.MFACoveragePct)
	}
	if iam.AccessKeyRotationCompliantPct != nil {
		t.Errorf("AccessKeyRotationCompliantPct = %v, want nil", *iam.AccessKeyRotationCompliantPct)
	}
	if iam.RootMFAEnabled != nil {
		t.Errorf("RootMFAEnabled = %v, want nil", *iam.RootMFAEnabled)
	}
	if iam.RootAccessProtected != nil {
		t.Errorf("RootAccessProtected = %v, want nil", *iam.RootAccessProtected)
	}

	jsonBytes, err := json.Marshal(cloudPosture)
	if err != nil {
		t.Fatalf("failed to marshal CloudPosture: %v", err)
	}
	var data map[string]any
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	// A metric group with nothing collected in it is left out whole.
	if iamJSON, present := data["accounts"].([]any)[0].(map[string]any)["iam"]; present {
		t.Errorf("iam group serialized with nothing collected: %v", iamJSON)
	}
	var iamJSON map[string]any
	for _, field := range []string{"mfa_coverage_pct", "root_mfa_enabled", "root_access_protected", "access_key_rotation_compliant_pct"} {
		if _, present := iamJSON[field]; present {
			t.Errorf("uncollected iam field %s serialized; want omitted", field)
		}
	}
}

func TestToCloudPosture_RootStateFromSummarySurvivesReportFailure(t *testing.T) {
	// Root state can be evaluated from the account summary even when the
	// credential report failed; only the report-derived aggregates are omitted.
	output := &Output{
		SchemaVersion: "1.0.0",
		Accounts: []AccountPosture{
			{
				AccountID: "123456789012",
				IAM: IAMMetrics{
					CredentialReportErrorCode:    "CredentialReportTimeout",
					RootCredentialStateEvaluated: true,
					RootMFAEnabled:               true,
					RootAccessProtected:          true,
				},
			},
		},
	}

	iam := output.ToCloudPosture().Accounts[0].IAM
	if iam.MFACoveragePct != nil {
		t.Errorf("MFACoveragePct = %v, want nil", *iam.MFACoveragePct)
	}
	if iam.RootMFAEnabled == nil || !*iam.RootMFAEnabled {
		t.Error("RootMFAEnabled != true, want true")
	}
	if iam.RootAccessProtected == nil || !*iam.RootAccessProtected {
		t.Error("RootAccessProtected != true, want true")
	}
}

// Inspector's findings in Security Hub could not be read, so the unpatched
// share is left out. Whether Inspector is on comes from its own status, and
// is left out only when a gap covers that read.
func TestToCloudPosture_UncollectedVulnScanningOmitted(t *testing.T) {
	output := &Output{
		Accounts: []AccountPosture{{
			AccountID: "123456789012",
			AccountSecurity: AccountSecurity{
				Inspector: InspectorStatus{Enabled: true, StatusErrorCode: "AccessDenied"},
			},
		}},
	}

	vuln := output.ToCloudPosture().Accounts[0].VulnScanning
	if vuln.Enabled == nil || !*vuln.Enabled {
		t.Errorf("Enabled = %v, want true", vuln.Enabled)
	}
	if vuln.UnpatchedPct != nil {
		t.Errorf("UnpatchedPct = %v, want nil", *vuln.UnpatchedPct)
	}

	gaps := newGapLog(nil)
	gaps.leaveOut(errors.New("AccessDenied"), "/accounts/0/account_security/inspector/enabled")
	if vuln := toCloudPosture(output, gaps).Accounts[0].VulnScanning; vuln.Enabled != nil {
		t.Errorf("Enabled = %v with the status unread, want nil", *vuln.Enabled)
	}
}

func TestNormalizedIAM_RootWithoutCredentialsCountsAsMFAProtected(t *testing.T) {
	removed := normalizedIAM(IAMMetrics{RootCredentialStateEvaluated: true, RootMFAEnabled: false, RootCredentialsPresent: false, RootAccessProtected: true})
	if removed.RootMFAEnabled == nil || !*removed.RootMFAEnabled {
		t.Errorf("root without credentials: root_mfa_enabled = %v, want true", removed.RootMFAEnabled)
	}

	unprotected := normalizedIAM(IAMMetrics{RootCredentialStateEvaluated: true, RootMFAEnabled: false, RootCredentialsPresent: true, RootAccessProtected: false})
	if unprotected.RootMFAEnabled == nil || *unprotected.RootMFAEnabled {
		t.Errorf("root password without MFA: root_mfa_enabled = %v, want false", unprotected.RootMFAEnabled)
	}
}

// The counts behind the IAM percentages are 0 over an empty population,
// where the percentage is left out, and left out where the credential
// report was not read. user_count is the users who can sign in, as
// members.local_member_count is, so it leaves out the users with only access
// keys. access_key_user_count is the users with an active access key, the
// root user included, as credential_count counts its keys, and the rotation
// share is over them.
func TestToCloudPosture_IAMCounts(t *testing.T) {
	account := evaluatedAccountFixture()
	account.IAM.IAMUserCount, account.IAM.ConsoleUserCount, account.IAM.AccessKeyUserCount, account.IAM.SAMLProviderCount = 7, 5, 2, intPtr(1)
	account.IAM.usage.keyUsers, account.IAM.usage.rotatedKeyUsers = 3, 2
	noUsers := evaluatedAccountFixture()
	noUsers.IAM.IAMUserCount, noUsers.IAM.ConsoleUserCount, noUsers.IAM.AccessKeyUserCount = 0, 0, 0
	noUsers.IAM.usage.keyUsers, noUsers.IAM.usage.rotatedKeyUsers = 0, 0
	noUsers.IAM.ConsoleMFAEnabled, noUsers.IAM.AccessKeysRotated = nil, nil
	unread := evaluatedAccountFixture()
	unread.IAM.CredentialReportEvaluated = false
	unread.IAM.SAMLProviderCount = nil

	posture := (&Output{Accounts: []AccountPosture{account, noUsers, unread}}).ToCloudPosture()

	got := posture.Accounts[0].IAM
	if !pctIs(got.UserCount, 5) || !pctIs(got.AccessKeyUserCount, 3) || !pctIs(got.SAMLProviderCount, 1) {
		t.Errorf("counts %s, %s, %s; want 5, 3, 1", showPct(got.UserCount), showPct(got.AccessKeyUserCount), showPct(got.SAMLProviderCount))
	}
	if got.AccessKeyRotationCompliantPct == nil || *got.AccessKeyRotationCompliantPct != 66 {
		t.Errorf("access_key_rotation_compliant_pct = %v, want 66", got.AccessKeyRotationCompliantPct)
	}
	got = posture.Accounts[1].IAM
	if !pctIs(got.UserCount, 0) || !pctIs(got.AccessKeyUserCount, 0) || got.MFACoveragePct != nil || got.AccessKeyRotationCompliantPct != nil {
		t.Errorf("no IAM users: counts %s and %s, percentages %v and %v; want 0, 0, and both left out",
			showPct(got.UserCount), showPct(got.AccessKeyUserCount), got.MFACoveragePct, got.AccessKeyRotationCompliantPct)
	}
	got = posture.Accounts[2].IAM
	if got.UserCount != nil || got.AccessKeyUserCount != nil || got.SAMLProviderCount != nil {
		t.Errorf("unread: counts %s, %s, %s; want all left out", showPct(got.UserCount), showPct(got.AccessKeyUserCount), showPct(got.SAMLProviderCount))
	}
}

func TestNormalizedWorkforceSignIn(t *testing.T) {
	accountInstance := orgInstance("d-1", 2, 0)
	accountInstance.InstanceType = "account"
	creating := orgInstance("d-1", 2, 0)
	creating.InstanceStatus = "CREATE_IN_PROGRESS"
	typeUnread := orgInstance("d-1", 2, 0)
	typeUnread.InstanceType = ""
	directoryUnread := orgInstance("d-1", 0, 0)
	directoryUnread.MFAEvidence = ""
	listingIncomplete := signInAccount(noInstance(), intPtr(0), intPtr(0))
	listingIncomplete.Regions = []string{"us-east-1", "us-west-2"}

	cases := []struct {
		name      string
		accounts  []AccountPosture
		failed    int
		inUse     *bool
		users     *int
		mfaSource string
	}{
		{"an organization instance in one account, its roles in another",
			[]AccountPosture{signInAccount(orgInstance("d-1", 3, 0), intPtr(0), intPtr(0)), signInAccount(noInstance(), intPtr(2), intPtr(1))},
			0, boolPtr(true), intPtr(3), "sign_in_service"},
		{"no Identity Center in any account",
			[]AccountPosture{signInAccount(noInstance(), intPtr(0), intPtr(0)), signInAccount(noInstance(), intPtr(0), intPtr(0))},
			0, boolPtr(false), nil, ""},
		{"roles in a member account that cannot see the instance",
			[]AccountPosture{signInAccount(noInstance(), intPtr(1), intPtr(0))},
			0, boolPtr(true), nil, "unknown"},
		{"Identity Center's SAML provider alone",
			[]AccountPosture{signInAccount(noInstance(), intPtr(0), intPtr(1))},
			0, boolPtr(true), nil, "unknown"},
		{"SAML providers unread, the instance and role listings found neither",
			[]AccountPosture{signInAccount(noInstance(), intPtr(0), nil)},
			0, boolPtr(false), nil, ""},
		{"an account instance",
			[]AccountPosture{signInAccount(accountInstance, intPtr(0), intPtr(0))},
			0, boolPtr(false), nil, ""},
		{"an instance still being created",
			[]AccountPosture{signInAccount(creating, intPtr(0), intPtr(0))},
			0, boolPtr(false), nil, ""},
		{"two accounts see the same directory",
			[]AccountPosture{signInAccount(orgInstance("d-1", 2, 2), intPtr(0), intPtr(0)), signInAccount(orgInstance("d-1", 2, 2), intPtr(1), intPtr(1))},
			0, boolPtr(true), intPtr(2), "external_idp"},
		{"two directories",
			[]AccountPosture{signInAccount(orgInstance("d-1", 2, 2), intPtr(0), intPtr(0)), signInAccount(orgInstance("d-2", 1, 0), intPtr(0), intPtr(0))},
			0, boolPtr(true), intPtr(3), "unknown"},
		{"a directory with no users",
			[]AccountPosture{signInAccount(orgInstance("d-1", 0, 0), intPtr(0), intPtr(0))},
			0, boolPtr(true), intPtr(0), "unknown"},
		{"an instance listing that failed in a region",
			[]AccountPosture{listingIncomplete},
			0, nil, nil, ""},
		{"roles unread",
			[]AccountPosture{signInAccount(noInstance(), nil, intPtr(0))},
			0, nil, nil, ""},
		{"an instance whose type is unread",
			[]AccountPosture{signInAccount(typeUnread, intPtr(0), intPtr(0))},
			0, nil, nil, ""},
		{"roles show it in use where another account's listing failed",
			[]AccountPosture{signInAccount(noInstance(), intPtr(1), intPtr(1)), listingIncomplete},
			0, boolPtr(true), nil, ""},
		{"the directory unread",
			[]AccountPosture{signInAccount(directoryUnread, intPtr(0), intPtr(0))},
			0, boolPtr(true), nil, ""},
		{"an account that failed, nothing elsewhere",
			[]AccountPosture{signInAccount(noInstance(), intPtr(0), intPtr(0))},
			1, nil, nil, ""},
		{"an account that failed, roles elsewhere",
			[]AccountPosture{signInAccount(noInstance(), intPtr(1), intPtr(0))},
			1, boolPtr(true), nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output := &Output{Accounts: tc.accounts}
			for i := 0; i < tc.failed; i++ {
				output.FailedAccounts = append(output.FailedAccounts, FailedAccountRecord{ErrorCode: "AccessDenied"})
			}
			got := output.ToCloudPosture().WorkforceSignIn
			if !samePtr(got.InUse, tc.inUse) || !sameInt(got.UserCount, tc.users) || got.MFASource != tc.mfaSource {
				t.Errorf("in_use %v, user_count %s, mfa_source %q; want %v, %s, %q",
					showBool(got.InUse), showPct(got.UserCount), got.MFASource, showBool(tc.inUse), showPct(tc.users), tc.mfaSource)
			}
		})
	}
}

// A folded value left out carries the gap of the read that left it unknown.
func TestNormalizedWorkforceSignIn_LeftOutValuesCarryTheirGap(t *testing.T) {
	c := newTestCollector(Config{})
	listing := componentsdk.CodeError(componentsdk.CodeRateLimited, errors.New("Throttling: Rate exceeded"))
	c.gaps.leaveOut(listing, "/accounts/0/identity_center")
	account := signInAccount(IdentityCenterStatus{}, intPtr(0), intPtr(0))

	posture := c.cloudPosture(&Output{Accounts: []AccountPosture{account}})

	if posture.WorkforceSignIn.InUse != nil {
		t.Errorf("in_use = %v, want it left out", *posture.WorkforceSignIn.InUse)
	}
	for _, pointer := range []string{"/workforce_sign_in/in_use", "/workforce_sign_in/user_count", "/workforce_sign_in/mfa_source"} {
		if g := normalizedGap(c, pointer); g == nil || g.Code != componentsdk.CodeRateLimited {
			t.Errorf("%s: gap %+v, want the instance listing's rate_limited", pointer, g)
		}
	}

	c = newTestCollector(Config{})
	users := componentsdk.CodeError(componentsdk.CodePermissionDenied, errors.New("AccessDeniedException: not authorized to perform: identitystore:ListUsers"))
	c.gaps.leaveOut(users, "/accounts/0/identity_center/user_count")
	unread := orgInstance("d-1", 0, 0)
	unread.MFAEvidence = ""
	posture = c.cloudPosture(&Output{Accounts: []AccountPosture{signInAccount(unread, intPtr(0), intPtr(0))}})
	if !samePtr(posture.WorkforceSignIn.InUse, boolPtr(true)) {
		t.Errorf("in_use = %s, want true from the instance", showBool(posture.WorkforceSignIn.InUse))
	}
	if g := normalizedGap(c, "/workforce_sign_in/in_use"); g != nil {
		t.Errorf("in_use has a gap: %+v", g)
	}
	for _, pointer := range []string{"/workforce_sign_in/user_count", "/workforce_sign_in/mfa_source"} {
		if g := normalizedGap(c, pointer); g == nil || g.Code != componentsdk.CodePermissionDenied {
			t.Errorf("%s: gap %+v, want the user listing's permission_denied", pointer, g)
		}
	}
}
