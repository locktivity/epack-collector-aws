package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

// accessAccount is an account scanned in us-east-1 with an organization
// instance of Identity Center, users IAM users of whom mfa have MFA and
// inactive are inactive, admins admins of whom mfaAdmins have MFA, and keys
// active access keys of which overdue are overdue for rotation.
func accessAccount(users, mfa, inactive, admins, mfaAdmins, keys, overdue int) AccountPosture {
	return AccountPosture{
		AccountID: "111111111111",
		Regions:   []string{"us-east-1"},
		IAM: IAMMetrics{
			CredentialReportEvaluated: true, IAMUserCount: users, MFAEnabledUserCount: mfa,
			RootCredentialStateEvaluated: true, RootMFAEnabled: true,
			SAMLProviderCount: intPtr(0), IdentityCenterSAMLProviderCount: intPtr(0), IdentityCenterRoleCount: intPtr(0),
			usage: iamUsage{inactiveUsers: inactive, activeKeys: keys, rotationOverdueKeys: overdue},
		},
		IdentityCenter: orgInstance("d-1", 5, 0),
		admins:         iamAdmins{read: true, admins: admins, mfaAdmins: mfaAdmins},
	}
}

// accessGap returns the gap recorded at pointer in the access-posture
// artifact, or nil.
func accessGap(gaps *gapLog, pointer string) *componentsdk.Gap {
	for _, g := range gaps.rec.Gaps() {
		if g.Path == accessPosturePath && g.Pointer == pointer {
			return &g
		}
	}
	return nil
}

func pctReading(r Reading[float64], want float64) bool {
	return r.Read && r.Value != nil && *r.Value == want
}

// Whether SSO or MFA is required, admin MFA over the admins present,
// never-expiring keys over the keys present, and inactive members over the
// members present.
func TestAccessPosture_RequirementsAndCoverage(t *testing.T) {
	gaps := newGapLog(nil)
	output := &Output{CollectedAtLevel: string(componentsdk.LevelAudit), Accounts: []AccountPosture{accessAccount(4, 3, 1, 2, 1, 3, 1)}}

	got := toAccessPosture(output, gaps)

	if !samePtr(got.SignIn.SSOConfigured, boolPtr(true)) {
		t.Errorf("sso_configured = %s, want true", showBool(got.SignIn.SSOConfigured))
	}
	for _, pointer := range []string{"/sign_in/sso_required", "/sign_in/mfa_required", "/scopes/0/sign_in/sso_required", "/scopes/0/sign_in/mfa_required"} {
		if g := accessGap(gaps, pointer); g == nil || g.Code != componentsdk.CodeUnsupported {
			t.Errorf("%s: gap %+v, want unsupported", pointer, g)
		}
	}
	for _, pointer := range []string{"/credentials/unrestricted_pct", "/credentials/write_access_pct", "/connected_apps", "/scopes/0/members/sso_member_count"} {
		if g := accessGap(gaps, pointer); g == nil || g.Code != componentsdk.CodeNotRead {
			t.Errorf("%s: gap %+v, want not_read", pointer, g)
		}
	}
	if !samePtr(got.Admins.LocalAdminsPresent, boolPtr(true)) || !pctReading(got.Admins.LocalAdminMFACoveragePct, 50) {
		t.Errorf("local admins present %s, MFA coverage %+v; want true and 50", showBool(got.Admins.LocalAdminsPresent), got.Admins.LocalAdminMFACoveragePct)
	}
	if !samePtr(got.Credentials.CredentialsPresent, boolPtr(true)) || !pctReading(got.Credentials.NeverExpiringPct, 100) {
		t.Errorf("credentials present %s, never expiring %+v; want true and 100", showBool(got.Credentials.CredentialsPresent), got.Credentials.NeverExpiringPct)
	}
	if !samePtr(got.Members.MembersPresent, boolPtr(true)) || !pctReading(got.Members.InactivePct, 25) {
		t.Errorf("members present %s, inactive %+v; want true and 25", showBool(got.Members.MembersPresent), got.Members.InactivePct)
	}
	if !pctReading(got.Members.LocalMFACoveragePct, 75) || !pctReading(got.Admins.AdminSharePct, 50) || !pctReading(got.Credentials.RotationOverduePct, 34) {
		t.Errorf("member MFA %+v, admin share %+v, overdue rotation %+v; want 75, 50, and 34",
			got.Members.LocalMFACoveragePct, got.Admins.AdminSharePct, got.Credentials.RotationOverduePct)
	}
	if !sameInt(got.Members.SSOMemberCount, intPtr(5)) || !sameInt(got.Root.RootAccountCount, intPtr(1)) {
		t.Errorf("sso members %s, root accounts %s; want 5 and 1", showPct(got.Members.SSOMemberCount), showPct(got.Root.RootAccountCount))
	}
	if len(got.Scopes) != 1 || got.Scopes[0].ID != "111111111111" || !sameInt(got.Scopes[0].Admins.AdminCount, intPtr(2)) {
		t.Errorf("scopes = %+v, want the account with its 2 admins", got.Scopes)
	}
}

// At the trust level the counts and the scopes are left out, and the present
// flags and percentages are written.
func TestAccessPosture_TrustLeavesOutCountsAndScopes(t *testing.T) {
	gaps := newGapLog(nil)
	output := &Output{CollectedAtLevel: string(componentsdk.LevelTrust), Accounts: []AccountPosture{accessAccount(4, 3, 1, 2, 1, 3, 1)}}

	got := toAccessPosture(output, gaps)

	if got.Scopes != nil {
		t.Errorf("scopes = %+v, want them left out", got.Scopes)
	}
	if got.Members.MemberCount != nil || got.Members.SSOMemberCount != nil || got.Admins.AdminCount != nil || got.Credentials.CredentialCount != nil || got.Root.RootAccountCount != nil {
		t.Error("a trust-level count was written")
	}
	if !samePtr(got.Admins.AdminsPresent, boolPtr(true)) || !pctReading(got.Admins.LocalAdminMFACoveragePct, 50) {
		t.Errorf("admins present %s, admin MFA %+v; want true and 50", showBool(got.Admins.AdminsPresent), got.Admins.LocalAdminMFACoveragePct)
	}
	for _, g := range gaps.rec.Gaps() {
		if g.Pointer == "/members/external_member_count" || g.Pointer == "/scopes/0/members/sso_member_count" {
			t.Errorf("a gap at %s, which the trust level does not write", g.Pointer)
		}
	}
}

// An empty population writes its present flag false and its percentages
// null.
func TestAccessPosture_EmptyPopulationsWriteNull(t *testing.T) {
	gaps := newGapLog(nil)
	output := &Output{CollectedAtLevel: string(componentsdk.LevelAudit), Accounts: []AccountPosture{accessAccount(0, 0, 0, 0, 0, 0, 0)}}

	got := toAccessPosture(output, gaps)

	for name, present := range map[string]*bool{
		"members_present": got.Members.MembersPresent, "local_members_present": got.Members.LocalMembersPresent,
		"admins_present": got.Admins.AdminsPresent, "local_admins_present": got.Admins.LocalAdminsPresent,
		"credentials_present": got.Credentials.CredentialsPresent,
	} {
		if !samePtr(present, boolPtr(false)) {
			t.Errorf("%s = %s, want false", name, showBool(present))
		}
	}
	for name, r := range map[string]Reading[float64]{
		"local_mfa_coverage_pct": got.Members.LocalMFACoveragePct, "inactive_pct": got.Members.InactivePct,
		"admin_share_pct": got.Admins.AdminSharePct, "local_admin_mfa_coverage_pct": got.Admins.LocalAdminMFACoveragePct,
		"never_expiring_pct": got.Credentials.NeverExpiringPct, "unused_pct": got.Credentials.UnusedPct,
		"rotation_overdue_pct": got.Credentials.RotationOverduePct,
	} {
		if !nullReading(r) {
			t.Errorf("%s = %+v, want null", name, r)
		}
	}
}

// The totals add up the accounts. A present flag is true when any account's
// is, and sso_configured only when every account's is. A failed account
// leaves each total out with its error, but not a present flag another
// account already sets.
func TestAccessPosture_FoldsAccounts(t *testing.T) {
	second := accessAccount(1, 1, 0, 0, 0, 0, 0)
	second.AccountID = "222222222222"
	second.IdentityCenter = noInstance()
	output := &Output{CollectedAtLevel: string(componentsdk.LevelAudit), Accounts: []AccountPosture{accessAccount(2, 1, 0, 1, 1, 1, 0), second}}

	got := toAccessPosture(output, newGapLog(nil))

	if !samePtr(got.SignIn.SSOConfigured, boolPtr(false)) {
		t.Errorf("sso_configured = %s, want false since the second account has no SSO", showBool(got.SignIn.SSOConfigured))
	}
	if !sameInt(got.Members.MemberCount, intPtr(3)) || !pctReading(got.Members.LocalMFACoveragePct, 66) || !sameInt(got.Root.RootAccountCount, intPtr(2)) {
		t.Errorf("members %s, MFA %+v, root accounts %s; want 3, 66, and 2", showPct(got.Members.MemberCount), got.Members.LocalMFACoveragePct, showPct(got.Root.RootAccountCount))
	}
	if len(got.Scopes) != 2 || !samePtr(got.Scopes[1].SignIn.SSOConfigured, boolPtr(false)) {
		t.Errorf("scopes = %+v, want the second account without SSO", got.Scopes)
	}

	failure := componentsdk.CodeError(componentsdk.CodePermissionDenied, errors.New("AccessDenied"))
	output.FailedAccounts = []FailedAccountRecord{{AccountID: "333333333333", ErrorCode: "AccessDenied", err: failure}}
	gaps := newGapLog(nil)
	got = toAccessPosture(output, gaps)

	if !samePtr(got.Members.MembersPresent, boolPtr(true)) || !samePtr(got.Admins.AdminsPresent, boolPtr(true)) || !samePtr(got.SignIn.SSOConfigured, boolPtr(false)) {
		t.Errorf("members present %s, admins present %s, sso_configured %s; want true, true, and false from the accounts collected",
			showBool(got.Members.MembersPresent), showBool(got.Admins.AdminsPresent), showBool(got.SignIn.SSOConfigured))
	}
	for _, pointer := range []string{"/members/member_count", "/members/local_mfa_coverage_pct", "/admins/local_admin_mfa_coverage_pct", "/credentials/never_expiring_pct", "/root/root_account_count"} {
		if g := accessGap(gaps, pointer); g == nil || g.Code != componentsdk.CodePermissionDenied {
			t.Errorf("%s: gap %+v, want the failed account's permission_denied", pointer, g)
		}
	}
	if len(got.Scopes) != 2 {
		t.Errorf("%d scopes, want the 2 accounts collected", len(got.Scopes))
	}
}

// A user whose policies could not be read leaves the admin counts and
// percentages out with a partial gap. admins_present stays true when another
// user is an admin.
func TestAccessPosture_UnmeasuredAdmins(t *testing.T) {
	account := accessAccount(3, 3, 0, 1, 1, 0, 0)
	account.admins = iamAdmins{read: true, admins: 1, mfaAdmins: 1, unmeasured: 1, err: componentsdk.CodeError(componentsdk.CodePermissionDenied, errors.New("AccessDenied"))}
	gaps := newGapLog(nil)

	got := toAccessPosture(&Output{CollectedAtLevel: string(componentsdk.LevelAudit), Accounts: []AccountPosture{account}}, gaps)

	if !samePtr(got.Admins.AdminsPresent, boolPtr(true)) {
		t.Errorf("admins_present = %s, want true", showBool(got.Admins.AdminsPresent))
	}
	for _, pointer := range []string{"/admins/admin_count", "/admins/local_admin_mfa_coverage_pct", "/admins/admin_share_pct"} {
		g := accessGap(gaps, pointer)
		if g == nil || g.Status != componentsdk.GapPartial || g.Unmeasured != 1 || g.Code != componentsdk.CodePermissionDenied {
			t.Errorf("%s: gap %+v, want partial permission_denied with 1 unmeasured", pointer, g)
		}
	}

	account.admins.admins, account.admins.mfaAdmins = 0, 0
	gaps = newGapLog(nil)
	got = toAccessPosture(&Output{CollectedAtLevel: string(componentsdk.LevelAudit), Accounts: []AccountPosture{account}}, gaps)
	if got.Admins.AdminsPresent != nil || accessGap(gaps, "/admins/admins_present") == nil {
		t.Errorf("admins_present = %s, want it left out with a gap when no user read is an admin", showBool(got.Admins.AdminsPresent))
	}
}

// Without the credential report, the members, admins, and keys are left out
// with the report's gap, and the root user is still read from the account
// summary.
func TestAccessPosture_CredentialReportFailed(t *testing.T) {
	account := accessAccount(0, 0, 0, 0, 0, 0, 0)
	account.IAM.CredentialReportEvaluated = false
	account.admins = iamAdmins{}
	gaps := newGapLog(nil)
	timeout := componentsdk.CodeError(componentsdk.CodeTimeout, errors.New("credential report not ready"))
	gaps.leaveOut(timeout, "/accounts/0/iam/iam_user_count", "/accounts/0/iam/access_key_user_count", "/accounts/0/iam/mfa_enabled_user_count")

	got := toAccessPosture(&Output{CollectedAtLevel: string(componentsdk.LevelAudit), Accounts: []AccountPosture{account}}, gaps)

	for _, pointer := range []string{"/members/members_present", "/members/inactive_pct", "/admins/admins_present", "/admins/local_admin_mfa_coverage_pct", "/credentials/credentials_present", "/credentials/never_expiring_pct"} {
		if g := accessGap(gaps, pointer); g == nil || g.Code != componentsdk.CodeTimeout {
			t.Errorf("%s: gap %+v, want the report's timeout", pointer, g)
		}
	}
	if got.Members.MembersPresent != nil || got.Credentials.NeverExpiringPct.Read {
		t.Error("a value over the unread report was written")
	}
	if !pctReading(got.Root.RootMFACoveragePct, 100) {
		t.Errorf("root MFA = %+v, want 100 from the account summary", got.Root.RootMFACoveragePct)
	}
}

// A root user with MFA, or with no password, access key, or signing
// certificate, counts as covered. A root user with a password and no MFA
// does not.
func TestAccessPosture_RootMFA(t *testing.T) {
	for _, tc := range []struct {
		name             string
		mfa, credentials bool
		want             float64
	}{
		{"MFA", true, true, 100},
		{"no credentials", false, false, 100},
		{"password without MFA", false, true, 0},
	} {
		account := accessAccount(0, 0, 0, 0, 0, 0, 0)
		account.IAM.RootMFAEnabled, account.IAM.RootCredentialsPresent = tc.mfa, tc.credentials
		got := toAccessPosture(&Output{Accounts: []AccountPosture{account}}, newGapLog(nil))
		if !pctReading(got.Root.RootMFACoveragePct, tc.want) {
			t.Errorf("%s: root MFA coverage = %+v, want %v", tc.name, got.Root.RootMFACoveragePct, tc.want)
		}
	}
}

// SSO counts as configured for an organization instance, the roles or SAML
// provider Identity Center creates, or a SAML provider the account trusts
// directly. A listing that failed leaves it unknown unless another one shows
// SSO.
func TestSSOConfiguredOf(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		idc                    IdentityCenterStatus
		roles, idcSAML, direct *int
		failed                 string
		want                   *bool
	}{
		{name: "organization instance", idc: orgInstance("d-1", 1, 0), roles: intPtr(0), idcSAML: intPtr(0), direct: intPtr(0), want: boolPtr(true)},
		{name: "Identity Center roles", idc: noInstance(), roles: intPtr(2), idcSAML: intPtr(0), direct: intPtr(0), want: boolPtr(true)},
		{name: "Identity Center SAML provider", idc: noInstance(), roles: intPtr(0), idcSAML: intPtr(1), direct: intPtr(0), want: boolPtr(true)},
		{name: "direct SAML provider", idc: noInstance(), roles: intPtr(0), idcSAML: intPtr(0), direct: intPtr(1), want: boolPtr(true)},
		{name: "none", idc: noInstance(), roles: intPtr(0), idcSAML: intPtr(0), direct: intPtr(0), want: boolPtr(false)},
		{name: "SAML listing failed", idc: noInstance(), roles: intPtr(0), failed: "saml_provider_count", want: nil},
		{name: "SAML listing failed, roles show it", idc: noInstance(), roles: intPtr(1), failed: "saml_provider_count", want: boolPtr(true)},
	} {
		account := AccountPosture{
			Regions:        []string{"us-east-1"},
			IAM:            IAMMetrics{IdentityCenterRoleCount: tc.roles, IdentityCenterSAMLProviderCount: tc.idcSAML, SAMLProviderCount: tc.direct},
			IdentityCenter: tc.idc,
		}
		gaps := newGapLog(nil)
		if tc.failed != "" {
			gaps.leaveOut(errors.New("AccessDenied"), "/accounts/0/iam/"+tc.failed, "/accounts/0/iam/identity_center_saml_provider_count")
		}
		got := ssoConfiguredOf(account, accountAt(0), gaps)
		switch {
		case tc.want == nil && got.why == nil:
			t.Errorf("%s: sso_configured = %t, want it unknown", tc.name, got.v)
		case tc.want != nil && (got.why != nil || got.v != *tc.want):
			t.Errorf("%s: sso_configured = %t (unknown %t), want %t", tc.name, got.v, got.why != nil, *tc.want)
		}
	}
}

// A collect list that leaves out the access-posture and vuln-scanning files
// skips the calls only they need, and records each file as not shared. The
// deprecated cloud-posture blocks that moved to them are left out too, each
// with a not_shared gap.
func TestCollectLeavesOutAccessAndVulnScanning(t *testing.T) {
	isolateAWSEnvironment(t)
	config := kitConfig()
	config["collect"] = []any{"cloud-posture", "details"}
	res := runKit(t, config, kitSecrets(), kitResponses())
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	for _, op := range res.Operations {
		if strings.HasPrefix(op.Name, "aws.inspector2.") || strings.HasPrefix(op.Name, "aws.iam.ListAttached") || op.Name == "aws.iam.ListGroupsForUser" {
			t.Errorf("%s was called %d times, want none", op.Name, op.Calls)
		}
	}
	for _, a := range res.Artifacts {
		if a.Path == accessPosturePath || a.Path == vulnScanningPath {
			t.Errorf("%s was written", a.Path)
		}
	}
	for _, schemaID := range []string{accessPostureSchema, vulnScanningSchema} {
		shared := false
		for _, g := range res.Result.Gaps {
			if g.Schema == schemaID && g.Code == componentsdk.CodeNotShared {
				shared = true
			}
		}
		if !shared {
			t.Errorf("%s has no not_shared gap", schemaID)
		}
	}
	var posture struct {
		Accounts        []map[string]any `json:"accounts"`
		WorkforceSignIn any              `json:"workforce_sign_in"`
	}
	for _, a := range res.Artifacts {
		if a.Path == cloudPosturePath {
			if err := json.Unmarshal(a.Data, &posture); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(posture.Accounts) == 0 || posture.WorkforceSignIn != nil {
		t.Errorf("cloud-posture has %d accounts and workforce_sign_in %v, want accounts and no workforce_sign_in", len(posture.Accounts), posture.WorkforceSignIn)
	}
	blocks := []string{"/workforce_sign_in"}
	for i, account := range posture.Accounts {
		for _, block := range []string{"iam", "vuln_scanning"} {
			if account[block] != nil {
				t.Errorf("account %d has %s = %v, which moved to a file collect leaves out", i, block, account[block])
			}
			blocks = append(blocks, fmt.Sprintf("/accounts/%d/%s", i, block))
		}
	}
	for _, pointer := range blocks {
		if g := gapAt(res, cloudPosturePath, pointer); g == nil || g.Code != componentsdk.CodeNotShared {
			t.Errorf("gap at %s = %+v, want not_shared", pointer, g)
		}
	}
	for _, g := range res.Result.Gaps {
		if g.Path == cloudPosturePath && (strings.Contains(g.Pointer, "/iam/") || strings.Contains(g.Pointer, "/vuln_scanning/") || strings.HasPrefix(g.Pointer, "/workforce_sign_in/")) {
			t.Errorf("gap %+v is inside a block the pack does not hold", g)
		}
	}
}

// With every kind collected, cloud-posture keeps the deprecated blocks.
func TestTheDeprecatedBlocksStayWithEveryKindCollected(t *testing.T) {
	isolateAWSEnvironment(t)
	res := runKit(t, kitConfig(), kitSecrets(), kitResponses())
	for _, a := range res.Artifacts {
		if a.Path != cloudPosturePath {
			continue
		}
		var posture struct {
			Accounts        []map[string]any `json:"accounts"`
			WorkforceSignIn any              `json:"workforce_sign_in"`
		}
		if err := json.Unmarshal(a.Data, &posture); err != nil {
			t.Fatal(err)
		}
		if len(posture.Accounts) == 0 || posture.Accounts[0]["iam"] == nil || posture.Accounts[0]["vuln_scanning"] == nil || posture.WorkforceSignIn == nil {
			t.Errorf("cloud-posture = %+v, want the deprecated blocks", posture)
		}
		return
	}
	t.Fatalf("no %s in %d artifacts", cloudPosturePath, len(res.Artifacts))
}
