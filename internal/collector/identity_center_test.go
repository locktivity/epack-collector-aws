package collector

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/smithy-go"
	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

func TestPermissionSetsToInventory_CopiesARNsDefensively(t *testing.T) {
	src := []string{"arn:aws:iam::aws:policy/AdministratorAccess"}
	in := []aws.IdentityCenterPermissionSet{
		{
			ARN:                    "arn:aws:sso:::permissionSet/ssoins-123/ps-abc",
			Name:                   "AdminAccess",
			Description:            "Full admin",
			SessionDurationISO8601: "PT8H",
			ManagedPoliciesCount:   1,
			AccountsAssignedCount:  3,
			ManagedPolicyARNs:      src,
			HasInlinePolicy:        true,
		},
		{
			ARN:                  "arn:aws:sso:::permissionSet/ssoins-123/ps-def",
			Name:                 "ReadOnly",
			ManagedPoliciesCount: 1,
		},
	}
	out := permissionSetsToInventory(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(out))
	}
	if out[0].Name != "AdminAccess" || out[0].SessionDurationISO8601 != "PT8H" || !out[0].HasInlinePolicy {
		t.Errorf("row 0 mis-projected: %+v", out[0])
	}
	if out[0].AccountsAssignedCount != 3 || out[0].ManagedPoliciesCount != 1 {
		t.Errorf("row 0 counts mis-projected: %+v", out[0])
	}

	// Defensive copy: mutating the source slice must not bleed into the projected row.
	src[0] = "mutated"
	if out[0].ManagedPolicyARNs[0] == "mutated" {
		t.Errorf("permissionSetsToInventory did not defensively copy ManagedPolicyARNs")
	}

	if len(out[1].ManagedPolicyARNs) != 0 {
		t.Errorf("row 1 (no ARNs) should have empty slice for omitempty, got %v", out[1].ManagedPolicyARNs)
	}
}

func TestIdentityStoreUsersToInventory_PreservesAllFields(t *testing.T) {
	in := []aws.IdentityStoreUser{
		{UserID: "u-1", UserName: "alice", DisplayName: "Alice Adams", PrimaryEmail: "alice@example.com"},
		{UserID: "u-2", UserName: "bob"},
	}
	out := identityStoreUsersToInventory(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(out))
	}
	if out[0].UserName != "alice" || out[0].PrimaryEmail != "alice@example.com" {
		t.Errorf("user 0 mis-projected: %+v", out[0])
	}
	if out[1].PrimaryEmail != "" {
		t.Errorf("user with no email should have empty PrimaryEmail, got %q", out[1].PrimaryEmail)
	}
}

func TestIdentityStoreGroupsToInventory_PropagatesMemberCount(t *testing.T) {
	in := []aws.IdentityStoreGroup{
		{GroupID: "g-1", DisplayName: "Admins", MemberCount: 5},
		{GroupID: "g-2", DisplayName: "Engineers"},
	}
	out := identityStoreGroupsToInventory(in)
	if out[0].MemberCount != 5 {
		t.Errorf("group 0 member count not propagated: %+v", out[0])
	}
	if out[1].MemberCount != 0 {
		t.Errorf("group 1 should have zero MemberCount, got %d", out[1].MemberCount)
	}
}

// fakeIdcClient is a focused mock for the idcClient interface. Every region
// answers the instance listing with instances and instancesErr, unless
// regionInstances or regionErrs names the region.
type fakeIdcClient struct {
	instances         []aws.IdentityCenterInstance
	instancesErr      error
	regionInstances   map[string][]aws.IdentityCenterInstance
	regionErrs        map[string]error
	users             []aws.IdentityStoreUser
	usersErr          error
	groups            []aws.IdentityStoreGroup
	groupsWithMembers []aws.IdentityStoreGroup
	groupsErr         error
	membersErr        error
	permSets          []aws.IdentityCenterPermissionSet
	permSetsErr       error
	describeErr       error
	assignments       map[string][]aws.IdentityCenterAssignment // keyed by "account:psARN"
	assignmentsErr    error
}

func (f fakeIdcClient) ListIdentityCenterInstances(_ context.Context, region string) ([]aws.IdentityCenterInstance, error) {
	if err := f.regionErrs[region]; err != nil {
		return nil, err
	}
	if instances, ok := f.regionInstances[region]; ok {
		return instances, nil
	}
	return f.instances, f.instancesErr
}

func (f fakeIdcClient) ListIdentityStoreUsers(_ context.Context, _, _ string) ([]aws.IdentityStoreUser, error) {
	return f.users, f.usersErr
}

func (f fakeIdcClient) ListIdentityStoreGroups(_ context.Context, _, _ string) ([]aws.IdentityStoreGroup, error) {
	return f.groups, f.groupsErr
}

func (f fakeIdcClient) ListIdentityStoreGroupMembers(_ context.Context, _, _ string, _ []aws.IdentityStoreGroup) ([]aws.IdentityStoreGroup, error) {
	return f.groupsWithMembers, f.membersErr
}

func (f fakeIdcClient) ListIdentityCenterPermissionSetARNs(_ context.Context, _, _ string) ([]string, error) {
	if f.permSetsErr != nil {
		return nil, f.permSetsErr
	}
	arns := make([]string, 0, len(f.permSets))
	for _, ps := range f.permSets {
		arns = append(arns, ps.ARN)
	}
	return arns, nil
}

func (f fakeIdcClient) DescribeIdentityCenterPermissionSets(_ context.Context, _, _ string, _ []string, _ bool) ([]aws.IdentityCenterPermissionSet, error) {
	return f.permSets, f.describeErr
}

func (f fakeIdcClient) ListIdentityCenterAccountAssignments(_ context.Context, _, _, accountID, psARN string) ([]aws.IdentityCenterAssignment, error) {
	if f.assignmentsErr != nil {
		return nil, f.assignmentsErr
	}
	return f.assignments[accountID+":"+psARN], nil
}

func rbacFakeClient() fakeIdcClient {
	return fakeIdcClient{
		instances: []aws.IdentityCenterInstance{{InstanceARN: "arn:aws:sso:::instance/ssoins-1", IdentityStoreID: "d-123", Region: "us-east-1", Status: "ACTIVE", OwnerAccountID: "111111111111"}},
		users: []aws.IdentityStoreUser{
			{UserID: "u-1", UserName: "ana", DisplayName: "Ana", PrimaryEmail: "ana@example.com"},
		},
		groups: []aws.IdentityStoreGroup{{GroupID: "g-1", DisplayName: "Admins"}},
		groupsWithMembers: []aws.IdentityStoreGroup{
			{GroupID: "g-1", DisplayName: "Admins", MemberCount: 1, MemberUserIDs: []string{"u-1"}},
		},
		permSets: []aws.IdentityCenterPermissionSet{
			{ARN: "ps-1", Name: "AdminAccess", AccountsAssignedCount: 1, ProvisionedAccountIDs: []string{"111111111111"}},
		},
		assignments: map[string][]aws.IdentityCenterAssignment{
			"111111111111:ps-1": {
				{AccountID: "111111111111", PermissionSetARN: "ps-1", PrincipalType: "GROUP", PrincipalID: "g-1"},
			},
		},
	}
}

func TestCollectIdentityCenter_AuditIncludesRosterAndAssignments(t *testing.T) {
	c := newTestCollector(Config{})

	status := c.collectIdentityCenter(context.Background(), rbacFakeClient(), []string{"us-east-1"}, "111111111111", accountAt(0), componentsdk.LevelAudit)

	if len(status.Users) != 1 || status.Users[0].UserID != "u-1" || status.Users[0].PrimaryEmail != "ana@example.com" {
		t.Errorf("audit users = %+v, want the roster", status.Users)
	}
	if len(status.Groups) != 1 || len(status.Groups[0].MemberUserIDs) != 1 || status.Groups[0].MemberUserIDs[0] != "u-1" {
		t.Errorf("audit groups = %+v, want member edges", status.Groups)
	}
	if len(status.PermissionSets) != 1 || len(status.PermissionSets[0].ProvisionedAccountIDs) != 1 {
		t.Errorf("audit permission sets = %+v, want provisioned account ids", status.PermissionSets)
	}
	if !status.AssignmentsEvaluated {
		t.Error("expected AssignmentsEvaluated true")
	}
	if len(status.AccountAssignments) != 1 {
		t.Fatalf("audit assignments = %+v, want 1 edge", status.AccountAssignments)
	}
	edge := status.AccountAssignments[0]
	if edge.AccountID != "111111111111" || edge.PermissionSetARN != "ps-1" || edge.PrincipalType != "GROUP" || edge.PrincipalID != "g-1" {
		t.Errorf("assignment edge = %+v", edge)
	}
}

func TestCollectIdentityCenter_TrustOmitsRoster(t *testing.T) {
	c := newTestCollector(Config{})

	status := c.collectIdentityCenter(context.Background(), rbacFakeClient(), []string{"us-east-1"}, "111111111111", accountAt(0), componentsdk.LevelTrust)

	if status.Users != nil || status.Groups != nil || status.AccountAssignments != nil {
		t.Errorf("trust must not carry roster or assignments: users=%v groups=%v assignments=%v", status.Users, status.Groups, status.AccountAssignments)
	}
	if status.UserCount != 1 || status.GroupCount != 1 || status.PermissionSetCount != 1 {
		t.Errorf("trust counts = %d/%d/%d, want 1/1/1", status.UserCount, status.GroupCount, status.PermissionSetCount)
	}
	if status.AssignmentsEvaluated {
		t.Error("AssignmentsEvaluated must stay false at trust")
	}
	requireNoGaps(t, c)
}

func TestCollectIdentityCenter_AssignmentFailureDiscardsPartial(t *testing.T) {
	c := newTestCollector(Config{})
	client := rbacFakeClient()
	client.assignmentsErr = errors.New("AccessDenied: no sso:ListAccountAssignments")

	status := c.collectIdentityCenter(context.Background(), client, []string{"us-east-1"}, "111111111111", accountAt(0), componentsdk.LevelAudit)

	if status.AssignmentsEvaluated {
		t.Error("expected AssignmentsEvaluated false on listing failure")
	}
	if len(status.AccountAssignments) != 0 {
		t.Errorf("expected empty assignments on failure, got %+v", status.AccountAssignments)
	}
	requireGap(t, c, "/accounts/0/identity_center/account_assignments")
	found := false
	for _, w := range c.warnings {
		if strings.Contains(w, "sso:ListAccountAssignments") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a warning naming sso:ListAccountAssignments, got %v", c.warnings)
	}
}

func TestCollectIdentityCenter_UserListingFailureLeavesRosterNull(t *testing.T) {
	c := newTestCollector(Config{})
	client := rbacFakeClient()
	client.usersErr = errors.New("Throttling")

	status := c.collectIdentityCenter(context.Background(), client, []string{"us-east-1"}, "111111111111", accountAt(0), componentsdk.LevelAudit)

	if status.Users != nil {
		t.Errorf("expected nil users on listing failure, got %+v", status.Users)
	}
	requireGap(t, c, "/accounts/0/identity_center/user_count", "/accounts/0/identity_center/users")
}

// AWS refuses an account instance's ARN on the permission set calls, and an
// account instance has no permission sets, so what those calls read is left
// out as not licensed.
func TestAccountInstancePermissionSetsAreNotLicensed(t *testing.T) {
	isolateAWSEnvironment(t)
	res := runKit(t, kitConfig(), kitSecrets(), replaceResponses(kitResponses(), collectortest.Response{
		Operation: "aws.ssoadmin.ListPermissionSets", Method: http.MethodPost, URL: regional("sso"), Status: http.StatusBadRequest,
		Header: jsonHeader("application/x-amz-json-1.1"),
		Body:   `{"__type":"ValidationException","Message":"Value of input 'instanceArn' failed to satisfy constraint: Member must satisfy regular expression pattern: arn:aws(-[a-z]{1,5}){0,3}:sso:::instance/(sso)?ins-[a-zA-Z0-9-.]{16}"}`,
	}))
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	for _, pointer := range []string{
		"/accounts/0/identity_center/permission_set_count",
		"/accounts/0/identity_center/permission_sets",
		"/accounts/0/identity_center/account_assignments",
	} {
		g := gapAt(res, awsPath, pointer)
		switch {
		case g == nil:
			t.Errorf("%s: no gap", pointer)
		case g.Code != componentsdk.CodeNotLicensed || g.Operation != "aws.ssoadmin.ListPermissionSets" || g.Call == 0:
			t.Errorf("%s: code %s, operation %q, call %d; want not_licensed naming a ListPermissionSets call", pointer, g.Code, g.Operation, g.Call)
		}
	}

	// An account instance cannot sign people in to AWS accounts, so with no
	// Identity Center roles here it does not count as in use.
	var detailed Output
	decodeArtifact(t, res, awsPath, &detailed)
	if got := detailed.Accounts[0].IdentityCenter.InstanceType; got != "account" {
		t.Errorf("instance_type = %q, want account", got)
	}
	var posture CloudPosture
	decodeArtifact(t, res, cloudPosturePath, &posture)
	if !samePtr(posture.WorkforceSignIn.InUse, boolPtr(false)) {
		t.Errorf("in_use = %s, want false", showBool(posture.WorkforceSignIn.InUse))
	}
}

// identityCenterInstance is an active organization instance in region.
func identityCenterInstance(region string) aws.IdentityCenterInstance {
	return aws.IdentityCenterInstance{InstanceARN: "arn:aws:sso:::instance/ssoins-1", IdentityStoreID: "d-123", Region: region, Status: "ACTIVE", OwnerAccountID: "111111111111"}
}

// The instance's home region need not be the first region scanned.
func TestCollectIdentityCenter_FindsInstanceInASecondRegion(t *testing.T) {
	c := newTestCollector(Config{})
	client := rbacFakeClient()
	client.regionInstances = map[string][]aws.IdentityCenterInstance{
		"us-east-1": {},
		"us-west-2": {identityCenterInstance("us-west-2")},
	}

	status := c.collectIdentityCenter(context.Background(), client, []string{"us-east-1", "us-west-2"}, "111111111111", accountAt(0), componentsdk.LevelTrust)

	if !status.Enabled || status.InstanceRegion != "us-west-2" {
		t.Errorf("enabled %v in %q, want the instance in us-west-2", status.Enabled, status.InstanceRegion)
	}
	if status.InstanceStatus != "ACTIVE" || status.InstanceOwnerAccountID != "111111111111" || status.InstanceType != "organization" {
		t.Errorf("status %q, owner %q, type %q; want an active organization instance this account owns", status.InstanceStatus, status.InstanceOwnerAccountID, status.InstanceType)
	}
	if len(status.RegionsChecked) != 2 || status.RegionsChecked[0] != "us-east-1" || status.RegionsChecked[1] != "us-west-2" {
		t.Errorf("regions checked = %v, want both, in order", status.RegionsChecked)
	}
	requireNoGaps(t, c)
}

// A region that did not answer could hold the instance, so with none found
// elsewhere, what an instance would set is left out over that region.
func TestCollectIdentityCenter_FailedRegionLeavesPartialGap(t *testing.T) {
	c := newTestCollector(Config{})
	client := rbacFakeClient()
	client.regionInstances = map[string][]aws.IdentityCenterInstance{"us-east-1": {}}
	client.regionErrs = map[string]error{"us-west-2": errors.New("Throttling: Rate exceeded")}

	status := c.collectIdentityCenter(context.Background(), client, []string{"us-east-1", "us-west-2"}, "111111111111", accountAt(0), componentsdk.LevelAudit)

	if status.Enabled || len(status.RegionsChecked) != 1 || status.RegionsChecked[0] != "us-east-1" {
		t.Errorf("enabled %v, regions checked %v; want no instance found and only us-east-1 checked", status.Enabled, status.RegionsChecked)
	}
	requireGap(t, c, "/accounts/0/identity_center/enabled", "/accounts/0/identity_center/user_count",
		"/accounts/0/identity_center/external_id_user_count", "/accounts/0/identity_center/users")
	if c.gaps.covered("/accounts/0/identity_center/regions_checked") {
		t.Error("the regions that answered are known")
	}
	if !hasWarning(c, "us-west-2") {
		t.Errorf("warnings = %v, want one naming the region that failed", c.warnings)
	}
}

// Once the instance turns up, a region that failed changes nothing.
func TestCollectIdentityCenter_InstanceFoundDespiteAFailedRegion(t *testing.T) {
	c := newTestCollector(Config{})
	client := rbacFakeClient()
	client.regionInstances = map[string][]aws.IdentityCenterInstance{"us-east-1": {identityCenterInstance("us-east-1")}}
	client.regionErrs = map[string]error{"us-west-2": errors.New("Throttling: Rate exceeded")}

	status := c.collectIdentityCenter(context.Background(), client, []string{"us-east-1", "us-west-2"}, "111111111111", accountAt(0), componentsdk.LevelTrust)

	if !status.Enabled || status.UserCount != 1 {
		t.Errorf("enabled %v with %d users, want the instance in us-east-1", status.Enabled, status.UserCount)
	}
	requireNoGaps(t, c)
}

func TestCollectIdentityCenter_EveryRegionFailingLeavesStatusOut(t *testing.T) {
	c := newTestCollector(Config{})
	client := rbacFakeClient()
	client.instancesErr = errors.New("AccessDeniedException: not authorized to perform: sso:ListInstances")

	c.collectIdentityCenter(context.Background(), client, []string{"us-east-1", "us-west-2"}, "111111111111", accountAt(0), componentsdk.LevelTrust)

	requireGap(t, c, "/accounts/0/identity_center")
	denials := 0
	for _, w := range c.warnings {
		if strings.Contains(w, "sso:ListInstances") {
			denials++
		}
	}
	if denials != 1 {
		t.Errorf("warnings = %v, want one naming sso:ListInstances", c.warnings)
	}
}

func TestIdentityCenterInstanceType(t *testing.T) {
	validation := &smithy.GenericAPIError{Code: "ValidationException", Message: "Value of input 'instanceArn' failed to satisfy constraint"}
	cases := []struct {
		name  string
		owner string
		err   error
		want  string
	}{
		{"another account owns it, seen from a delegated administrator", "999999999999", validation, "organization"},
		{"the permission set listing answers", "111111111111", nil, "organization"},
		{"the permission set listing refuses the instance", "111111111111", validation, "account"},
		{"the permission set listing failed", "111111111111", errors.New("Throttling: Rate exceeded"), ""},
		{"no owner and the listing denied", "", &smithy.GenericAPIError{Code: "AccessDeniedException"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inst := identityCenterInstance("us-east-1")
			inst.OwnerAccountID = tc.owner
			if got := identityCenterInstanceType(inst, "111111111111", tc.err); got != tc.want {
				t.Errorf("type = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIdentityCenterMFAEvidence(t *testing.T) {
	cases := []struct {
		users, withExternalID int
		want                  string
	}{
		{3, 3, "external_idp"},
		{3, 0, "manual_required"},
		{3, 1, "unknown"},
		{0, 0, "unknown"},
	}
	for _, tc := range cases {
		if got := identityCenterMFAEvidence(tc.users, tc.withExternalID); got != tc.want {
			t.Errorf("%d users, %d with an external ID: %q, want %q", tc.users, tc.withExternalID, got, tc.want)
		}
	}
}

func TestCollectIdentityCenter_DirectoryEvidence(t *testing.T) {
	client := rbacFakeClient()
	client.users = []aws.IdentityStoreUser{
		{UserID: "u-1", UserName: "ana", HasExternalID: true},
		{UserID: "u-2", UserName: "ben", HasExternalID: true},
	}
	c := newTestCollector(Config{})

	status := c.collectIdentityCenter(context.Background(), client, []string{"us-east-1"}, "111111111111", accountAt(0), componentsdk.LevelAudit)

	if status.UserCount != 2 || status.ExternalIDUserCount != 2 || status.MFAEvidence != "external_idp" {
		t.Errorf("%d users, %d with an external ID, evidence %q; want 2, 2, external_idp", status.UserCount, status.ExternalIDUserCount, status.MFAEvidence)
	}
	if len(status.Users) != 2 || !status.Users[0].HasExternalID {
		t.Errorf("users = %+v, want rows that say each has an external ID", status.Users)
	}

	client.usersErr = errors.New("Throttling: Rate exceeded")
	c = newTestCollector(Config{})
	status = c.collectIdentityCenter(context.Background(), client, []string{"us-east-1"}, "111111111111", accountAt(0), componentsdk.LevelTrust)
	if status.MFAEvidence != "" {
		t.Errorf("evidence = %q, want it left out with the directory unread", status.MFAEvidence)
	}
	requireGap(t, c, "/accounts/0/identity_center/mfa_evidence", "/accounts/0/identity_center/external_id_user_count")
}

// Trust counts permission sets from their listing alone, which the trust
// policy allows, so a denied describe call changes nothing there.
func TestCollectIdentityCenter_TrustCountsPermissionSetsWithoutDescribing(t *testing.T) {
	client := rbacFakeClient()
	client.describeErr = errors.New("AccessDeniedException: not authorized to perform: sso:DescribePermissionSet")
	c := newTestCollector(Config{})

	status := c.collectIdentityCenter(context.Background(), client, []string{"us-east-1"}, "111111111111", accountAt(0), componentsdk.LevelTrust)

	if status.PermissionSetCount != 1 || status.InstanceType != "organization" {
		t.Errorf("%d permission sets on a %q instance, want 1 on an organization instance", status.PermissionSetCount, status.InstanceType)
	}
	requireNoGaps(t, c)

	c = newTestCollector(Config{})
	status = c.collectIdentityCenter(context.Background(), client, []string{"us-east-1"}, "111111111111", accountAt(0), componentsdk.LevelAudit)
	if status.PermissionSetCount != 1 {
		t.Errorf("permission set count = %d, want the listing's 1", status.PermissionSetCount)
	}
	requireGap(t, c, "/accounts/0/identity_center/permission_sets", "/accounts/0/identity_center/account_assignments")
	if c.gaps.covered("/accounts/0/identity_center/permission_set_count") {
		t.Error("the count comes from the listing, which answered")
	}
}

// A permission set listing that fails for another reason than refusing an
// account instance leaves the instance's type unknown.
func TestCollectIdentityCenter_UnreadPermissionSetsLeaveTypeOut(t *testing.T) {
	client := rbacFakeClient()
	client.permSetsErr = errors.New("Throttling: Rate exceeded")
	c := newTestCollector(Config{})

	status := c.collectIdentityCenter(context.Background(), client, []string{"us-east-1"}, "111111111111", accountAt(0), componentsdk.LevelTrust)

	if status.InstanceType != "" {
		t.Errorf("type = %q, want it left out", status.InstanceType)
	}
	requireGap(t, c, "/accounts/0/identity_center/instance_type", "/accounts/0/identity_center/permission_set_count")
}

func hasWarning(c *Collector, substr string) bool {
	for _, w := range c.warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// A directory where some users came from SCIM provisioning and the rest
// carry an external ID from another issuer is a mix, so where its users' MFA
// is set is unknown. Neither issuer nor ID reaches the artifacts.
func TestIdentityCenterExternalIDsFromMixedIssuers(t *testing.T) {
	isolateAWSEnvironment(t)
	res := runKit(t, kitConfig(), kitSecrets(), externalIDUsersResponses(kitRootOnlyReport, kitSCIMIssuer, kitDirectoryIssuer))
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}

	var detailed Output
	decodeArtifact(t, res, awsPath, &detailed)
	idc := detailed.Accounts[0].IdentityCenter
	if idc.ExternalIDUserCount != 1 || idc.MFAEvidence != "unknown" {
		t.Errorf("%d users with a SCIM external ID, evidence %q; want 1 and unknown", idc.ExternalIDUserCount, idc.MFAEvidence)
	}
	if len(idc.Users) != 2 || !idc.Users[0].HasExternalID || idc.Users[1].HasExternalID {
		t.Errorf("users = %+v, want only dana's external ID from SCIM provisioning", idc.Users)
	}
	var posture CloudPosture
	decodeArtifact(t, res, cloudPosturePath, &posture)
	if got := posture.WorkforceSignIn; !samePtr(got.InUse, boolPtr(true)) || got.MFASource != "unknown" {
		t.Errorf("in_use %s, mfa_source %q; want true and unknown", showBool(got.InUse), got.MFASource)
	}

	for _, a := range res.Artifacts {
		for _, secret := range externalIDCanaries() {
			if strings.Contains(string(a.Data), secret) {
				t.Errorf("%s carries %q", a.Path, secret)
			}
		}
	}
}
