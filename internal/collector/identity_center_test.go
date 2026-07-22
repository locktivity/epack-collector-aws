package collector

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
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

// fakeIdcClient is a focused mock for the idcClient interface.
type fakeIdcClient struct {
	instances         []aws.IdentityCenterInstance
	instancesErr      error
	users             []aws.IdentityStoreUser
	usersErr          error
	groups            []aws.IdentityStoreGroup
	groupsWithMembers []aws.IdentityStoreGroup
	groupsErr         error
	permSets          []aws.IdentityCenterPermissionSet
	permSetsErr       error
	assignments       map[string][]aws.IdentityCenterAssignment // keyed by "account:psARN"
	assignmentsErr    error
}

func (f fakeIdcClient) ListIdentityCenterInstances(_ context.Context, _ string) ([]aws.IdentityCenterInstance, error) {
	return f.instances, f.instancesErr
}

func (f fakeIdcClient) ListIdentityStoreUsers(_ context.Context, _, _ string) ([]aws.IdentityStoreUser, error) {
	return f.users, f.usersErr
}

func (f fakeIdcClient) ListIdentityStoreGroups(_ context.Context, _, _ string, withMembers bool) ([]aws.IdentityStoreGroup, error) {
	if withMembers {
		return f.groupsWithMembers, f.groupsErr
	}
	return f.groups, f.groupsErr
}

func (f fakeIdcClient) ListIdentityCenterPermissionSets(_ context.Context, _, _ string, _ bool) ([]aws.IdentityCenterPermissionSet, error) {
	return f.permSets, f.permSetsErr
}

func (f fakeIdcClient) ListIdentityCenterAccountAssignments(_ context.Context, _, _, accountID, psARN string) ([]aws.IdentityCenterAssignment, error) {
	if f.assignmentsErr != nil {
		return nil, f.assignmentsErr
	}
	return f.assignments[accountID+":"+psARN], nil
}

func rbacFakeClient() fakeIdcClient {
	return fakeIdcClient{
		instances: []aws.IdentityCenterInstance{{InstanceARN: "arn:aws:sso:::instance/ssoins-1", IdentityStoreID: "d-123", Region: "us-east-1"}},
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
	c := &Collector{}

	status := c.collectIdentityCenter(context.Background(), rbacFakeClient(), "us-east-1", "111111111111", componentsdk.LevelAudit)

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
	c := &Collector{}

	status := c.collectIdentityCenter(context.Background(), rbacFakeClient(), "us-east-1", "111111111111", componentsdk.LevelTrust)

	if status.Users != nil || status.Groups != nil || status.AccountAssignments != nil {
		t.Errorf("trust must not carry roster or assignments: users=%v groups=%v assignments=%v", status.Users, status.Groups, status.AccountAssignments)
	}
	if status.UserCount != 1 || status.GroupCount != 1 || status.PermissionSetCount != 1 {
		t.Errorf("trust counts = %d/%d/%d, want 1/1/1", status.UserCount, status.GroupCount, status.PermissionSetCount)
	}
	if status.AssignmentsEvaluated {
		t.Error("AssignmentsEvaluated must stay false at trust")
	}
}

func TestCollectIdentityCenter_AssignmentFailureDiscardsPartial(t *testing.T) {
	c := &Collector{}
	client := rbacFakeClient()
	client.assignmentsErr = errors.New("AccessDenied: no sso:ListAccountAssignments")

	status := c.collectIdentityCenter(context.Background(), client, "us-east-1", "111111111111", componentsdk.LevelAudit)

	if status.AssignmentsEvaluated {
		t.Error("expected AssignmentsEvaluated false on listing failure")
	}
	if len(status.AccountAssignments) != 0 {
		t.Errorf("expected empty assignments on failure, got %+v", status.AccountAssignments)
	}
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
	c := &Collector{}
	client := rbacFakeClient()
	client.usersErr = errors.New("Throttling")

	status := c.collectIdentityCenter(context.Background(), client, "us-east-1", "111111111111", componentsdk.LevelAudit)

	if status.Users != nil {
		t.Errorf("expected nil users on listing failure (null before level normalization), got %+v", status.Users)
	}
	if status.UserCount != 0 {
		t.Errorf("expected zero user count on listing failure, got %d", status.UserCount)
	}
}
