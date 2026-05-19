package collector

import (
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
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
