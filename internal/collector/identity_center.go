package collector

import (
	"context"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// collectIdentityCenter collects IAM Identity Center status. Probes the primary
// region only — accounts with IdC deployed elsewhere should configure the
// collector with that region as primary. Returns an empty (Enabled=false)
// status when IdC is not enabled in the primary region or when the call is
// denied (e.g., member accounts that aren't the IdC delegated admin).
func (c *Collector) collectIdentityCenter(ctx context.Context, client *aws.AWSClient, primaryRegion, accountID string, level componentsdk.Level) IdentityCenterStatus {
	var status IdentityCenterStatus

	instances, err := client.ListIdentityCenterInstances(ctx, primaryRegion)
	if err != nil {
		if isAccessDeniedErr(err) {
			c.warnAccessDenied(accountID, "identity_center", "sso:ListInstances")
			return status
		}
		c.warn("account %s: failed to list identity center instances: %v", accountID, err)
		return status
	}
	if len(instances) == 0 {
		return status
	}

	inst := instances[0]
	status.Enabled = true
	status.InstanceARN = inst.InstanceARN
	status.InstanceRegion = inst.Region
	status.IdentityStoreID = inst.IdentityStoreID

	users, err := client.ListIdentityStoreUsers(ctx, inst.Region, inst.IdentityStoreID)
	if err != nil {
		c.warn("account %s: failed to list identity store users: %v", accountID, err)
	} else {
		status.UserCount = len(users)
	}

	groups, err := client.ListIdentityStoreGroups(ctx, inst.Region, inst.IdentityStoreID, false)
	if err != nil {
		c.warn("account %s: failed to list identity store groups: %v", accountID, err)
	} else {
		status.GroupCount = len(groups)
	}

	if level.AtLeast(componentsdk.LevelAudit) {
		permSets, err := client.ListIdentityCenterPermissionSets(ctx, inst.Region, inst.InstanceARN, level.AtLeast(componentsdk.LevelInternal))
		if err != nil {
			c.warn("account %s: failed to list IdC permission sets: %v", accountID, err)
		} else {
			status.PermissionSetCount = len(permSets)
			status.PermissionSets = permissionSetsToInventory(permSets)
		}
	} else {
		// Trust still wants the count; cheap separate call.
		permSets, err := client.ListIdentityCenterPermissionSets(ctx, inst.Region, inst.InstanceARN, false)
		if err == nil {
			status.PermissionSetCount = len(permSets)
		}
	}

	if level.AtLeast(componentsdk.LevelInternal) {
		status.Users = identityStoreUsersToInventory(users)
		// Re-fetch groups with member counts (we only have summary rows above).
		groupsWithMembers, err := client.ListIdentityStoreGroups(ctx, inst.Region, inst.IdentityStoreID, true)
		if err != nil {
			c.warn("account %s: failed to enrich IdC groups with member counts: %v", accountID, err)
			status.Groups = identityStoreGroupsToInventory(groups)
		} else {
			status.Groups = identityStoreGroupsToInventory(groupsWithMembers)
		}
	}

	return status
}

func permissionSetsToInventory(in []aws.IdentityCenterPermissionSet) []IdentityCenterPermissionSetRow {
	out := make([]IdentityCenterPermissionSetRow, 0, len(in))
	for _, ps := range in {
		row := IdentityCenterPermissionSetRow{
			Name:                   ps.Name,
			ARN:                    ps.ARN,
			Description:            ps.Description,
			SessionDurationISO8601: ps.SessionDurationISO8601,
			ManagedPoliciesCount:   ps.ManagedPoliciesCount,
			AccountsAssignedCount:  ps.AccountsAssignedCount,
			HasInlinePolicy:        ps.HasInlinePolicy,
		}
		if len(ps.ManagedPolicyARNs) > 0 {
			row.ManagedPolicyARNs = append([]string(nil), ps.ManagedPolicyARNs...)
		}
		out = append(out, row)
	}
	return out
}

func identityStoreUsersToInventory(in []aws.IdentityStoreUser) []IdentityCenterUserRow {
	out := make([]IdentityCenterUserRow, 0, len(in))
	for _, u := range in {
		out = append(out, IdentityCenterUserRow{
			UserID:       u.UserID,
			UserName:     u.UserName,
			DisplayName:  u.DisplayName,
			PrimaryEmail: u.PrimaryEmail,
		})
	}
	return out
}

func identityStoreGroupsToInventory(in []aws.IdentityStoreGroup) []IdentityCenterGroupRow {
	out := make([]IdentityCenterGroupRow, 0, len(in))
	for _, g := range in {
		out = append(out, IdentityCenterGroupRow{
			GroupID:     g.GroupID,
			DisplayName: g.DisplayName,
			Description: g.Description,
			MemberCount: g.MemberCount,
		})
	}
	return out
}
