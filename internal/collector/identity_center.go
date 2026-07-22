package collector

import (
	"context"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// idcClient is the slice of the AWS client used by collectIdentityCenter,
// extracted so level gating and failure paths can be tested without AWS.
type idcClient interface {
	ListIdentityCenterInstances(ctx context.Context, region string) ([]aws.IdentityCenterInstance, error)
	ListIdentityStoreUsers(ctx context.Context, region, identityStoreID string) ([]aws.IdentityStoreUser, error)
	ListIdentityStoreGroups(ctx context.Context, region, identityStoreID string, withMembers bool) ([]aws.IdentityStoreGroup, error)
	ListIdentityCenterPermissionSets(ctx context.Context, region, instanceARN string, withInternalEnrichment bool) ([]aws.IdentityCenterPermissionSet, error)
	ListIdentityCenterAccountAssignments(ctx context.Context, region, instanceARN, accountID, permissionSetARN string) ([]aws.IdentityCenterAssignment, error)
}

// collectIdentityCenter collects IAM Identity Center status. Probes the primary
// region only — accounts with IdC deployed elsewhere should configure the
// collector with that region as primary. Returns an empty (Enabled=false)
// status when IdC is not enabled in the primary region or when the call is
// denied (e.g., member accounts that aren't the IdC delegated admin).
//
// At audit, the full access model is surfaced: users, groups with member
// edges, permission sets with their provisioned accounts, and the account
// assignment edges. Internal adds managed-policy detail on permission sets.
func (c *Collector) collectIdentityCenter(ctx context.Context, client idcClient, primaryRegion, accountID string, level componentsdk.Level) IdentityCenterStatus {
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

	users, usersErr := client.ListIdentityStoreUsers(ctx, inst.Region, inst.IdentityStoreID)
	if usersErr != nil {
		c.warn("account %s: failed to list identity store users: %v", accountID, usersErr)
	} else {
		status.UserCount = len(users)
	}

	groups, groupsErr := client.ListIdentityStoreGroups(ctx, inst.Region, inst.IdentityStoreID, false)
	if groupsErr != nil {
		c.warn("account %s: failed to list identity store groups: %v", accountID, groupsErr)
	} else {
		status.GroupCount = len(groups)
	}

	if !level.AtLeast(componentsdk.LevelAudit) {
		// Trust still wants the count; cheap separate call.
		permSets, err := client.ListIdentityCenterPermissionSets(ctx, inst.Region, inst.InstanceARN, false)
		if err == nil {
			status.PermissionSetCount = len(permSets)
		}
		return status
	}

	permSets, err := client.ListIdentityCenterPermissionSets(ctx, inst.Region, inst.InstanceARN, level.AtLeast(componentsdk.LevelInternal))
	if err != nil {
		c.warn("account %s: failed to list IdC permission sets: %v", accountID, err)
	} else {
		status.PermissionSetCount = len(permSets)
		status.PermissionSets = permissionSetsToInventory(permSets)
		status.AccountAssignments, status.AssignmentsEvaluated, status.AssignmentsTruncated, status.AssignmentsDroppedCount =
			c.collectIdentityCenterAssignments(ctx, client, inst, permSets, accountID)
	}

	if usersErr == nil {
		status.Users = identityStoreUsersToInventory(users)
	}

	if groupsErr == nil {
		// Re-fetch groups with member edges (we only have summary rows above).
		groupsWithMembers, err := client.ListIdentityStoreGroups(ctx, inst.Region, inst.IdentityStoreID, true)
		if err != nil {
			c.warn("account %s: failed to enrich IdC groups with member edges: %v", accountID, err)
			status.Groups = identityStoreGroupsToInventory(groups)
		} else {
			status.Groups = identityStoreGroupsToInventory(groupsWithMembers)
		}
	}

	return status
}

// collectIdentityCenterAssignments walks each permission set's provisioned
// accounts and lists the principal assignments. Any failure discards the
// partial inventory (a partial assignment list would silently understate
// access) and reports evaluated=false with a diagnostic.
func (c *Collector) collectIdentityCenterAssignments(ctx context.Context, client idcClient, inst aws.IdentityCenterInstance, permSets []aws.IdentityCenterPermissionSet, accountID string) (rows []IdentityCenterAssignmentRow, evaluated, truncated bool, dropped int) {
	rows = []IdentityCenterAssignmentRow{}
	for _, ps := range permSets {
		for _, provisionedAccountID := range ps.ProvisionedAccountIDs {
			assignments, err := client.ListIdentityCenterAccountAssignments(ctx, inst.Region, inst.InstanceARN, provisionedAccountID, ps.ARN)
			if err != nil {
				if isAccessDeniedErr(err) {
					c.warnAccessDenied(accountID, "identity_center_assignments", "sso:ListAccountAssignments")
				} else {
					c.warn("account %s: failed to list IdC account assignments: %v", accountID, err)
				}
				return []IdentityCenterAssignmentRow{}, false, false, 0
			}
			for _, a := range assignments {
				rows = append(rows, IdentityCenterAssignmentRow{
					AccountID:        a.AccountID,
					PermissionSetARN: a.PermissionSetARN,
					PrincipalType:    a.PrincipalType,
					PrincipalID:      a.PrincipalID,
				})
			}
		}
	}

	kept, droppedCount, wasTruncated := Truncate(rows, IdentityCenterAssignmentsCap, func(a, b IdentityCenterAssignmentRow) bool {
		if a.AccountID != b.AccountID {
			return a.AccountID < b.AccountID
		}
		if a.PermissionSetARN != b.PermissionSetARN {
			return a.PermissionSetARN < b.PermissionSetARN
		}
		return a.PrincipalID < b.PrincipalID
	})
	if wasTruncated {
		c.warn("account %s: IdC account assignment inventory truncated to %d (dropped %d)", accountID, IdentityCenterAssignmentsCap, droppedCount)
	}
	return kept, true, wasTruncated, droppedCount
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
			ProvisionedAccountIDs:  append([]string{}, ps.ProvisionedAccountIDs...),
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
		row := IdentityCenterGroupRow{
			GroupID:     g.GroupID,
			DisplayName: g.DisplayName,
			Description: g.Description,
			MemberCount: g.MemberCount,
		}
		if g.MemberUserIDs != nil {
			row.MemberUserIDs = append([]string{}, g.MemberUserIDs...)
		}
		out = append(out, row)
	}
	return out
}
