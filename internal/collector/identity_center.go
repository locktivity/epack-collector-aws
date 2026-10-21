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
	ListIdentityStoreGroups(ctx context.Context, region, identityStoreID string) ([]aws.IdentityStoreGroup, error)
	ListIdentityStoreGroupMembers(ctx context.Context, region, identityStoreID string, groups []aws.IdentityStoreGroup) ([]aws.IdentityStoreGroup, error)
	ListIdentityCenterPermissionSets(ctx context.Context, region, instanceARN string, withInternalEnrichment bool) ([]aws.IdentityCenterPermissionSet, error)
	ListIdentityCenterAccountAssignments(ctx context.Context, region, instanceARN, accountID, permissionSetARN string) ([]aws.IdentityCenterAssignment, error)
}

// collectIdentityCenter collects IAM Identity Center status. Probes the primary
// region only — accounts with IdC deployed elsewhere should configure the
// collector with that region as primary. Returns an empty (Enabled=false)
// status when IdC is not enabled in the primary region. When the instance
// listing fails, including when it is denied (e.g., member accounts that
// aren't the IdC delegated admin), the whole status is left out; a narrower
// failure leaves out only what it covers.
//
// At audit, the full access model is surfaced: users, groups with member
// edges, permission sets with their provisioned accounts, and the account
// assignment edges. Internal adds managed-policy detail on permission sets.
func (c *Collector) collectIdentityCenter(ctx context.Context, client idcClient, primaryRegion, accountID string, at at, level componentsdk.Level) IdentityCenterStatus {
	var status IdentityCenterStatus
	idcAt := at.sub("identity_center")
	audit := level.AtLeast(componentsdk.LevelAudit)

	instances, err := client.ListIdentityCenterInstances(ctx, primaryRegion)
	if err != nil {
		if isAccessDeniedErr(err) {
			c.warnAccessDenied(accountID, "identity_center", "sso:ListInstances")
		} else {
			c.warn("account %s: failed to list identity center instances: %v", accountID, err)
		}
		c.gaps.leaveOut(err, idcAt.base)
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
		status.missing.add(usersErr, "user_count")
		if audit {
			status.missing.add(usersErr, "users")
		}
	} else {
		status.UserCount = len(users)
	}

	groups, groupsErr := client.ListIdentityStoreGroups(ctx, inst.Region, inst.IdentityStoreID)
	if groupsErr != nil {
		c.warn("account %s: failed to list identity store groups: %v", accountID, groupsErr)
		status.missing.add(groupsErr, "group_count")
		if audit {
			status.missing.add(groupsErr, "groups")
		}
	} else {
		status.GroupCount = len(groups)
	}

	if !audit {
		permSets, err := client.ListIdentityCenterPermissionSets(ctx, inst.Region, inst.InstanceARN, false)
		if err != nil {
			status.missing.add(c.permissionSetsUnread(accountID, err), "permission_set_count")
		} else {
			status.PermissionSetCount = len(permSets)
		}
		c.recordUnread(idcAt, status.missing)
		return status
	}

	permSets, err := client.ListIdentityCenterPermissionSets(ctx, inst.Region, inst.InstanceARN, level.AtLeast(componentsdk.LevelInternal))
	if err != nil {
		status.missing.add(c.permissionSetsUnread(accountID, err), "permission_set_count", "permission_sets", "account_assignments")
	} else {
		status.PermissionSetCount = len(permSets)
		status.PermissionSets = permissionSetsToInventory(permSets)
		var assignmentsErr error
		status.AccountAssignments, status.AssignmentsEvaluated, status.AssignmentsTruncated, status.AssignmentsDroppedCount, assignmentsErr =
			c.collectIdentityCenterAssignments(ctx, client, inst, permSets, accountID)
		status.missing.add(assignmentsErr, "account_assignments")
	}

	if usersErr == nil {
		status.Users = identityStoreUsersToInventory(users)
	}

	// The rows enrich the listing group_count came from, so the count and the
	// rows never come from two different answers.
	if groupsErr == nil {
		groupsWithMembers, err := client.ListIdentityStoreGroupMembers(ctx, inst.Region, inst.IdentityStoreID, groups)
		if err != nil {
			c.warn("account %s: failed to enrich IdC groups with member edges: %v", accountID, err)
			status.Groups = identityStoreGroupsToInventory(groups)
			for i := range status.Groups {
				status.Groups[i].missing.add(err, "member_count", "member_user_ids")
			}
		} else {
			status.Groups = identityStoreGroupsToInventory(groupsWithMembers)
		}
	}

	c.recordUnread(idcAt, status.missing)
	recordRowsUnread(c, idcAt.sub("groups"), status.Groups, func(r *IdentityCenterGroupRow) unread { return r.missing })
	return status
}

// permissionSetsUnread codes a failed permission set listing. An account
// instance has no permission sets, and AWS refuses its instance ARN with a
// ValidationException, since the ID is longer than the permission set calls
// accept.
func (c *Collector) permissionSetsUnread(accountID string, err error) error {
	if apiErrorCode(err) == "ValidationException" {
		c.warn("account %s: Identity Center is an account instance, which has no permission sets", accountID)
		return componentsdk.CodeError(componentsdk.CodeNotLicensed, err)
	}
	c.warn("account %s: failed to list IdC permission sets: %v", accountID, err)
	return err
}

func (c *Collector) collectIdentityCenterAssignments(ctx context.Context, client idcClient, inst aws.IdentityCenterInstance, permSets []aws.IdentityCenterPermissionSet, accountID string) (rows []IdentityCenterAssignmentRow, evaluated, truncated bool, dropped int, failure error) {
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
				return []IdentityCenterAssignmentRow{}, false, false, 0, err
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
	return kept, true, wasTruncated, droppedCount, nil
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
