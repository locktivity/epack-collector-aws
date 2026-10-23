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
	ListIdentityCenterPermissionSetARNs(ctx context.Context, region, instanceARN string) ([]string, error)
	DescribeIdentityCenterPermissionSets(ctx context.Context, region, instanceARN string, arns []string, withInternalEnrichment bool) ([]aws.IdentityCenterPermissionSet, error)
	ListIdentityCenterAccountAssignments(ctx context.Context, region, instanceARN, accountID, permissionSetARN string) ([]aws.IdentityCenterAssignment, error)
}

// Identity Center instance types and the status of an instance in use, as
// instance_type and instance_status report them. An account instance cannot
// sign people in to AWS accounts.
const (
	identityCenterOrganizationInstance = "organization"
	identityCenterAccountInstance      = "account"
	identityCenterActive               = "ACTIVE"
)

// Where Identity Center users' MFA is set, as mfa_evidence reports it.
const (
	mfaEvidenceExternalIdP    = "external_idp"
	mfaEvidenceManualRequired = "manual_required"
	mfaEvidenceUnknown        = "unknown"
)

// collectIdentityCenter collects IAM Identity Center status. The instance
// listing answers for one region and the instance's home region may be any of
// them, so every requested region is probed. A member account sees no
// organization instance, only an account instance of its own. When the
// listing fails in every region, the whole status is left out. When it fails
// in some and no instance turns up in the others, the values an instance
// there would set are left out with a partial gap. A narrower failure leaves
// out only what it covers.
//
// At audit, the full access model is surfaced: users, groups with member
// edges, permission sets with their provisioned accounts, and the account
// assignment edges. Internal adds managed-policy detail on permission sets.
func (c *Collector) collectIdentityCenter(ctx context.Context, client idcClient, regions []string, accountID string, at at, level componentsdk.Level) IdentityCenterStatus {
	var status IdentityCenterStatus
	idcAt := at.sub("identity_center")
	audit := level.AtLeast(componentsdk.LevelAudit)

	inst, found, failed, err := c.findIdentityCenterInstance(ctx, client, regions, accountID, &status)
	if len(status.RegionsChecked) == 0 {
		c.gaps.leaveOut(err, idcAt.base)
		return status
	}
	if !found {
		status.missing.addPartial(err, failed, "enabled", "user_count", "external_id_user_count", "group_count", "permission_set_count")
		if audit {
			status.missing.addPartial(err, failed, "users", "groups", "permission_sets", "account_assignments")
		}
		c.recordUnread(idcAt, status.missing)
		return status
	}

	status.Enabled = true
	status.InstanceARN = inst.InstanceARN
	status.InstanceRegion = inst.Region
	status.InstanceStatus = inst.Status
	status.InstanceOwnerAccountID = inst.OwnerAccountID
	status.IdentityStoreID = inst.IdentityStoreID

	users, usersErr := client.ListIdentityStoreUsers(ctx, inst.Region, inst.IdentityStoreID)
	if usersErr != nil {
		c.warn("account %s: failed to list identity store users: %v", accountID, usersErr)
		status.missing.add(usersErr, "user_count", "external_id_user_count", "mfa_evidence")
		if audit {
			status.missing.add(usersErr, "users")
		}
	} else {
		status.UserCount = len(users)
		for _, u := range users {
			if u.HasExternalID {
				status.ExternalIDUserCount++
			}
		}
		status.MFAEvidence = identityCenterMFAEvidence(status.UserCount, status.ExternalIDUserCount)
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

	arns, arnsErr := client.ListIdentityCenterPermissionSetARNs(ctx, inst.Region, inst.InstanceARN)
	status.InstanceType = identityCenterInstanceType(inst, accountID, arnsErr)
	if arnsErr != nil {
		arnsErr = c.permissionSetsUnread(accountID, arnsErr)
		status.missing.add(arnsErr, "permission_set_count")
		if status.InstanceType == "" {
			status.missing.add(arnsErr, "instance_type")
		}
		if audit {
			status.missing.add(arnsErr, "permission_sets", "account_assignments")
		}
	} else {
		status.PermissionSetCount = len(arns)
	}

	if !audit {
		c.recordUnread(idcAt, status.missing)
		return status
	}

	// The rows describe the listing permission_set_count came from.
	if arnsErr == nil {
		permSets, err := client.DescribeIdentityCenterPermissionSets(ctx, inst.Region, inst.InstanceARN, arns, level.AtLeast(componentsdk.LevelInternal))
		if err != nil {
			c.warn("account %s: failed to describe IdC permission sets: %v", accountID, err)
			status.missing.add(err, "permission_sets", "account_assignments")
		} else {
			status.PermissionSets = permissionSetsToInventory(permSets)
			var assignmentsErr error
			status.AccountAssignments, status.AssignmentsEvaluated, status.AssignmentsTruncated, status.AssignmentsDroppedCount, assignmentsErr =
				c.collectIdentityCenterAssignments(ctx, client, inst, permSets, accountID)
			status.missing.add(assignmentsErr, "account_assignments")
		}
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

// findIdentityCenterInstance lists the instances in each region and returns
// the one to report: the first active one in region order, or else the
// first. It records the regions whose listing answered in status, and
// returns whether it found an instance, how many regions failed, and the
// first failure.
func (c *Collector) findIdentityCenterInstance(ctx context.Context, client idcClient, regions []string, accountID string, status *IdentityCenterStatus) (aws.IdentityCenterInstance, bool, int, error) {
	type regionInstances struct {
		instances []aws.IdentityCenterInstance
		err       error
	}
	scans := mapConcurrent(regions, regionConcurrency, func(region string) regionInstances {
		instances, err := client.ListIdentityCenterInstances(ctx, region)
		return regionInstances{instances: instances, err: err}
	})

	status.RegionsChecked = []string{}
	var found []aws.IdentityCenterInstance
	seen := map[string]bool{}
	failed := 0
	denied := false
	var firstErr error
	for i, region := range regions {
		if err := scans[i].err; err != nil {
			switch {
			case !isAccessDeniedErr(err):
				c.warn("account %s region %s: failed to list identity center instances: %v", accountID, region, err)
			case !denied:
				c.warnAccessDenied(accountID, "identity_center", "sso:ListInstances")
				denied = true
			}
			failed++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		status.RegionsChecked = append(status.RegionsChecked, region)
		for _, inst := range scans[i].instances {
			if !seen[inst.InstanceARN] {
				seen[inst.InstanceARN] = true
				found = append(found, inst)
			}
		}
	}
	if len(found) == 0 {
		return aws.IdentityCenterInstance{}, false, failed, firstErr
	}
	report := found[0]
	for _, inst := range found {
		if inst.Status == identityCenterActive {
			report = inst
			break
		}
	}
	if len(found) > 1 {
		c.warn("account %s: found %d Identity Center instances; reporting %s", accountID, len(found), report.InstanceARN)
	}
	return report, true, failed, firstErr
}

// identityCenterInstanceType says whether inst is its organization's instance
// or an account instance. An instance another account owns is the
// organization's, seen from a delegated administrator. Otherwise the
// permission set listing decides: AWS answers it for an organization instance
// and refuses an account instance's ARN with a ValidationException, since the
// ID is longer than the permission set calls accept. It returns "" when the
// listing failed for another reason.
func identityCenterInstanceType(inst aws.IdentityCenterInstance, accountID string, permissionSetsErr error) string {
	switch {
	case inst.OwnerAccountID != "" && inst.OwnerAccountID != accountID:
		return identityCenterOrganizationInstance
	case permissionSetsErr == nil:
		return identityCenterOrganizationInstance
	case apiErrorCode(permissionSetsErr) == "ValidationException":
		return identityCenterAccountInstance
	}
	return ""
}

// identityCenterMFAEvidence says where the MFA of a directory's users is set,
// from how many of them have an external ID from SCIM provisioning, which IAM
// Identity Center sets when an external identity provider provisions a user:
// at that provider when every user has one, in Identity Center when none
// does, and unknown for a mix or a directory with no users. Users synced from
// Active Directory count as Identity Center's own.
func identityCenterMFAEvidence(users, withExternalID int) string {
	switch {
	case users > 0 && withExternalID == users:
		return mfaEvidenceExternalIdP
	case users > 0 && withExternalID == 0:
		return mfaEvidenceManualRequired
	}
	return mfaEvidenceUnknown
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
			UserID:        u.UserID,
			UserName:      u.UserName,
			DisplayName:   u.DisplayName,
			PrimaryEmail:  u.PrimaryEmail,
			HasExternalID: u.HasExternalID,
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
