package collector

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/locktivity/epack/componentsdk"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

// iamUsage is what the credential report shows of the IAM users' activity
// and access keys. The root user is not counted.
type iamUsage struct {
	// inactiveUsers counts the users whose password and access keys were all
	// last used before the cutoff, or never.
	inactiveUsers int

	// activeKeys counts the active access keys.
	activeKeys int

	// unusedKeys counts the active access keys last used before the cutoff,
	// or never.
	unusedKeys int

	// rotationOverdueKeys counts the active access keys last rotated before
	// the cutoff, or with no rotation date.
	rotationOverdueKeys int

	// consoleUsers counts the users with a console password, who are the
	// access-posture artifact's members. A user with access keys and no
	// password is a credential, not a member. consoleMFAUsers counts those
	// with MFA, and consoleInactiveUsers those inactive.
	consoleUsers, consoleMFAUsers, consoleInactiveUsers int
}

// credentialUsage counts the users' activity and access keys in report
// against now. A user is inactive and a key is unused when its last use is
// more than InactiveDaysThreshold days before now, or there is none. A key
// is overdue for rotation by the same rule hasRotatedKeys applies, with
// AccessKeyAgeThreshold days.
func credentialUsage(report *aws.CredentialReport, now time.Time) iamUsage {
	inactiveBefore := now.AddDate(0, 0, -InactiveDaysThreshold)
	rotateBefore := now.AddDate(0, 0, -AccessKeyAgeThreshold)
	var u iamUsage
	for _, user := range report.Users {
		if user.IsRootUser() {
			continue
		}
		inactive := !usedSince(inactiveBefore, user.PasswordLastUsed, user.AccessKey1LastUsedDate, user.AccessKey2LastUsedDate)
		if inactive {
			u.inactiveUsers++
		}
		if user.PasswordEnabled {
			u.consoleUsers++
			if user.MFAActive {
				u.consoleMFAUsers++
			}
			if inactive {
				u.consoleInactiveUsers++
			}
		}
		for _, key := range []struct {
			active           bool
			rotated, lastUse *time.Time
		}{
			{user.AccessKey1Active, user.AccessKey1LastRotated, user.AccessKey1LastUsedDate},
			{user.AccessKey2Active, user.AccessKey2LastRotated, user.AccessKey2LastUsedDate},
		} {
			if !key.active {
				continue
			}
			u.activeKeys++
			if !usedSince(inactiveBefore, key.lastUse) {
				u.unusedKeys++
			}
			if key.rotated == nil || key.rotated.Before(rotateBefore) {
				u.rotationOverdueKeys++
			}
		}
	}
	return u
}

// usedSince reports whether any of the times is at or after cutoff.
func usedSince(cutoff time.Time, times ...*time.Time) bool {
	for _, t := range times {
		if t != nil && !t.Before(cutoff) {
			return true
		}
	}
	return false
}

// adminPolicies end the ARNs of the AWS managed policies that let a user
// change who has access or change or delete any resource, in every
// partition. AdministratorAccess and PowerUserAccess can change or delete
// any resource, and IAMFullAccess can change who has access.
var adminPolicies = []string{
	":iam::aws:policy/AdministratorAccess",
	":iam::aws:policy/PowerUserAccess",
	":iam::aws:policy/IAMFullAccess",
}

// errPolicyDocumentsNotRead is why a user with an inline or customer
// managed policy, and none of adminPolicies, is unmeasured.
var errPolicyDocumentsNotRead = componentsdk.CodeError(componentsdk.CodeNotRead,
	errors.New("an IAM user or one of its groups has an inline or customer managed policy, whose document, from GetUserPolicy, GetGroupPolicy or GetPolicyVersion, this collector does not read"))

// adminPolicyLister is the slice of the AWS client collectIAMAdmins uses,
// extracted so the failure paths can be tested without AWS.
type adminPolicyLister interface {
	ListAttachedUserPolicyARNs(ctx context.Context, userName string) ([]string, error)
	ListUserPolicyNames(ctx context.Context, userName string) ([]string, error)
	ListGroupsForUser(ctx context.Context, userName string) ([]string, error)
	ListAttachedGroupPolicyARNs(ctx context.Context, groupName string) ([]string, error)
	ListGroupPolicyNames(ctx context.Context, groupName string) ([]string, error)
}

// iamAdmins counts the IAM users with administrator access and how many of
// them have MFA. A user whose policies or groups could not be read is
// unmeasured, and so is one with an inline or customer managed policy that
// may grant it. err is the first failure, or errPolicyDocumentsNotRead when
// only such policies left users unmeasured. read is false when the
// credential report could not be read, so there were no users to check.
type iamAdmins struct {
	read       bool
	admins     int
	mfaAdmins  int
	unmeasured int
	err        error
}

// collectIAMAdmins checks each IAM user in the credential report with a
// console password for one of adminPolicies, attached to the user or to a
// group the user belongs to. A user without a password is a credential, not
// a member, so it is not checked. Each group's policies are read once. A
// nil report checks no one.
func (c *Collector) collectIAMAdmins(ctx context.Context, client adminPolicyLister, report *aws.CredentialReport, accountID string) iamAdmins {
	out := iamAdmins{}
	if report == nil {
		return out
	}
	out.read = true
	groups := map[string]policyCheck{}
	unread := false
	for _, user := range report.Users {
		if user.IsRootUser() || !user.PasswordEnabled {
			continue
		}
		check := c.userIsAdmin(ctx, client, user.User, groups)
		switch {
		case check.err != nil:
			c.warn("account %s: failed to read the policies of %s: %v", accountID, named{"IAM user " + user.User, "an IAM user"}, check.err)
			out.unmeasured++
			if out.err == nil {
				out.err = check.err
			}
		case check.admin:
			out.admins++
			if user.MFAActive {
				out.mfaAdmins++
			}
		case check.unread:
			out.unmeasured++
			unread = true
		}
	}
	if out.err == nil && unread {
		out.err = errPolicyDocumentsNotRead
	}
	return out
}

// policyCheck is whether a user's or a group's policies grant administrator
// access, whether an inline or customer managed policy that may grant it
// went unread, or why they could not be listed.
type policyCheck struct {
	admin, unread bool
	err           error
}

// userIsAdmin checks the user and the groups the user belongs to for one
// of adminPolicies. groups caches each group's answer.
func (c *Collector) userIsAdmin(ctx context.Context, client adminPolicyLister, userName string, groups map[string]policyCheck) policyCheck {
	check := checkPolicies(ctx, userName, client.ListAttachedUserPolicyARNs, client.ListUserPolicyNames)
	if check.err != nil || check.admin {
		return check
	}
	names, err := client.ListGroupsForUser(ctx, userName)
	if err != nil {
		return policyCheck{err: err}
	}
	for _, name := range names {
		g, ok := groups[name]
		if !ok {
			g = checkPolicies(ctx, name, client.ListAttachedGroupPolicyARNs, client.ListGroupPolicyNames)
			groups[name] = g
		}
		if g.admin {
			return g
		}
		check.unread = check.unread || g.unread
		if check.err == nil {
			check.err = g.err
		}
	}
	return check
}

// checkPolicies lists the managed policies attached to the user or group
// called name, and its inline policies when none of them is one of
// adminPolicies.
func checkPolicies(ctx context.Context, name string, attached, inline func(context.Context, string) ([]string, error)) policyCheck {
	arns, err := attached(ctx, name)
	if err != nil {
		return policyCheck{err: err}
	}
	if grantsAdministratorAccess(arns) {
		return policyCheck{admin: true}
	}
	embedded, err := inline(ctx, name)
	if err != nil {
		return policyCheck{err: err}
	}
	customer := slices.ContainsFunc(arns, func(arn string) bool { return !strings.Contains(arn, ":iam::aws:policy/") })
	return policyCheck{unread: customer || len(embedded) > 0}
}

// grantsAdministratorAccess reports whether the policy ARNs include one of
// adminPolicies.
func grantsAdministratorAccess(arns []string) bool {
	for _, arn := range arns {
		for _, policy := range adminPolicies {
			if strings.HasPrefix(arn, "arn:") && strings.HasSuffix(arn, policy) {
				return true
			}
		}
	}
	return false
}
