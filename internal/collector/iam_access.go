package collector

import (
	"context"
	"strings"
	"time"

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
		if !usedSince(inactiveBefore, user.PasswordLastUsed, user.AccessKey1LastUsedDate, user.AccessKey2LastUsedDate) {
			u.inactiveUsers++
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

// administratorAccessPolicy ends the ARN of the AWS managed policy that
// grants full access, in every partition.
const administratorAccessPolicy = ":iam::aws:policy/AdministratorAccess"

// adminPolicyLister is the slice of the AWS client collectIAMAdmins uses,
// extracted so the failure paths can be tested without AWS.
type adminPolicyLister interface {
	ListAttachedUserPolicyARNs(ctx context.Context, userName string) ([]string, error)
	ListGroupsForUser(ctx context.Context, userName string) ([]string, error)
	ListAttachedGroupPolicyARNs(ctx context.Context, groupName string) ([]string, error)
}

// iamAdmins counts the IAM users with administrator access and how many of
// them have MFA. A user whose policies or groups could not be read is
// unmeasured, and err is the first failure. read is false when the
// credential report could not be read, so there were no users to check.
type iamAdmins struct {
	read       bool
	admins     int
	mfaAdmins  int
	unmeasured int
	err        error
}

// collectIAMAdmins checks each IAM user in the credential report for the AWS
// managed AdministratorAccess policy, attached to the user or to a group the
// user belongs to. Each group's policies are read once. A nil report checks
// no one.
func (c *Collector) collectIAMAdmins(ctx context.Context, client adminPolicyLister, report *aws.CredentialReport, accountID string) iamAdmins {
	out := iamAdmins{}
	if report == nil {
		return out
	}
	out.read = true
	groups := map[string]groupAdmin{}
	for _, user := range report.Users {
		if user.IsRootUser() {
			continue
		}
		admin, err := c.userIsAdmin(ctx, client, user.User, groups)
		if err != nil {
			c.warn("account %s: failed to read the policies of IAM user %s: %v", accountID, user.User, err)
			out.unmeasured++
			if out.err == nil {
				out.err = err
			}
			continue
		}
		if admin {
			out.admins++
			if user.MFAActive {
				out.mfaAdmins++
			}
		}
	}
	return out
}

// groupAdmin is whether a group's attached policies grant administrator
// access, or why they could not be read.
type groupAdmin struct {
	admin bool
	err   error
}

// userIsAdmin reports whether the user, or a group the user belongs to, has
// the AdministratorAccess policy attached. groups caches each group's answer.
func (c *Collector) userIsAdmin(ctx context.Context, client adminPolicyLister, userName string, groups map[string]groupAdmin) (bool, error) {
	policies, err := client.ListAttachedUserPolicyARNs(ctx, userName)
	if err != nil {
		return false, err
	}
	if grantsAdministratorAccess(policies) {
		return true, nil
	}
	names, err := client.ListGroupsForUser(ctx, userName)
	if err != nil {
		return false, err
	}
	var groupErr error
	for _, name := range names {
		g, ok := groups[name]
		if !ok {
			arns, err := client.ListAttachedGroupPolicyARNs(ctx, name)
			g = groupAdmin{admin: err == nil && grantsAdministratorAccess(arns), err: err}
			groups[name] = g
		}
		if g.admin {
			return true, nil
		}
		if g.err != nil && groupErr == nil {
			groupErr = g.err
		}
	}
	return false, groupErr
}

// grantsAdministratorAccess reports whether the policy ARNs include the AWS
// managed AdministratorAccess policy.
func grantsAdministratorAccess(arns []string) bool {
	for _, arn := range arns {
		if strings.HasPrefix(arn, "arn:") && strings.HasSuffix(arn, administratorAccessPolicy) {
			return true
		}
	}
	return false
}
