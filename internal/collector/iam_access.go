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
// and the account's access keys. The root user is not counted among the
// users, and its access keys are counted among the keys.
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

	// keyUsers counts the users with an active access key, the root user
	// included, and rotatedKeyUsers those of them whose every active key was
	// rotated within AccessKeyAgeThreshold days, as hasRotatedKeys decides.
	keyUsers, rotatedKeyUsers int

	// consoleUsers counts the users with a console password, who are the
	// access-posture artifact's members. A user with access keys and no
	// password is a credential, not a member. consoleMFAUsers counts those
	// with MFA, and consoleInactiveUsers those inactive.
	consoleUsers, consoleMFAUsers, consoleInactiveUsers int
}

// credentialUsage counts the users' activity and the access keys in report
// against now. A user is inactive and a key is unused when its last use is
// more than InactiveDaysThreshold days before now, or there is none. A key
// is overdue for rotation by the same rule hasRotatedKeys applies, with
// AccessKeyAgeThreshold days. The root user's keys count as any other
// user's.
func credentialUsage(report *aws.CredentialReport, now time.Time) iamUsage {
	inactiveBefore := now.AddDate(0, 0, -InactiveDaysThreshold)
	rotateBefore := now.AddDate(0, 0, -AccessKeyAgeThreshold)
	var u iamUsage
	for _, user := range report.Users {
		if user.AccessKey1Active || user.AccessKey2Active {
			u.keyUsers++
			if hasRotatedKeys(user, rotateBefore) {
				u.rotatedKeyUsers++
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
	errors.New("an IAM user or one of its groups has an inline or customer managed policy, whose document the admin check does not evaluate"))

// iamPolicyClient is the slice of the AWS client the admin check and the
// access key evaluation use, extracted so the failure paths can be tested
// without AWS.
type iamPolicyClient interface {
	ListAttachedUserPolicyARNs(ctx context.Context, userName string) ([]string, error)
	ListUserPolicyNames(ctx context.Context, userName string) ([]string, error)
	ListGroupsForUser(ctx context.Context, userName string) ([]string, error)
	ListAttachedGroupPolicyARNs(ctx context.Context, groupName string) ([]string, error)
	ListGroupPolicyNames(ctx context.Context, groupName string) ([]string, error)
	GetPolicyDocument(ctx context.Context, arn string) (string, error)
	GetUserPolicyDocument(ctx context.Context, userName, policyName string) (string, error)
	GetGroupPolicyDocument(ctx context.Context, groupName, policyName string) (string, error)
	GetUserPermissionsBoundary(ctx context.Context, userName string) (string, error)
}

// iamPolicies reads one account's IAM user and group policies for the admin
// check and the access key evaluation. Each listing and each document is
// read once, and warn is told of each read that fails.
type iamPolicies struct {
	ctx       context.Context
	client    iamPolicyClient
	warn      func(what named, err error)
	users     map[string]policySet
	groups    map[string]policySet
	memberOf  map[string]groupList
	documents map[string]documentRead
}

// policySet is what IAM lists of a user's or a group's own policies: the
// ARNs of the managed policies attached to it and the names of its inline
// policies, or why they could not be listed.
type policySet struct {
	attached, inline []string
	err              error
}

// groupList is the groups a user belongs to, or why they could not be
// listed.
type groupList struct {
	names []string
	err   error
}

func newIAMPolicies(ctx context.Context, client iamPolicyClient, warn func(what named, err error)) *iamPolicies {
	return &iamPolicies{
		ctx: ctx, client: client, warn: warn,
		users: map[string]policySet{}, groups: map[string]policySet{},
		memberOf: map[string]groupList{}, documents: map[string]documentRead{},
	}
}

// policiesWarn returns the function an account's iamPolicies tells of each
// read that fails, which warns of it as accountID's.
func (c *Collector) policiesWarn(accountID string) func(what named, err error) {
	return func(what named, err error) {
		c.warn("account %s: failed to read %s: %v", accountID, what, err)
	}
}

// user lists the IAM user's own policies.
func (p *iamPolicies) user(name string) policySet {
	set, ok := p.users[name]
	if !ok {
		set = p.list(name, p.client.ListAttachedUserPolicyARNs, p.client.ListUserPolicyNames)
		p.users[name] = set
		if set.err != nil {
			p.warn(named{"the policies of IAM user " + name, "the policies of an IAM user"}, set.err)
		}
	}
	return set
}

// group lists the IAM group's own policies.
func (p *iamPolicies) group(name string) policySet {
	set, ok := p.groups[name]
	if !ok {
		set = p.list(name, p.client.ListAttachedGroupPolicyARNs, p.client.ListGroupPolicyNames)
		p.groups[name] = set
		if set.err != nil {
			p.warn(named{"the policies of IAM group " + name, "the policies of an IAM group"}, set.err)
		}
	}
	return set
}

// groupsOf lists the groups the IAM user belongs to.
func (p *iamPolicies) groupsOf(user string) groupList {
	list, ok := p.memberOf[user]
	if !ok {
		list.names, list.err = p.client.ListGroupsForUser(p.ctx, user)
		p.memberOf[user] = list
		if list.err != nil {
			p.warn(named{"the groups of IAM user " + user, "the groups of an IAM user"}, list.err)
		}
	}
	return list
}

// list lists the managed policies attached to the user or group called
// name, and its inline policies.
func (p *iamPolicies) list(name string, attached, inline func(context.Context, string) ([]string, error)) policySet {
	arns, err := attached(p.ctx, name)
	if err != nil {
		return policySet{err: err}
	}
	names, err := inline(p.ctx, name)
	if err != nil {
		return policySet{err: err}
	}
	return policySet{attached: arns, inline: names}
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
// a member, so it is not checked. A nil report checks no one.
func (c *Collector) collectIAMAdmins(policies *iamPolicies, report *aws.CredentialReport) iamAdmins {
	out := iamAdmins{}
	if report == nil {
		return out
	}
	out.read = true
	unread := false
	for _, user := range report.Users {
		if user.IsRootUser() || !user.PasswordEnabled {
			continue
		}
		check := userIsAdmin(policies, user.User)
		switch {
		case check.err != nil:
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
// of adminPolicies. The groups are listed only when the user's own policies
// grant no administrator access.
func userIsAdmin(policies *iamPolicies, userName string) policyCheck {
	check := checkPolicies(policies.user(userName))
	if check.err != nil || check.admin {
		return check
	}
	groups := policies.groupsOf(userName)
	if groups.err != nil {
		return policyCheck{err: groups.err}
	}
	for _, name := range groups.names {
		g := checkPolicies(policies.group(name))
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

// checkPolicies checks a user's or a group's own policies for one of
// adminPolicies.
func checkPolicies(set policySet) policyCheck {
	if set.err != nil {
		return policyCheck{err: set.err}
	}
	if grantsAdministratorAccess(set.attached) {
		return policyCheck{admin: true}
	}
	customer := slices.ContainsFunc(set.attached, func(arn string) bool { return !strings.Contains(arn, ":iam::aws:policy/") })
	return policyCheck{unread: customer || len(set.inline) > 0}
}

// grantsAdministratorAccess reports whether the policy ARNs include one of
// adminPolicies.
func grantsAdministratorAccess(arns []string) bool {
	return slices.ContainsFunc(arns, func(arn string) bool { return awsManaged(arn, adminPolicies) })
}

// awsManaged reports whether arn, in any partition, ends with one of
// policies.
func awsManaged(arn string, policies []string) bool {
	return strings.HasPrefix(arn, "arn:") && slices.ContainsFunc(policies, func(policy string) bool { return strings.HasSuffix(arn, policy) })
}
