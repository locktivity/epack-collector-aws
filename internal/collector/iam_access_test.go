package collector

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

func lastAt(t time.Time) *time.Time { return &t }

// A user is inactive when neither the password nor an access key was used in
// the last 90 days, including a user who never signed in. A key counts when
// it is active, the root user's included, and is unused or overdue for
// rotation by its own dates.
func TestCredentialUsage(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	recent, old := now.AddDate(0, 0, -10), now.AddDate(0, 0, -91)
	edge := now.AddDate(0, 0, -InactiveDaysThreshold)
	report := &aws.CredentialReport{Users: []aws.CredentialReportUser{
		{User: "<root_account>", PasswordLastUsed: lastAt(old), AccessKey1Active: true, AccessKey1LastRotated: lastAt(old)},
		{User: "console", PasswordEnabled: true, PasswordLastUsed: lastAt(recent)},
		{User: "stale-console", PasswordEnabled: true, PasswordLastUsed: lastAt(old)},
		{User: "never", PasswordEnabled: true},
		{User: "on-the-day", PasswordEnabled: true, PasswordLastUsed: lastAt(edge)},
		{User: "keys-only", AccessKey1Active: true, AccessKey1LastRotated: lastAt(old), AccessKey1LastUsedDate: lastAt(recent),
			AccessKey2Active: true, AccessKey2LastRotated: lastAt(recent)},
		{User: "inactive-key", AccessKey1Active: false, AccessKey1LastRotated: lastAt(old), AccessKey1LastUsedDate: lastAt(recent),
			AccessKey2Active: true, AccessKey2LastUsedDate: lastAt(old)},
	}}

	got := credentialUsage(report, now)

	// stale-console and never are inactive. inactive-key used its deactivated
	// key recently, so it is active.
	if got.inactiveUsers != 2 {
		t.Errorf("inactive users = %d, want 2", got.inactiveUsers)
	}
	// The four users with a console password are members. Of them,
	// stale-console and never are inactive, and none has MFA.
	if got.consoleUsers != 4 || got.consoleInactiveUsers != 2 || got.consoleMFAUsers != 0 {
		t.Errorf("console users = %d, inactive %d, with MFA %d; want 4, 2, 0", got.consoleUsers, got.consoleInactiveUsers, got.consoleMFAUsers)
	}
	if got.activeKeys != 4 {
		t.Errorf("active keys = %d, want 4", got.activeKeys)
	}
	// The root user's key and keys-only's second key were never used, and
	// inactive-key's second key was last used 91 days ago.
	if got.unusedKeys != 3 {
		t.Errorf("unused keys = %d, want 3", got.unusedKeys)
	}
	// The root user's key and keys-only's first key were rotated 91 days
	// ago, and inactive-key's second key has no rotation date.
	if got.rotationOverdueKeys != 3 {
		t.Errorf("keys overdue for rotation = %d, want 3", got.rotationOverdueKeys)
	}
	// The root user, keys-only, and inactive-key have an active key, and
	// each has one overdue.
	if got.keyUsers != 3 || got.rotatedKeyUsers != 0 {
		t.Errorf("users with keys = %d, with every key rotated %d; want 3 and 0", got.keyUsers, got.rotatedKeyUsers)
	}
}

// fakeAdminPolicies answers the admin check's calls from maps, and counts the
// group reads.
type fakeAdminPolicies struct {
	user, groupsOf map[string][]string
	group          map[string][]string
	userInline     map[string][]string
	groupInline    map[string][]string
	userErr        map[string]error
	groupErr       map[string]error
	groupReads     map[string]int
}

func (f *fakeAdminPolicies) ListAttachedUserPolicyARNs(_ context.Context, user string) ([]string, error) {
	return f.user[user], f.userErr[user]
}

func (f *fakeAdminPolicies) ListUserPolicyNames(_ context.Context, user string) ([]string, error) {
	return f.userInline[user], nil
}

func (f *fakeAdminPolicies) ListGroupPolicyNames(_ context.Context, group string) ([]string, error) {
	return f.groupInline[group], nil
}

func (f *fakeAdminPolicies) ListGroupsForUser(_ context.Context, user string) ([]string, error) {
	return f.groupsOf[user], nil
}

func (f *fakeAdminPolicies) ListAttachedGroupPolicyARNs(_ context.Context, group string) ([]string, error) {
	if f.groupReads == nil {
		f.groupReads = map[string]int{}
	}
	f.groupReads[group]++
	return f.group[group], f.groupErr[group]
}

func (f *fakeAdminPolicies) GetPolicyDocument(context.Context, string) (string, error) {
	return "", errors.New("the admin check reads no policy document")
}

func (f *fakeAdminPolicies) GetUserPolicyDocument(context.Context, string, string) (string, error) {
	return "", errors.New("the admin check reads no policy document")
}

func (f *fakeAdminPolicies) GetGroupPolicyDocument(context.Context, string, string) (string, error) {
	return "", errors.New("the admin check reads no policy document")
}

func (f *fakeAdminPolicies) GetUserPermissionsBoundary(context.Context, string) (string, error) {
	return "", errors.New("the admin check reads no permissions boundary")
}

// adminsFrom runs the admin check over report with client's answers.
func adminsFrom(client iamPolicyClient, report *aws.CredentialReport) iamAdmins {
	c := newTestCollector(Config{})
	return c.collectIAMAdmins(newIAMPolicies(context.Background(), client, c.policiesWarn("111122223333")), report)
}

func reportOf(users ...aws.CredentialReportUser) *aws.CredentialReport {
	return &aws.CredentialReport{Users: append([]aws.CredentialReportUser{{User: "<root_account>"}}, users...)}
}

// AdministratorAccess, PowerUserAccess and IAMFullAccess count when they are
// attached to the user or to one of the user's groups, in any partition. A
// customer managed policy with the same name does not count, and each group
// is read once.
func TestCollectIAMAdmins(t *testing.T) {
	client := &fakeAdminPolicies{
		user: map[string][]string{
			"direct":    {"arn:aws:iam::aws:policy/ReadOnlyAccess", "arn:aws:iam::aws:policy/AdministratorAccess"},
			"govcloud":  {"arn:aws-us-gov:iam::aws:policy/AdministratorAccess"},
			"lookalike": {"arn:aws:iam::111122223333:policy/AdministratorAccess"},
		},
		groupsOf: map[string][]string{
			"via-group":  {"developers", "platform-admins"},
			"via-group2": {"platform-admins"},
			"developer":  {"developers"},
		},
		group: map[string][]string{
			"developers":      {"arn:aws:iam::aws:policy/PowerUserAccess"},
			"platform-admins": {"arn:aws:iam::aws:policy/AdministratorAccess"},
		},
	}
	report := reportOf(
		aws.CredentialReportUser{User: "direct", PasswordEnabled: true, MFAActive: true},
		aws.CredentialReportUser{User: "govcloud", PasswordEnabled: true},
		aws.CredentialReportUser{User: "lookalike", PasswordEnabled: true, MFAActive: true},
		aws.CredentialReportUser{User: "via-group", PasswordEnabled: true, MFAActive: true},
		aws.CredentialReportUser{User: "via-group2", PasswordEnabled: true},
		aws.CredentialReportUser{User: "developer", PasswordEnabled: true, MFAActive: true},
	)

	got := adminsFrom(client, report)

	if !got.read || got.unmeasured != 1 || !errors.Is(got.err, errPolicyDocumentsNotRead) {
		t.Fatalf("read %t, %d unmeasured, err %v; want lookalike unmeasured for its unread policy", got.read, got.unmeasured, got.err)
	}
	// developer's group has PowerUserAccess. lookalike's customer managed
	// policy is not read, so lookalike is unmeasured.
	if got.admins != 5 || got.mfaAdmins != 3 {
		t.Errorf("%d admins, %d with MFA; want 5 and 3", got.admins, got.mfaAdmins)
	}
	for group, reads := range client.groupReads {
		if reads != 1 {
			t.Errorf("group %s read %d times, want once", group, reads)
		}
	}
}

// A user whose policies cannot be read is unmeasured. A group that cannot be
// read leaves its member unmeasured unless another group makes the member an
// admin.
func TestCollectIAMAdmins_UnreadPolicies(t *testing.T) {
	denied := errors.New("AccessDenied")
	client := &fakeAdminPolicies{
		user:     map[string][]string{"admin": {"arn:aws:iam::aws:policy/AdministratorAccess"}},
		userErr:  map[string]error{"unreadable": denied},
		groupsOf: map[string][]string{"blocked-group": {"secret"}, "two-groups": {"secret", "platform-admins"}},
		group:    map[string][]string{"platform-admins": {"arn:aws:iam::aws:policy/AdministratorAccess"}},
		groupErr: map[string]error{"secret": denied},
	}
	report := reportOf(
		aws.CredentialReportUser{User: "admin", PasswordEnabled: true, MFAActive: true},
		aws.CredentialReportUser{User: "unreadable", PasswordEnabled: true},
		aws.CredentialReportUser{User: "blocked-group", PasswordEnabled: true},
		aws.CredentialReportUser{User: "two-groups", PasswordEnabled: true},
	)

	got := adminsFrom(client, report)

	if got.unmeasured != 2 || !errors.Is(got.err, denied) {
		t.Errorf("%d unmeasured, err %v; want 2 and the denial", got.unmeasured, got.err)
	}
	if got.admins != 2 || got.mfaAdmins != 1 {
		t.Errorf("%d admins, %d with MFA among the users read; want 2 and 1", got.admins, got.mfaAdmins)
	}
}

// A user with an inline or customer managed policy, on the user or a group,
// and none of the admin policies, is unmeasured, since the policy's document
// is not read. A user with an admin policy is an admin whatever else they
// have, and a user without a console password is a credential, so it is not
// checked.
func TestCollectIAMAdmins_InlineAndCustomerManagedPolicies(t *testing.T) {
	client := &fakeAdminPolicies{
		user: map[string][]string{
			"admin":   {"arn:aws:iam::aws:policy/IAMFullAccess", "arn:aws:iam::111122223333:policy/deploy"},
			"managed": {"arn:aws:iam::111122223333:policy/deploy"},
			"reader":  {"arn:aws:iam::aws:policy/ReadOnlyAccess"},
			"keys":    {"arn:aws:iam::aws:policy/AdministratorAccess"},
		},
		userInline:  map[string][]string{"inline": {"s3-write"}},
		groupsOf:    map[string][]string{"via-group": {"ops"}},
		groupInline: map[string][]string{"ops": {"ops-inline"}},
	}
	report := reportOf(
		aws.CredentialReportUser{User: "admin", PasswordEnabled: true},
		aws.CredentialReportUser{User: "managed", PasswordEnabled: true},
		aws.CredentialReportUser{User: "inline", PasswordEnabled: true},
		aws.CredentialReportUser{User: "via-group", PasswordEnabled: true},
		aws.CredentialReportUser{User: "reader", PasswordEnabled: true},
		aws.CredentialReportUser{User: "keys", AccessKey1Active: true},
	)

	got := adminsFrom(client, report)

	if got.admins != 1 || got.unmeasured != 3 || !errors.Is(got.err, errPolicyDocumentsNotRead) {
		t.Errorf("%d admins, %d unmeasured, err %v; want 1, 3, and the unread policy documents", got.admins, got.unmeasured, got.err)
	}
}

// Without a credential report there are no users to check.
func TestCollectIAMAdmins_NoReport(t *testing.T) {
	got := adminsFrom(&fakeAdminPolicies{}, nil)
	if got.read {
		t.Error("read = true without a credential report")
	}
}
