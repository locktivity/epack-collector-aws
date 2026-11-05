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
// it is active, and is unused or overdue for rotation by its own dates.
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
	if got.activeKeys != 3 {
		t.Errorf("active keys = %d, want 3", got.activeKeys)
	}
	// keys-only's second key was never used, and inactive-key's second key
	// was last used 91 days ago.
	if got.unusedKeys != 2 {
		t.Errorf("unused keys = %d, want 2", got.unusedKeys)
	}
	// keys-only's first key was rotated 91 days ago, and inactive-key's
	// second key has no rotation date.
	if got.rotationOverdueKeys != 2 {
		t.Errorf("keys overdue for rotation = %d, want 2", got.rotationOverdueKeys)
	}
}

// fakeAdminPolicies answers the admin check's calls from maps, and counts the
// group reads.
type fakeAdminPolicies struct {
	user, groupsOf map[string][]string
	group          map[string][]string
	userErr        map[string]error
	groupErr       map[string]error
	groupReads     map[string]int
}

func (f *fakeAdminPolicies) ListAttachedUserPolicyARNs(_ context.Context, user string) ([]string, error) {
	return f.user[user], f.userErr[user]
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

func reportOf(users ...aws.CredentialReportUser) *aws.CredentialReport {
	return &aws.CredentialReport{Users: append([]aws.CredentialReportUser{{User: "<root_account>"}}, users...)}
}

// AdministratorAccess counts when it is attached to the user or to one of
// the user's groups, in any partition. A customer managed policy with the
// same name does not count, and each group is read once.
func TestCollectIAMAdmins(t *testing.T) {
	c := newTestCollector(Config{})
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
		aws.CredentialReportUser{User: "direct", MFAActive: true},
		aws.CredentialReportUser{User: "govcloud"},
		aws.CredentialReportUser{User: "lookalike", MFAActive: true},
		aws.CredentialReportUser{User: "via-group", MFAActive: true},
		aws.CredentialReportUser{User: "via-group2"},
		aws.CredentialReportUser{User: "developer", MFAActive: true},
	)

	got := c.collectIAMAdmins(context.Background(), client, report, "111122223333")

	if !got.read || got.unmeasured != 0 || got.err != nil {
		t.Fatalf("read %t, %d unmeasured, err %v; want every user read", got.read, got.unmeasured, got.err)
	}
	if got.admins != 4 || got.mfaAdmins != 2 {
		t.Errorf("%d admins, %d with MFA; want 4 and 2", got.admins, got.mfaAdmins)
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
	c := newTestCollector(Config{})
	denied := errors.New("AccessDenied")
	client := &fakeAdminPolicies{
		user:     map[string][]string{"admin": {"arn:aws:iam::aws:policy/AdministratorAccess"}},
		userErr:  map[string]error{"unreadable": denied},
		groupsOf: map[string][]string{"blocked-group": {"secret"}, "two-groups": {"secret", "platform-admins"}},
		group:    map[string][]string{"platform-admins": {"arn:aws:iam::aws:policy/AdministratorAccess"}},
		groupErr: map[string]error{"secret": denied},
	}
	report := reportOf(
		aws.CredentialReportUser{User: "admin", MFAActive: true},
		aws.CredentialReportUser{User: "unreadable"},
		aws.CredentialReportUser{User: "blocked-group"},
		aws.CredentialReportUser{User: "two-groups"},
	)

	got := c.collectIAMAdmins(context.Background(), client, report, "111122223333")

	if got.unmeasured != 2 || !errors.Is(got.err, denied) {
		t.Errorf("%d unmeasured, err %v; want 2 and the denial", got.unmeasured, got.err)
	}
	if got.admins != 2 || got.mfaAdmins != 1 {
		t.Errorf("%d admins, %d with MFA among the users read; want 2 and 1", got.admins, got.mfaAdmins)
	}
}

// Without a credential report there are no users to check.
func TestCollectIAMAdmins_NoReport(t *testing.T) {
	got := newTestCollector(Config{}).collectIAMAdmins(context.Background(), &fakeAdminPolicies{}, nil, "111122223333")
	if got.read {
		t.Error("read = true without a credential report")
	}
}
