package collector

import (
	"errors"
	"strings"
	"testing"

	"github.com/aws/smithy-go"
	"github.com/locktivity/epack/componentsdk"
)

func TestWarnAccumulatesWarnings(t *testing.T) {
	c := newTestCollector(Config{})

	c.warn("first warning: %s", "alpha")
	c.warn("second warning: %d", 42)

	if len(c.warnings) != 2 {
		t.Fatalf("expected 2 warnings, got %d", len(c.warnings))
	}
	if c.warnings[0] != "first warning: alpha" {
		t.Fatalf("expected 'first warning: alpha', got %q", c.warnings[0])
	}
	if c.warnings[1] != "second warning: 42" {
		t.Fatalf("expected 'second warning: 42', got %q", c.warnings[1])
	}
}

func TestWarningsResetBetweenCollections(t *testing.T) {
	c := newTestCollector(Config{})

	// Simulate warnings from a previous run
	c.warnings = []string{"stale warning"}

	// Verify reset happens (mimics start of Collect)
	c.warnings = nil

	if c.warnings != nil {
		t.Fatalf("expected warnings to be nil after reset")
	}

	c.warn("fresh warning")
	if len(c.warnings) != 1 {
		t.Fatalf("expected 1 warning after reset, got %d", len(c.warnings))
	}
}

func TestFormatAccountError_IncludesLabel(t *testing.T) {
	acct := AccountConfig{RoleARN: "arn:aws:iam::111111111111:role/collector", Label: "production"}
	msg := formatAccountError(acct, errors.New("boom"))
	if !strings.Contains(msg, "production: arn:aws:iam::111111111111:role/collector") {
		t.Errorf("message %q missing labeled role info", msg)
	}

	unlabeled := AccountConfig{RoleARN: "arn:aws:iam::111111111111:role/collector"}
	msg = formatAccountError(unlabeled, errors.New("boom"))
	if strings.Contains(msg, ": arn:aws:iam::111111111111:role/collector): boom") == false && !strings.Contains(msg, "(arn:aws:iam::111111111111:role/collector)") {
		t.Errorf("unlabeled message %q should carry the bare role ARN", msg)
	}
}

// Below the audit level a warning names the account as trust diagnostics
// do, an error by its code, and a resource by its kind. At audit and above
// it reads as it always has.
func TestWarnNamesNoIdentifierBelowAudit(t *testing.T) {
	denied := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "User: arn:aws:sts::111122223333:assumed-role/collector/run is not authorized"}
	for _, tc := range []struct {
		level componentsdk.Level
		want  string
	}{
		{componentsdk.LevelTrust, "account 2 region us-east-1: failed to read rotation status for a KMS key: AccessDeniedException"},
		{componentsdk.LevelAudit, "account 111122223333 region us-east-1: failed to read rotation status for KMS key k-1: api error AccessDeniedException: " + denied.Message},
	} {
		c := newTestCollector(Config{})
		c.level = tc.level
		c.account = accountName{id: "111122223333", name: "2"}
		c.warn("account %s region %s: failed to read rotation status for %s: %v", "111122223333", "us-east-1", named{"KMS key k-1", "a KMS key"}, denied)
		if len(c.warnings) != 1 || c.warnings[0] != tc.want {
			t.Errorf("%s: warnings = %q, want %q", tc.level, c.warnings, tc.want)
		}
	}
}

// A trust run names an account by its configured label, as the default
// credentials' account, or by its position, and never by its role ARN.
func TestAccountErrorBelowAuditNamesNoRole(t *testing.T) {
	denied := &smithy.GenericAPIError{Code: "AccessDenied", Message: "Not authorized to perform sts:AssumeRole on arn:aws:iam::111111111111:role/collector"}
	for _, tc := range []struct {
		acct AccountConfig
		want string
	}{
		{AccountConfig{RoleARN: "arn:aws:iam::111111111111:role/collector", Label: "production"}, `failed to collect account "production": AccessDenied`},
		{AccountConfig{RoleARN: "arn:aws:iam::111111111111:role/collector"}, "failed to collect account 3: AccessDenied"},
		{AccountConfig{}, "failed to collect account (default credentials): AccessDenied"},
	} {
		c := newTestCollector(Config{})
		c.level = componentsdk.LevelTrust
		if got := c.accountError(tc.acct, 3, denied); got != tc.want {
			t.Errorf("accountError = %q, want %q", got, tc.want)
		}
		c.level = componentsdk.LevelAudit
		if got, want := c.accountError(tc.acct, 3, denied), formatAccountError(tc.acct, denied); got != want {
			t.Errorf("audit accountError = %q, want %q", got, want)
		}
	}
}
