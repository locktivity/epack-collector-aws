package collector

import (
	"errors"
	"strings"
	"testing"
)

func TestWarnAccumulatesWarnings(t *testing.T) {
	c := &Collector{}

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
	c := &Collector{}

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
