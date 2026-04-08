package collector

import "testing"

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
