package collector

import "testing"

func TestPercent(t *testing.T) {
	if got := percent(0, 0); got != 0 {
		t.Fatalf("expected 0 for zero total, got %d", got)
	}
	if got := percent(1, 4); got != 25 {
		t.Fatalf("expected 25, got %d", got)
	}
	if got := percent(3, 2); got != 150 {
		t.Fatalf("expected 150, got %d", got)
	}
}
