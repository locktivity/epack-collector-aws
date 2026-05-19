package collector

import (
	"reflect"
	"testing"
)

func TestTruncate_BelowCap(t *testing.T) {
	items := []int{3, 1, 2}
	kept, dropped, truncated := Truncate(items, 10, func(a, b int) bool { return a < b })

	if truncated {
		t.Error("truncated=true when below cap; want false")
	}
	if dropped != 0 {
		t.Errorf("dropped=%d when below cap; want 0", dropped)
	}
	// Below-cap path returns input unchanged (no sort).
	if !reflect.DeepEqual(kept, items) {
		t.Errorf("below-cap output sorted unexpectedly: got %v, want %v", kept, items)
	}
}

func TestTruncate_AtCap(t *testing.T) {
	items := []int{1, 2, 3}
	kept, dropped, truncated := Truncate(items, 3, func(a, b int) bool { return a < b })

	if truncated {
		t.Error("truncated=true when exactly at cap; want false")
	}
	if dropped != 0 {
		t.Errorf("dropped=%d when at cap; want 0", dropped)
	}
	if len(kept) != 3 {
		t.Errorf("len(kept)=%d when at cap; want 3", len(kept))
	}
}

func TestTruncate_OverCapSortsAndDrops(t *testing.T) {
	items := []int{5, 1, 4, 2, 3}
	kept, dropped, truncated := Truncate(items, 2, func(a, b int) bool { return a < b })

	if !truncated {
		t.Error("truncated=false when over cap; want true")
	}
	if dropped != 3 {
		t.Errorf("dropped=%d when over cap by 3; want 3", dropped)
	}
	want := []int{1, 2}
	if !reflect.DeepEqual(kept, want) {
		t.Errorf("kept=%v after sort+truncate; want %v", kept, want)
	}
}

func TestTruncate_SortIsStable(t *testing.T) {
	type row struct {
		key   int
		label string
	}
	items := []row{
		{1, "a"}, {2, "b"}, {1, "c"}, {2, "d"}, {1, "e"},
	}
	kept, dropped, truncated := Truncate(items, 3, func(a, b row) bool { return a.key < b.key })

	if !truncated || dropped != 2 {
		t.Fatalf("truncated=%v dropped=%d; want true,2", truncated, dropped)
	}
	// Stable sort preserves a, c, e ordering for the key=1 rows.
	want := []row{{1, "a"}, {1, "c"}, {1, "e"}}
	if !reflect.DeepEqual(kept, want) {
		t.Errorf("kept=%v; want %v (stable sort should preserve insertion order within equal keys)", kept, want)
	}
}
