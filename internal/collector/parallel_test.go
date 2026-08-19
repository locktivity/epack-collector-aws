package collector

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Later items finish first, so results assembled by completion order would
// come back reversed. The helper must return them in item order regardless.
func TestMapConcurrentPreservesItemOrder(t *testing.T) {
	items := make([]string, 8)
	for i := range items {
		items[i] = fmt.Sprintf("region-%d", i)
	}

	delays := map[string]time.Duration{}
	for i, item := range items {
		delays[item] = time.Duration(len(items)-i) * 10 * time.Millisecond
	}
	results := mapConcurrent(items, len(items), func(item string) string {
		time.Sleep(delays[item])
		return "scanned:" + item
	})

	if len(results) != len(items) {
		t.Fatalf("got %d results, want %d", len(results), len(items))
	}
	for i, item := range items {
		if results[i] != "scanned:"+item {
			t.Errorf("results[%d] = %q, want %q", i, results[i], "scanned:"+item)
		}
	}
}

func TestMapConcurrentRespectsLimit(t *testing.T) {
	const limit = 3
	items := make([]string, 12)
	for i := range items {
		items[i] = fmt.Sprintf("region-%d", i)
	}

	var inFlight, maxInFlight, calls int64
	var mu sync.Mutex
	mapConcurrent(items, limit, func(string) struct{} {
		n := atomic.AddInt64(&inFlight, 1)
		mu.Lock()
		if n > maxInFlight {
			maxInFlight = n
		}
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt64(&inFlight, -1)
		atomic.AddInt64(&calls, 1)
		return struct{}{}
	})

	if calls != int64(len(items)) {
		t.Errorf("f called %d times, want %d", calls, len(items))
	}
	if maxInFlight > limit {
		t.Errorf("observed %d concurrent calls, limit is %d", maxInFlight, limit)
	}
}

// A limit below one must not deadlock or panic; it degrades to serial.
func TestMapConcurrentClampsLimit(t *testing.T) {
	var order []string
	results := mapConcurrent([]string{"a", "b", "c"}, 0, func(item string) string {
		order = append(order, item)
		return item
	})
	for i, want := range []string{"a", "b", "c"} {
		if results[i] != want || order[i] != want {
			t.Fatalf("serial fallback broke ordering: results=%v order=%v", results, order)
		}
	}
}
