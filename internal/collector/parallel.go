package collector

import "sync"

// regionConcurrency bounds how many regions are scanned at once. AWS service
// quotas are independent per region, so concurrent regions do not compete for
// API rate limits; the bound keeps total connection and retry pressure
// predictable.
const regionConcurrency = 5

// mapConcurrent runs f once per item with at most limit calls in flight and
// returns results indexed by item order, so callers can assemble output
// deterministically regardless of completion order.
func mapConcurrent[T any](items []string, limit int, f func(item string) T) []T {
	if limit < 1 {
		limit = 1
	}
	results := make([]T, len(items))
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i, item := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = f(item)
		}()
	}
	wg.Wait()
	return results
}
