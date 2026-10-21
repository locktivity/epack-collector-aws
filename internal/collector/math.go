package collector

// percent calculates the percentage of count over total, returning 0 if total is 0.
func percent(count, total int) int {
	if total == 0 {
		return 0
	}
	return (count * MaxPercentage) / total
}

// pctOf returns count as a whole percentage of total, or nil when total is
// zero: a percentage over an empty population is not a value.
func pctOf(count, total int) *int {
	if total == 0 {
		return nil
	}
	p := percent(count, total)
	return &p
}

// sumCounts adds counts that may not have been read, which stay nil until
// one was.
func sumCounts(a, b *int) *int {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	}
	sum := *a + *b
	return &sum
}

// appendRows joins two regions' rows, keeping an empty list empty rather than
// nil, so a list that was read and found empty stays [].
func appendRows[T any](a, b []T) []T {
	if a == nil && b == nil {
		return nil
	}
	return append(append(make([]T, 0, len(a)+len(b)), a...), b...)
}
