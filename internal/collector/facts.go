package collector

import (
	"errors"
	"fmt"

	"github.com/locktivity/epack/componentsdk"
)

// reason is why a normalized value is left out. It is the gap of the
// detailed value at pointer, or err, which a partial gap records with the
// number of items left unmeasured.
type reason struct {
	pointer    string
	err        error
	unmeasured int
}

// unsupported is the reason for a value AWS never reports, with a
// one-sentence detail.
func unsupported(detail string) *reason {
	return &reason{err: componentsdk.CodeError(componentsdk.CodeUnsupported, errors.New(detail))}
}

// notRead is the reason for a value AWS reports and the collector does not
// read, with a detail that names the call that would supply it.
func notRead(detail string) *reason {
	return &reason{err: componentsdk.CodeError(componentsdk.CodeNotRead, errors.New(detail))}
}

// record leaves the values at pointers in the artifact at path out for r.
func (r *reason) record(gaps *gapLog, path string, pointers ...string) {
	gaps.rec.Helper()
	for _, p := range pointers {
		switch {
		case r.pointer != "":
			if !gaps.mirrorTo(path, r.pointer, p) {
				gaps.leaveOutIn(path, fmt.Errorf("%s was expected to carry a gap", r.pointer), p)
			}
		case r.unmeasured > 0:
			gaps.partialIn(path, r.unmeasured, r.err, p)
		default:
			gaps.leaveOutIn(path, r.err, p)
		}
	}
}

// count is a number folded from the accounts' evidence, or why it is not
// known.
type count struct {
	n   int
	why *reason
}

// truth is a true-or-false value folded from the accounts' evidence, or why
// it is not known.
type truth struct {
	v   bool
	why *reason
}

// countAt is n, unless a gap covers the detailed value at pointer it is
// read with.
func countAt(gaps *gapLog, pointer string, n int) count {
	if gaps.covered(pointer) {
		return count{why: &reason{pointer: pointer}}
	}
	return count{n: n}
}

// truthAt is v, unless a gap covers the detailed value at pointer it is
// read with.
func truthAt(gaps *gapLog, pointer string, v bool) truth {
	if gaps.covered(pointer) {
		return truth{why: &reason{pointer: pointer}}
	}
	return truth{v: v}
}

// sumOf adds the counts. It is unknown, for the first unknown count's
// reason, when any count is.
func sumOf(counts ...count) count {
	total := 0
	for _, c := range counts {
		if c.why != nil {
			return c
		}
		total += c.n
	}
	return count{n: total}
}

// presentIn is true when any count is above 0. Otherwise it is unknown, for
// the first unknown count's reason, when any count is, and false when none
// is.
func presentIn(counts ...count) truth {
	var why *reason
	for _, c := range counts {
		switch {
		case c.why == nil && c.n > 0:
			return truth{v: true}
		case c.why != nil && why == nil:
			why = c.why
		}
	}
	return truth{why: why}
}

// anyOf is true when any value is true. Otherwise it is unknown, for the
// first unknown value's reason, when any value is, and false when none is.
func anyOf(values ...truth) truth {
	var why *reason
	for _, t := range values {
		switch {
		case t.why == nil && t.v:
			return truth{v: true}
		case t.why != nil && why == nil:
			why = t.why
		}
	}
	return truth{why: why}
}

// allOf is false when any value is false. Otherwise it is unknown, for the
// first unknown value's reason, when any value is, and true when none is.
func allOf(values ...truth) truth {
	var why *reason
	for _, t := range values {
		switch {
		case t.why == nil && !t.v:
			return truth{v: false}
		case t.why != nil && why == nil:
			why = t.why
		}
	}
	if why != nil {
		return truth{why: why}
	}
	return truth{v: true}
}

// writer writes folded values into one normalized artifact at path, and
// records a gap at each value it leaves out. audit is true at the audit
// level and above, where the counts are written.
type writer struct {
	gaps  *gapLog
	path  string
	audit bool
}

// count returns c to write from the audit level, or nil when it is left
// out.
func (w writer) count(c count, pointer string) *int {
	if !w.audit {
		return nil
	}
	w.gaps.rec.Helper()
	if c.why != nil {
		c.why.record(w.gaps, w.path, pointer)
		return nil
	}
	return intPtr(c.n)
}

// truth returns t to write, or nil when it is left out.
func (w writer) truth(t truth, pointer string) *bool {
	w.gaps.rec.Helper()
	if t.why != nil {
		t.why.record(w.gaps, w.path, pointer)
		return nil
	}
	return boolPtr(t.v)
}

// pct returns num as a percentage of den, rounded as rounding says. It is
// null when den is 0, and left out when den, or num over a population that
// is not empty, is unknown.
func (w writer) pct(num, den count, rounding componentsdk.Rounding, pointer string) Reading[float64] {
	w.gaps.rec.Helper()
	switch {
	case den.why != nil:
		den.why.record(w.gaps, w.path, pointer)
		return Reading[float64]{}
	case den.n == 0:
		return Reading[float64]{Read: true}
	case num.why != nil:
		num.why.record(w.gaps, w.path, pointer)
		return Reading[float64]{}
	}
	return percentOf(num.n, den.n, rounding)
}

// leaveOut records the values at pointers as left out for why. Values
// marked audit are passed over below the audit level, where they are not
// written.
func (w writer) leaveOut(why *reason, audit bool, pointers ...string) {
	if audit && !w.audit {
		return
	}
	w.gaps.rec.Helper()
	why.record(w.gaps, w.path, pointers...)
}
