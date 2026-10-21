package collector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/locktivity/epack/componentsdk"
)

const (
	awsPath            = "artifacts/aws.json"
	cloudPosturePath   = "artifacts/aws.cloud-posture.json"
	cloudPostureSchema = "evidencepack/cloud-posture@v1"
)

type gap struct {
	path       string
	pointer    string
	err        error
	unmeasured int
}

// gapLog records each value the collector leaves out in the run's recorder,
// and keeps the reasons so a normalized value derived from a detailed one can
// carry the same gap.
type gapLog struct {
	mu   sync.Mutex
	rec  *componentsdk.Recorder
	gaps []gap
}

func newGapLog(rec *componentsdk.Recorder) *gapLog {
	if rec == nil {
		rec = &componentsdk.Recorder{}
	}
	return &gapLog{rec: rec}
}

// leaveOut records the values at pointers in the detailed artifact as left
// out because of err. A nil err records nothing, so callers can pass the
// outcome of a read as it is.
func (l *gapLog) leaveOut(err error, pointers ...string) {
	l.rec.Helper()
	for _, pointer := range pointers {
		l.add(gap{path: awsPath, pointer: pointer, err: err})
	}
}

// partial records rollups at pointers as left out because unmeasured of the
// items they cover could not be read, err being one of the failures.
func (l *gapLog) partial(unmeasured int, err error, pointers ...string) {
	l.rec.Helper()
	if unmeasured <= 0 {
		l.leaveOut(err, pointers...)
		return
	}
	for _, pointer := range pointers {
		l.add(gap{path: awsPath, pointer: pointer, err: err, unmeasured: unmeasured})
	}
}

// mirror records, at a value in the normalized artifact, the gap covering
// the detailed value it is derived from, if any. It reports whether there
// was one.
func (l *gapLog) mirror(fromPointer, toPointer string) bool {
	if !l.covered(fromPointer) {
		return false
	}
	l.rec.Mirror(componentsdk.Location{Path: awsPath, Pointer: fromPointer}, componentsdk.Location{Path: cloudPosturePath, Pointer: toPointer})
	return true
}

// leaveOutNormalized records a value in the normalized artifact as left out
// because of err.
func (l *gapLog) leaveOutNormalized(err error, pointers ...string) {
	l.rec.Helper()
	for _, pointer := range pointers {
		l.add(gap{path: cloudPosturePath, pointer: pointer, err: err})
	}
}

// covered reports whether a gap covers the detailed value at pointer.
func (l *gapLog) covered(pointer string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.coveringLocked(awsPath, pointer)
	return ok
}

func (l *gapLog) add(g gap) {
	l.rec.Helper()
	if g.err == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, existing := range l.gaps {
		if existing.path == g.path && existing.pointer == g.pointer {
			return
		}
	}
	l.gaps = append(l.gaps, g)
	at := componentsdk.Location{Path: g.path, Pointer: g.pointer}
	opts := permissionOptions(g.err)
	if g.unmeasured > 0 {
		l.rec.Partial(at, g.unmeasured, g.err, opts...)
		return
	}
	l.rec.NotCollected(at, g.err, opts...)
}

// coveringLocked returns the gap at pointer or at an object that contains it.
func (l *gapLog) coveringLocked(path, pointer string) (gap, bool) {
	for _, g := range l.gaps {
		if g.path == path && (g.pointer == pointer || strings.HasPrefix(pointer, g.pointer+"/")) {
			return g, true
		}
	}
	return gap{}, false
}

// at builds JSON pointers under one account's entry in the detailed
// artifact, such as /accounts/0/iam/mfa_enabled.
type at struct {
	base string
}

func accountAt(index int) at {
	return at{base: fmt.Sprintf("/accounts/%d", index)}
}

// p joins path segments onto the account's pointer.
func (a at) p(segments ...any) string {
	var b strings.Builder
	b.WriteString(a.base)
	for _, s := range segments {
		b.WriteByte('/')
		b.WriteString(escapePointerToken(fmt.Sprint(s)))
	}
	return b.String()
}

// sub returns a builder for a nested object.
func (a at) sub(segments ...any) at {
	return at{base: a.p(segments...)}
}

func escapePointerToken(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

// pointers returns the pointers of the gaps recorded in the artifact at path.
func (l *gapLog) pointers(path string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, g := range l.gaps {
		if g.path == path {
			out = append(out, g.pointer)
		}
	}
	return out
}

// leaveOutCovered returns data as a JSON document in which every value a gap
// at path covers is null. The collector's structs hold a zero where a read
// failed; the gap is what decides that the zero never reaches the artifact.
func (l *gapLog) leaveOutCovered(path string, data any) (any, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	for _, pointer := range l.pointers(path) {
		nullAt(doc, pointer)
	}
	return doc, nil
}

// nullAt sets the value at an RFC 6901 pointer to null when it is present.
func nullAt(doc any, pointer string) {
	if pointer == "" || pointer[0] != '/' {
		return
	}
	tokens := strings.Split(pointer[1:], "/")
	cur := doc
	for i, token := range tokens {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		last := i == len(tokens)-1
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[token]
			if !ok {
				return
			}
			if last {
				node[token] = nil
				return
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(token)
			if err != nil || idx < 0 || idx >= len(node) {
				return
			}
			if last {
				node[idx] = nil
				return
			}
			cur = node[idx]
		default:
			return
		}
	}
}

// unread collects, during one scan of a surface or one row, the values a
// failed read left unknown: fields by JSON name relative to the surface or
// row ("a/b" for a nested field), each with the first error and the number
// of items it left unmeasured. The account's gaps are written from it once
// every region is merged, so concurrent scans never touch the gap log.
type unread struct {
	fields []unreadField
}

type unreadField struct {
	field      string
	err        error
	unmeasured int
}

// add marks fields as unknown because of err. A nil err marks nothing.
func (u *unread) add(err error, fields ...string) {
	u.addPartial(err, 0, fields...)
}

// addPartial marks rollups as unknown because unmeasured of the items they
// cover could not be read.
func (u *unread) addPartial(err error, unmeasured int, fields ...string) {
	if err == nil {
		return
	}
	for _, f := range fields {
		found := false
		for i := range u.fields {
			if u.fields[i].field == f {
				u.fields[i].unmeasured += unmeasured
				found = true
				break
			}
		}
		if !found {
			u.fields = append(u.fields, unreadField{field: f, err: err, unmeasured: unmeasured})
		}
	}
}

// merge folds o into u.
func (u *unread) merge(o unread) {
	for _, f := range o.fields {
		u.addPartial(f.err, f.unmeasured, f.field)
	}
}

// recordUnread writes u's fields as gaps under at.
func (c *Collector) recordUnread(at at, u unread) {
	c.gaps.rec.Helper()
	for _, f := range u.fields {
		segments := strings.Split(f.field, "/")
		parts := make([]any, len(segments))
		for i, s := range segments {
			parts[i] = s
		}
		c.gaps.partial(f.unmeasured, f.err, at.p(parts...))
	}
}

// recordRowsUnread writes each row's unknown fields as gaps under the rows'
// array at at, by the row's final index.
func recordRowsUnread[T any](c *Collector, at at, rows []T, missing func(*T) unread) {
	c.gaps.rec.Helper()
	for i := range rows {
		c.recordUnread(at.sub(i), missing(&rows[i]))
	}
}
