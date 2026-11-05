package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// guardDutyClient answers one region's GuardDuty with a single enabled
// detector holding total unarchived high findings. When countFails is set,
// the unsorted ListFindings reads that count the findings (and the stale
// ones) fail with a server error, while the sorted listing that fetches
// them still answers.
func guardDutyClient(t *testing.T, total int, countFails bool) *aws.AWSClient {
	t.Helper()
	isolateAWSEnvironment(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDKITEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "kit-secret")
	t.Setenv("AWS_REGION", "us-east-1")

	reply := func(r *http.Request, status int, contentType, body string) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Status:     fmt.Sprintf("%d", status),
			Header:     http.Header{"Content-Type": []string{contentType}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    r,
		}, nil
	}
	const detector = "det1"
	rt := roundTripper(func(r *http.Request) (*http.Response, error) {
		var raw []byte
		if r.Body != nil {
			raw, _ = io.ReadAll(r.Body)
		}
		body := string(raw)
		host, path := r.URL.Host, r.URL.Path
		switch {
		case strings.HasPrefix(host, "guardduty."):
			switch {
			case r.Method == http.MethodGet && path == "/detector":
				return reply(r, 200, "application/json", `{"detectorIds":["`+detector+`"]}`)
			case r.Method == http.MethodGet && path == "/detector/"+detector:
				return reply(r, 200, "application/json", `{"status":"ENABLED","findingPublishingFrequency":"SIX_HOURS","features":[]}`)
			case r.Method == http.MethodGet && path == "/detector/"+detector+"/administrator":
				return reply(r, 200, "application/json", `{}`)
			case r.Method == http.MethodPost && path == "/detector/"+detector+"/findings":
				var req struct {
					NextToken    *string        `json:"nextToken"`
					SortCriteria map[string]any `json:"sortCriteria"`
				}
				_ = json.Unmarshal(raw, &req)
				sorted := req.SortCriteria != nil
				stale := strings.Contains(body, "updatedAt")
				if !sorted && countFails {
					return reply(r, 500, "application/json", `{"message":"internal failure","__type":"InternalServerErrorException"}`)
				}
				count := total
				if stale {
					count = 0
				}
				start := 0
				if req.NextToken != nil {
					start, _ = strconv.Atoi(*req.NextToken)
				}
				end := start + 50
				if end > count {
					end = count
				}
				ids := []string{}
				for i := start; i < end; i++ {
					ids = append(ids, fmt.Sprintf("f-%05d", i))
				}
				out := map[string]any{"findingIds": ids}
				if end < count {
					out["nextToken"] = strconv.Itoa(end)
				}
				b, _ := json.Marshal(out)
				return reply(r, 200, "application/json", string(b))
			case r.Method == http.MethodPost && path == "/detector/"+detector+"/findings/get":
				var req struct {
					FindingIds []string `json:"findingIds"`
				}
				_ = json.Unmarshal(raw, &req)
				findings := []map[string]any{}
				for _, id := range req.FindingIds {
					findings = append(findings, map[string]any{
						"id": id, "type": "Recon:IAMUser/MaliciousIPCaller", "title": "t", "severity": 8,
						"createdAt": "2026-01-01T00:00:00.000Z", "updatedAt": "2026-01-02T00:00:00.000Z",
						"resource": map[string]any{"resourceType": "AccessKey"},
					})
				}
				b, _ := json.Marshal(map[string]any{"findings": findings})
				return reply(r, 200, "application/json", string(b))
			}
		case strings.HasPrefix(host, "events."):
			return reply(r, 200, "application/x-amz-json-1.1", `{"Rules":[]}`)
		}
		return reply(r, 404, "application/json", `{"message":"unexpected `+r.Method+` `+host+path+`"}`)
	})

	client, err := aws.NewClient(context.Background(), aws.Options{
		HTTPClient: &http.Client{Transport: rt},
		Now:        func() time.Time { return time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// When a detector's finding count could not be read, the number of findings
// past the cap is unknown, so findings_dropped_count is left out.
func TestCollectGuardDutyStatus_DroppedCountUnknownWhenTheCountFails(t *testing.T) {
	client := guardDutyClient(t, GuardDutyFindingsCap+200, true)
	c := newTestCollector(Config{})
	var status GuardDutyStatus

	c.collectGuardDutyStatus(context.Background(), client, []string{"us-east-1"}, "111122223333", &status, componentsdk.LevelInternal)

	if !status.FindingsTruncated {
		t.Fatalf("FindingsTruncated = false with %d findings listed", len(status.Findings))
	}
	if status.FindingsDroppedCount != 0 || !hasUnread(status.missing, "findings_dropped_count", 0) {
		t.Errorf("FindingsDroppedCount = %d, want it left out", status.FindingsDroppedCount)
	}
}

// When the count is readable, the findings past the cap are counted.
func TestCollectGuardDutyStatus_DroppedCountPastTheCap(t *testing.T) {
	client := guardDutyClient(t, GuardDutyFindingsCap+200, false)
	c := newTestCollector(Config{})
	var status GuardDutyStatus

	c.collectGuardDutyStatus(context.Background(), client, []string{"us-east-1"}, "111122223333", &status, componentsdk.LevelInternal)

	if !status.FindingsTruncated {
		t.Fatalf("FindingsTruncated = false with %d findings listed", len(status.Findings))
	}
	if len(status.Findings) != GuardDutyFindingsCap {
		t.Errorf("len(Findings) = %d, want the cap %d", len(status.Findings), GuardDutyFindingsCap)
	}
	if status.FindingsDroppedCount != 200 {
		t.Errorf("FindingsDroppedCount = %d, want 200", status.FindingsDroppedCount)
	}
}

// gdNow is the clock fakeGuardDuty runs on.
var gdNow = time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)

const (
	gdAccount = "111122223333" // the scanned account
	gdMember  = "444455556666" // another account in the same GuardDuty organization
)

// gdFinding is one finding in a fakeGuardDuty detector.
type gdFinding struct {
	ID        string
	AccountID string
	Severity  float64
	Title     string
	Sample    bool
	Archived  bool
	Updated   time.Time
}

func (f gdFinding) json() map[string]any {
	service := map[string]any{"archived": f.Archived}
	if f.Sample {
		service["additionalInfo"] = map[string]any{"type": "default", "value": `{"sample":true}`}
	}
	return map[string]any{
		"id": f.ID, "accountId": f.AccountID, "type": "Recon:IAMUser/MaliciousIPCaller", "title": f.Title,
		"severity": f.Severity, "createdAt": "2026-01-01T00:00:00.000Z", "updatedAt": f.Updated.Format("2006-01-02T15:04:05.000Z"),
		"resource": map[string]any{"resourceType": "AccessKey"},
		"service":  service,
	}
}

// fakeGuardDuty answers GuardDuty for one region with one enabled detector
// holding findings. It applies the criteria ListFindings is given as the
// API documents them, so a count or a listing holds what the request asked
// for. It refuses an attribute it does not model.
type fakeGuardDuty struct {
	findings []gdFinding
	// getFindingsDenied makes GetFindings fail with AccessDenied, as for a
	// role with guardduty:ListFindings and without guardduty:GetFindings.
	getFindingsDenied bool
}

type gdCondition struct {
	Eq                 []string `json:"eq"`
	Equals             []string `json:"equals"`
	Neq                []string `json:"neq"`
	NotEquals          []string `json:"notEquals"`
	Gt                 *int64   `json:"gt"`
	Gte                *int64   `json:"gte"`
	Lt                 *int64   `json:"lt"`
	Lte                *int64   `json:"lte"`
	GreaterThan        *int64   `json:"greaterThan"`
	GreaterThanOrEqual *int64   `json:"greaterThanOrEqual"`
	LessThan           *int64   `json:"lessThan"`
	LessThanOrEqual    *int64   `json:"lessThanOrEqual"`
}

func firstLimit(vs ...*int64) *int64 {
	for _, v := range vs {
		if v != nil {
			return v
		}
	}
	return nil
}

// matches reports whether f satisfies every criterion, and false with an
// error for an attribute the fake does not model.
func (f gdFinding) matches(criteria map[string]gdCondition) (bool, error) {
	for attr, c := range criteria {
		var number *float64
		var str *string
		switch attr {
		case "severity":
			v := f.Severity
			number = &v
		case "updatedAt":
			v := float64(f.Updated.UnixMilli())
			number = &v
		case "service.archived":
			s := strconv.FormatBool(f.Archived)
			str = &s
		case "accountId":
			s := f.AccountID
			str = &s
		default:
			return false, fmt.Errorf("criterion %q is not modeled", attr)
		}
		if number != nil {
			if v := firstLimit(c.Gt, c.GreaterThan); v != nil && !(*number > float64(*v)) {
				return false, nil
			}
			if v := firstLimit(c.Gte, c.GreaterThanOrEqual); v != nil && !(*number >= float64(*v)) {
				return false, nil
			}
			if v := firstLimit(c.Lt, c.LessThan); v != nil && !(*number < float64(*v)) {
				return false, nil
			}
			if v := firstLimit(c.Lte, c.LessThanOrEqual); v != nil && !(*number <= float64(*v)) {
				return false, nil
			}
		}
		if want := append(append([]string{}, c.Eq...), c.Equals...); len(want) > 0 {
			ok := false
			for _, w := range want {
				ok = ok || (str != nil && *str == w)
			}
			if !ok {
				return false, nil
			}
		}
		if not := append(append([]string{}, c.Neq...), c.NotEquals...); len(not) > 0 {
			for _, w := range not {
				if str != nil && *str == w {
					return false, nil
				}
			}
		}
	}
	return true, nil
}

func (g *fakeGuardDuty) client(t *testing.T) *aws.AWSClient {
	t.Helper()
	isolateAWSEnvironment(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDKITEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "kit-secret")
	t.Setenv("AWS_REGION", "us-east-1")

	reply := func(r *http.Request, status int, contentType, body string) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Status:     fmt.Sprintf("%d", status),
			Header:     http.Header{"Content-Type": []string{contentType}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    r,
		}, nil
	}
	const detector = "det1"
	rt := roundTripper(func(r *http.Request) (*http.Response, error) {
		var raw []byte
		if r.Body != nil {
			raw, _ = io.ReadAll(r.Body)
		}
		host, path := r.URL.Host, r.URL.Path
		switch {
		case strings.HasPrefix(host, "guardduty."):
			switch {
			case r.Method == http.MethodGet && path == "/detector":
				return reply(r, 200, "application/json", `{"detectorIds":["`+detector+`"]}`)
			case r.Method == http.MethodGet && path == "/detector/"+detector:
				return reply(r, 200, "application/json", `{"status":"ENABLED","findingPublishingFrequency":"SIX_HOURS","features":[]}`)
			case r.Method == http.MethodGet && path == "/detector/"+detector+"/administrator":
				return reply(r, 200, "application/json", `{}`)
			case r.Method == http.MethodPost && path == "/detector/"+detector+"/findings":
				var req struct {
					FindingCriteria struct {
						Criterion map[string]gdCondition `json:"criterion"`
					} `json:"findingCriteria"`
					MaxResults   int            `json:"maxResults"`
					NextToken    *string        `json:"nextToken"`
					SortCriteria map[string]any `json:"sortCriteria"`
				}
				_ = json.Unmarshal(raw, &req)
				var matched []gdFinding
				for _, f := range g.findings {
					ok, err := f.matches(req.FindingCriteria.Criterion)
					if err != nil {
						return reply(r, 400, "application/json", `{"message":"`+err.Error()+`","__type":"BadRequestException"}`)
					}
					if ok {
						matched = append(matched, f)
					}
				}
				if req.SortCriteria != nil {
					sort.SliceStable(matched, func(i, j int) bool { return matched[i].Severity > matched[j].Severity })
				}
				start := 0
				if req.NextToken != nil {
					start, _ = strconv.Atoi(*req.NextToken)
				}
				end := start + 50
				if end > len(matched) {
					end = len(matched)
				}
				ids := []string{}
				for _, f := range matched[start:end] {
					ids = append(ids, f.ID)
				}
				out := map[string]any{"findingIds": ids}
				if end < len(matched) {
					out["nextToken"] = strconv.Itoa(end)
				}
				b, _ := json.Marshal(out)
				return reply(r, 200, "application/json", string(b))
			case r.Method == http.MethodPost && path == "/detector/"+detector+"/findings/get":
				if g.getFindingsDenied {
					return reply(r, 403, "application/json", `{"message":"User is not authorized to perform: guardduty:GetFindings","__type":"AccessDeniedException"}`)
				}
				var req struct {
					FindingIds []string `json:"findingIds"`
				}
				_ = json.Unmarshal(raw, &req)
				byID := map[string]gdFinding{}
				for _, f := range g.findings {
					byID[f.ID] = f
				}
				findings := []map[string]any{}
				for _, id := range req.FindingIds {
					findings = append(findings, byID[id].json())
				}
				b, _ := json.Marshal(map[string]any{"findings": findings})
				return reply(r, 200, "application/json", string(b))
			}
		case strings.HasPrefix(host, "events."):
			return reply(r, 200, "application/x-amz-json-1.1", `{"Rules":[]}`)
		}
		return reply(r, 404, "application/json", `{"message":"unexpected `+r.Method+` `+host+path+`"}`)
	})

	client, err := aws.NewClient(context.Background(), aws.Options{
		HTTPClient: &http.Client{Transport: rt},
		Now:        func() time.Time { return gdNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// scan runs the GuardDuty step for gdAccount at internal level.
func (g *fakeGuardDuty) scan(t *testing.T) GuardDutyStatus {
	t.Helper()
	c := newTestCollector(Config{})
	var status GuardDutyStatus
	c.collectGuardDutyStatus(context.Background(), g.client(t), []string{"us-east-1"}, gdAccount, &status, componentsdk.LevelInternal)
	return status
}

func gdFindingOf(id string, account string, severity float64, updated time.Time) gdFinding {
	return gdFinding{ID: id, AccountID: account, Severity: severity, Title: "finding " + id, Updated: updated}
}

var (
	gdStale = gdNow.Add(-72 * time.Hour)
	gdFresh = gdNow.Add(-2 * time.Hour)
)

// scanGuardDutyAudit runs the GuardDuty step for gdAccount at audit level.
func scanGuardDutyAudit(t *testing.T, g *fakeGuardDuty) GuardDutyStatus {
	t.Helper()
	c := newTestCollector(Config{})
	var status GuardDutyStatus
	c.collectGuardDutyStatus(context.Background(), g.client(t), []string{"us-east-1"}, gdAccount, &status, componentsdk.LevelAudit)
	if len(status.Detectors) != 1 {
		t.Fatalf("Detectors = %d rows, want 1", len(status.Detectors))
	}
	return status
}

// The counts and the listing leave out archived findings and findings under
// severity 7. The stale count also leaves out findings updated in the last 48
// hours.
func TestCollectGuardDutyStatus_CountsUnarchivedHighFindings(t *testing.T) {
	g := &fakeGuardDuty{findings: []gdFinding{
		gdFindingOf("stale-high", gdAccount, 8, gdStale),
		gdFindingOf("fresh-high", gdAccount, 8.9, gdFresh),
		gdFindingOf("stale-critical", gdAccount, 9.5, gdStale),
		{ID: "archived", AccountID: gdAccount, Severity: 8, Updated: gdStale, Archived: true},
		gdFindingOf("stale-medium", gdAccount, 6.9, gdStale),
	}}

	status := scanGuardDutyAudit(t, g)
	d := status.Detectors[0]
	if d.HighOrCriticalFindings != 3 {
		t.Errorf("HighOrCriticalFindings = %d, want 3 (two stale, one fresh)", d.HighOrCriticalFindings)
	}
	if d.HighOrCriticalFindingsOlderThan48Hours != 2 || status.UnremediatedFindingsOver48Hours != 2 {
		t.Errorf("stale = %d on the detector, %d on the account, want 2", d.HighOrCriticalFindingsOlderThan48Hours, status.UnremediatedFindingsOver48Hours)
	}
	if rows := g.scan(t).Findings; len(rows) != 3 {
		t.Errorf("len(Findings) = %d, want 3", len(rows))
	}
}

// Sample findings carry placeholder values and "sample": true in
// additionalInfo. ListFindings has no criterion for them, so they count until
// they are archived. They are left out of the listing once fetched.
func TestCollectGuardDutyStatus_ListsNoSampleFindings(t *testing.T) {
	sample := func(id string) gdFinding {
		f := gdFindingOf(id, gdAccount, 8, gdStale)
		f.Title, f.Sample = "[SAMPLE] Backdoor:EC2/C&CActivity.B!DNS", true
		return f
	}
	g := &fakeGuardDuty{findings: []gdFinding{
		gdFindingOf("real", gdAccount, 8, gdStale),
		sample("sample-1"),
		sample("sample-2"),
	}}

	status := scanGuardDutyAudit(t, g)
	d := status.Detectors[0]
	if d.HighOrCriticalFindings != 3 {
		t.Errorf("HighOrCriticalFindings = %d, want 3 with the two sample findings", d.HighOrCriticalFindings)
	}
	if d.HighOrCriticalFindingsOlderThan48Hours != 3 || status.UnremediatedFindingsOver48Hours != 3 {
		t.Errorf("stale = %d on the detector, %d on the account, want 3", d.HighOrCriticalFindingsOlderThan48Hours, status.UnremediatedFindingsOver48Hours)
	}
	rows := g.scan(t).Findings
	if len(rows) != 1 || rows[0].ID != "real" {
		t.Errorf("findings = %v, want only the real finding", rows)
	}
}

// An administrator's detector also holds its member accounts' findings, each
// with its own accountId. The counts and the listing keep the scanned
// account's own findings.
func TestCollectGuardDutyStatus_CountsOnlyTheScannedAccount(t *testing.T) {
	g := &fakeGuardDuty{findings: []gdFinding{
		gdFindingOf("own", gdAccount, 8, gdStale),
		gdFindingOf("member-1", gdMember, 8, gdStale),
		gdFindingOf("member-2", gdMember, 9, gdStale),
	}}

	status := scanGuardDutyAudit(t, g)
	d := status.Detectors[0]
	if d.HighOrCriticalFindings != 1 {
		t.Errorf("HighOrCriticalFindings = %d, want 1 from %s", d.HighOrCriticalFindings, gdAccount)
	}
	if d.HighOrCriticalFindingsOlderThan48Hours != 1 || status.UnremediatedFindingsOver48Hours != 1 {
		t.Errorf("stale = %d on the detector, %d on the account, want 1", d.HighOrCriticalFindingsOlderThan48Hours, status.UnremediatedFindingsOver48Hours)
	}
	if rows := g.scan(t).Findings; len(rows) != 1 {
		t.Errorf("len(Findings) = %d, want 1", len(rows))
	}
}

// When the findings cannot be fetched, the detector may hold more than the
// cap, so findings_truncated and findings_dropped_count are left out.
func TestCollectGuardDutyStatus_TruncationUnknownWhenFindingsCannotBeFetched(t *testing.T) {
	var many []gdFinding
	for i := 0; i < GuardDutyFindingsCap+200; i++ {
		many = append(many, gdFindingOf(fmt.Sprintf("f-%05d", i), gdAccount, 8, gdFresh))
	}

	status := (&fakeGuardDuty{findings: many, getFindingsDenied: true}).scan(t)
	for _, field := range []string{"findings", "findings_truncated", "findings_dropped_count"} {
		if !hasUnread(status.missing, field, 0) {
			t.Errorf("%s is not marked unread after GetFindings was denied: %+v", field, status.missing)
		}
	}

	status = (&fakeGuardDuty{findings: many}).scan(t)
	if !status.FindingsTruncated || status.FindingsDroppedCount != 200 || len(status.Findings) != GuardDutyFindingsCap {
		t.Errorf("FindingsTruncated = %v, FindingsDroppedCount = %d, len(Findings) = %d; want true, 200 and %d",
			status.FindingsTruncated, status.FindingsDroppedCount, len(status.Findings), GuardDutyFindingsCap)
	}
}
