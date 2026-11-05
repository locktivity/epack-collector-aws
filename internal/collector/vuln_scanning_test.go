package collector

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// fakeInspector answers the Inspector reads by region.
type fakeInspector struct {
	status    map[string]aws.InspectorAccountStatus
	statusErr map[string]error
	active    map[string]int
	all       map[string]int
	findings  []aws.InspectorFinding
	calls     []string
}

func (f *fakeInspector) GetInspectorAccountStatus(_ context.Context, region, _ string) (aws.InspectorAccountStatus, error) {
	f.calls = append(f.calls, "status "+region)
	return f.status[region], f.statusErr[region]
}

func (f *fakeInspector) CountInspectorCoverage(_ context.Context, region, _ string, activeOnly bool) (map[string]int, error) {
	f.calls = append(f.calls, "coverage "+region)
	if activeOnly {
		return f.active, nil
	}
	return f.all, nil
}

func (f *fakeInspector) ListInspectorFindings(_ context.Context, region, _ string, visit func(aws.InspectorFinding)) error {
	f.calls = append(f.calls, "findings "+region)
	for _, finding := range f.findings {
		visit(finding)
	}
	return nil
}

// inspectorOn is Inspector on with every scan type on.
func inspectorOn() aws.InspectorAccountStatus {
	return aws.InspectorAccountStatus{Enabled: true, ScanEnabled: map[string]bool{
		aws.InspectorEC2Instance: true, aws.InspectorECRImage: true, aws.InspectorLambdaFunction: true,
	}}
}

// A finding is overdue when it is critical and open more than 30 days, or
// high and open more than 90. Medium and low findings are never overdue.
func TestCollectInspectorScan_OverdueRule(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	daysAgo := func(d int) time.Time { return now.AddDate(0, 0, -d) }
	finding := func(severity string, days int) aws.InspectorFinding {
		return aws.InspectorFinding{ResourceType: aws.InspectorEC2Instance, Severity: severity, FirstObservedAt: daysAgo(days)}
	}
	client := &fakeInspector{
		status: map[string]aws.InspectorAccountStatus{"us-east-1": inspectorOn()},
		findings: []aws.InspectorFinding{
			finding("CRITICAL", 31), finding("CRITICAL", 30), finding("CRITICAL", 29),
			finding("HIGH", 91), finding("HIGH", 90), finding("HIGH", 89),
			finding("MEDIUM", 400), finding("LOW", 400), finding("INFORMATIONAL", 400),
		},
	}
	c := newTestCollector(Config{Now: func() time.Time { return now }})

	scan := c.collectInspectorScan(context.Background(), client, []string{"us-east-1"}, "111111111111")

	got := scan.regions[0].findings[aws.InspectorEC2Instance]
	want := findingCounts{critical: 3, high: 3, medium: 1, low: 1, overdueCritical: 1, overdueHigh: 1}
	if got == nil || *got != want {
		t.Errorf("counts = %+v, want %+v", got, want)
	}
}

// A region where Inspector is off is not read past its status, and one
// where ECR scanning is off is not asked for its ECR images.
func TestCollectInspectorScan_ReadsOnlyWhereOn(t *testing.T) {
	ec2Only := aws.InspectorAccountStatus{Enabled: true, ScanEnabled: map[string]bool{aws.InspectorEC2Instance: true}}
	client := &fakeInspector{status: map[string]aws.InspectorAccountStatus{"us-east-1": ec2Only, "us-west-2": {}}}

	newTestCollector(Config{}).collectInspectorScan(context.Background(), client, []string{"us-east-1", "us-west-2"}, "111111111111")

	want := []string{"status us-east-1", "coverage us-east-1", "findings us-east-1", "status us-west-2"}
	if len(client.calls) != len(want) {
		t.Fatalf("calls = %v, want %v", client.calls, want)
	}
	for i := range want {
		if client.calls[i] != want[i] {
			t.Errorf("calls = %v, want %v", client.calls, want)
			break
		}
	}
}

// vulnAccount is an account with one running instance and one function, and
// scan as its Inspector evidence.
func vulnAccount(scan inspectorScan) AccountPosture {
	return AccountPosture{
		AccountID: "111111111111",
		Regions:   []string{"us-east-1", "us-west-2"},
		EC2:       EC2Metrics{InstanceCount: 1},
		Lambda:    LambdaMetrics{FunctionCount: 1},
		inspector: scan,
	}
}

// vulnGap returns the gap recorded at pointer in the vuln-scanning artifact,
// or nil.
func vulnGap(gaps *gapLog, pointer string) *componentsdk.Gap {
	for _, g := range gaps.rec.Gaps() {
		if g.Path == vulnScanningPath && g.Pointer == pointer {
			return &g
		}
	}
	return nil
}

// A scanner is enabled only when its scan type is on in every region. A
// region where Inspector is off adds no scanned resource and no finding, and
// the ECR images there are left out as not read.
func TestVulnScanning_RegionOff(t *testing.T) {
	east := inspectorRegion{region: "us-east-1", status: inspectorOn(),
		active:    map[string]int{aws.InspectorEC2Instance: 1},
		ecrImages: 3,
		findings:  map[string]*findingCounts{aws.InspectorEC2Instance: {critical: 1, overdueCritical: 1}},
	}
	west := inspectorRegion{region: "us-west-2"}
	gaps := newGapLog(nil)
	output := &Output{CollectedAtLevel: string(componentsdk.LevelAudit), Accounts: []AccountPosture{vulnAccount(inspectorScan{regions: []inspectorRegion{east, west}})}}

	got := toVulnScanning(output, gaps)

	hosts, containers := got.Scanners[0], got.Scanners[1]
	if !samePtr(hosts.Enabled, boolPtr(false)) || !pctReading(hosts.CoveragePct, 100) {
		t.Errorf("hosts enabled %s, coverage %+v; want false and 100", showBool(hosts.Enabled), hosts.CoveragePct)
	}
	if !samePtr(hosts.OpenCriticalPresent, boolPtr(true)) || !samePtr(hosts.OverduePresent, boolPtr(true)) || !sameInt(hosts.OpenCriticalCount, intPtr(1)) {
		t.Errorf("hosts critical present %s, overdue present %s, critical %s; want true, true, and 1",
			showBool(hosts.OpenCriticalPresent), showBool(hosts.OverduePresent), showPct(hosts.OpenCriticalCount))
	}
	if containers.ResourceCount != nil || containers.CoveragePct.Read {
		t.Errorf("containers resource_count %s, coverage %+v; want both left out", showPct(containers.ResourceCount), containers.CoveragePct)
	}
	for _, pointer := range []string{"/scanners/1/resource_count", "/scanners/1/resources_present", "/scanners/1/coverage_pct"} {
		if g := vulnGap(gaps, pointer); g == nil || g.Code != componentsdk.CodeNotRead {
			t.Errorf("%s: gap %+v, want not_read", pointer, g)
		}
	}
}

// A region whose status cannot be read leaves out Inspector's values, with
// its error, unless another region already decides the value. The
// resources the collector lists still count.
func TestVulnScanning_StatusUnread(t *testing.T) {
	denied := componentsdk.CodeError(componentsdk.CodePermissionDenied, errors.New("AccessDenied"))
	off := inspectorRegion{region: "us-east-1", status: aws.InspectorAccountStatus{ScanEnabled: map[string]bool{}}}
	unread := inspectorRegion{region: "us-west-2", statusErr: denied}
	gaps := newGapLog(nil)
	output := &Output{Accounts: []AccountPosture{vulnAccount(inspectorScan{regions: []inspectorRegion{off, unread}})}}

	got := toVulnScanning(output, gaps).Scanners[0]

	if !samePtr(got.Enabled, boolPtr(false)) || !samePtr(got.ResourcesPresent, boolPtr(true)) {
		t.Errorf("enabled %s, resources present %s; want false from the region that is off, and true", showBool(got.Enabled), showBool(got.ResourcesPresent))
	}
	for _, pointer := range []string{"/scanners/0/coverage_pct", "/scanners/0/open_critical_present", "/scanners/0/overdue_present"} {
		if g := vulnGap(gaps, pointer); g == nil || g.Code != componentsdk.CodePermissionDenied {
			t.Errorf("%s: gap %+v, want permission_denied", pointer, g)
		}
	}
}

// More scanned resources than the collector lists means the reads disagree,
// so the scanned count and the coverage are left out.
func TestVulnScanning_ScannedAboveResources(t *testing.T) {
	east := inspectorRegion{region: "us-east-1", status: inspectorOn(), active: map[string]int{aws.InspectorEC2Instance: 2}, findings: map[string]*findingCounts{}}
	account := vulnAccount(inspectorScan{regions: []inspectorRegion{east}})
	account.Regions = []string{"us-east-1"}
	gaps := newGapLog(nil)

	got := toVulnScanning(&Output{CollectedAtLevel: string(componentsdk.LevelAudit), Accounts: []AccountPosture{account}}, gaps).Scanners[0]

	if got.ScannedResourceCount != nil || got.CoveragePct.Read {
		t.Errorf("scanned %s, coverage %+v; want both left out", showPct(got.ScannedResourceCount), got.CoveragePct)
	}
	if g := vulnGap(gaps, "/scanners/0/coverage_pct"); g == nil || g.Code != componentsdk.CodeInvalidResponse {
		t.Errorf("coverage gap %+v, want invalid_response", g)
	}
}

// The totals add up the accounts, and enabled is true only when every
// account's is. A failed account leaves each total out with its error.
func TestVulnScanning_FoldsAccounts(t *testing.T) {
	on := inspectorRegion{region: "us-east-1", status: inspectorOn(), active: map[string]int{aws.InspectorEC2Instance: 1}, ecrImages: 1, findings: map[string]*findingCounts{}}
	first := vulnAccount(inspectorScan{regions: []inspectorRegion{on}})
	second := vulnAccount(inspectorScan{regions: []inspectorRegion{on}})
	second.AccountID, second.EC2.InstanceCount = "222222222222", 3
	output := &Output{CollectedAtLevel: string(componentsdk.LevelAudit), Accounts: []AccountPosture{first, second}}

	got := toVulnScanning(output, newGapLog(nil))

	hosts := got.Scanners[0]
	if !samePtr(hosts.Enabled, boolPtr(true)) || !sameInt(hosts.ResourceCount, intPtr(4)) || !pctReading(hosts.CoveragePct, 50) {
		t.Errorf("enabled %s, resources %s, coverage %+v; want true, 4, and 50", showBool(hosts.Enabled), showPct(hosts.ResourceCount), hosts.CoveragePct)
	}
	if len(got.Scopes) != 2 || !pctReading(got.Scopes[1].Scanners[0].CoveragePct, 33) {
		t.Errorf("scopes = %+v, want the second account at 33", got.Scopes)
	}

	failure := componentsdk.CodeError(componentsdk.CodeAuthFailed, errors.New("InvalidIdentityToken"))
	output.FailedAccounts = []FailedAccountRecord{{ErrorCode: "InvalidIdentityToken", err: failure}}
	gaps := newGapLog(nil)
	hosts = toVulnScanning(output, gaps).Scanners[0]
	if !samePtr(hosts.ResourcesPresent, boolPtr(true)) || hosts.CoveragePct.Read {
		t.Errorf("resources present %s, coverage %+v; want true and left out", showBool(hosts.ResourcesPresent), hosts.CoveragePct)
	}
	if g := vulnGap(gaps, "/scanners/0/enabled"); g == nil || g.Code != componentsdk.CodeAuthFailed {
		t.Errorf("enabled gap %+v, want the failed account's auth_failed", g)
	}
}
