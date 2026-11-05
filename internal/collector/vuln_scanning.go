package collector

import (
	"fmt"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// VulnScanning is the evidencepack/vuln-scanning@v1 artifact for every
// account collected, with one Amazon Inspector entry for each kind of
// resource. The scanners hold totals across the accounts, and from
// the audit level scopes holds each account alone. A value left out has a
// gap, and the counts and scopes are written from the audit level only.
type VulnScanning struct {
	SchemaVersion string        `json:"schema_version"`
	CollectedAt   string        `json:"collected_at"`
	Provider      string        `json:"provider"`
	Scanners      []VulnScanner `json:"scanners"`
	Scopes        []VulnScope   `json:"scopes,omitempty"`
}

// VulnScanner is one scanner's coverage and open findings for one kind of
// resource.
type VulnScanner struct {
	Scanner              string           `json:"scanner"`
	Category             string           `json:"category"`
	Enabled              *bool            `json:"enabled,omitempty"`
	ResourcesPresent     *bool            `json:"resources_present,omitempty"`
	ResourceCount        *int             `json:"resource_count,omitempty"`
	ScannedResourceCount *int             `json:"scanned_resource_count,omitempty"`
	CoveragePct          Reading[float64] `json:"coverage_pct,omitzero"`
	OpenCriticalPresent  *bool            `json:"open_critical_present,omitempty"`
	OpenHighPresent      *bool            `json:"open_high_present,omitempty"`
	OverduePresent       *bool            `json:"overdue_present,omitempty"`
	OpenCriticalCount    *int             `json:"open_critical_count,omitempty"`
	OpenHighCount        *int             `json:"open_high_count,omitempty"`
	OpenMediumCount      *int             `json:"open_medium_count,omitempty"`
	OpenLowCount         *int             `json:"open_low_count,omitempty"`
	OverdueCriticalCount *int             `json:"overdue_critical_count,omitempty"`
	OverdueHighCount     *int             `json:"overdue_high_count,omitempty"`
}

// VulnScope is one account's scanners, written from the audit level.
type VulnScope struct {
	ID       string        `json:"id"`
	Kind     string        `json:"kind"`
	Scanners []VulnScanner `json:"scanners"`
}

// inspectorScanner is the scanner name of every entry.
const inspectorScanner = "inspector"

// inspectorCategories pairs each vuln-scanning category with its resource
// type in Inspector.
var inspectorCategories = []struct {
	category, resourceType string
}{
	{"hosts", aws.InspectorEC2Instance},
	{"containers", aws.InspectorECRImage},
	{"functions", aws.InspectorLambdaFunction},
}

// ecrImagesNotRead is why the ECR image count is left out where ECR scanning
// is off.
var ecrImagesNotRead = notRead("Where ECR scanning is off, the ECR images are listed with ECR's DescribeRepositories and DescribeImages, which this collector does not call.")

// scannerFacts is one category's evidence in one account, or totaled across
// the accounts.
type scannerFacts struct {
	enabled            truth
	resources, scanned count
	resourcesPresent   truth

	critical, high, medium, low  count
	overdueCritical, overdueHigh count
	criticalPresent, highPresent truth
	overduePresent               truth
}

// failedScanner is a failed account's evidence, every value unknown because
// of err.
func failedScanner(err error) scannerFacts {
	why := &reason{err: err}
	c, t := count{why: why}, truth{why: why}
	return scannerFacts{
		enabled: t, resources: c, scanned: c, resourcesPresent: t,
		critical: c, high: c, medium: c, low: c, overdueCritical: c, overdueHigh: c,
		criticalPresent: t, highPresent: t, overduePresent: t,
	}
}

// scannerOf folds account i's evidence for the resource type. Inspector is
// enabled for it when its scan type is on in every region scanned. A region
// where Inspector is off adds no scanned resource and no finding. The EC2
// instances and Lambda functions are the ones the collector lists. The ECR
// images come from Inspector's coverage, which holds them only where ECR
// scanning is on.
func scannerOf(acct AccountPosture, i int, resourceType string, gaps *gapLog) scannerFacts {
	scan := acct.inspector
	if scan.err != nil {
		return failedScanner(scan.err)
	}
	var enabled []truth
	var scanned, images []count
	var critical, high, medium, low, overdueCritical, overdueHigh []count
	for _, r := range scan.regions {
		if r.statusErr != nil {
			unread := count{why: &reason{err: r.statusErr}}
			enabled = append(enabled, truth{why: unread.why})
			scanned, images = append(scanned, unread), append(images, unread)
			critical, high, medium, low = append(critical, unread), append(high, unread), append(medium, unread), append(low, unread)
			overdueCritical, overdueHigh = append(overdueCritical, unread), append(overdueHigh, unread)
			continue
		}
		enabled = append(enabled, truth{v: r.status.ScanEnabled[resourceType]})
		switch {
		case !r.status.ScanEnabled[aws.InspectorECRImage]:
			images = append(images, count{why: ecrImagesNotRead})
		case r.ecrImagesErr != nil:
			images = append(images, count{why: &reason{err: r.ecrImagesErr}})
		default:
			images = append(images, count{n: r.ecrImages})
		}
		switch {
		case !r.status.Enabled:
			scanned = append(scanned, count{})
		case r.activeErr != nil:
			scanned = append(scanned, count{why: &reason{err: r.activeErr}})
		default:
			scanned = append(scanned, count{n: r.active[resourceType]})
		}
		var f findingCounts
		var why *reason
		switch {
		case !r.status.Enabled:
		case r.findingsErr != nil:
			why = &reason{err: r.findingsErr}
		case r.findings[resourceType] != nil:
			f = *r.findings[resourceType]
		}
		for _, c := range []struct {
			dst *[]count
			n   int
		}{
			{&critical, f.critical}, {&high, f.high}, {&medium, f.medium}, {&low, f.low},
			{&overdueCritical, f.overdueCritical}, {&overdueHigh, f.overdueHigh},
		} {
			*c.dst = append(*c.dst, count{n: c.n, why: why})
		}
	}

	at := accountAt(i)
	var resources count
	switch resourceType {
	case aws.InspectorEC2Instance:
		resources = countAt(gaps, at.p("ec2", "instance_count"), acct.EC2.InstanceCount)
	case aws.InspectorLambdaFunction:
		resources = countAt(gaps, at.p("lambda", "function_count"), acct.Lambda.FunctionCount)
	default:
		resources = sumOf(images...)
	}
	return scannerFacts{
		enabled:          allOf(enabled...),
		resources:        resources,
		resourcesPresent: presentIn(resources),
		scanned:          sumOf(scanned...),
		critical:         sumOf(critical...),
		high:             sumOf(high...),
		medium:           sumOf(medium...),
		low:              sumOf(low...),
		overdueCritical:  sumOf(overdueCritical...),
		overdueHigh:      sumOf(overdueHigh...),
		criticalPresent:  presentIn(critical...),
		highPresent:      presentIn(high...),
		overduePresent:   presentIn(append(append([]count{}, overdueCritical...), overdueHigh...)...),
	}
}

// foldScanners totals one category across the accounts. Counts add up, a
// present flag is true when any account's is, and enabled is true only when
// every account's is.
func foldScanners(accounts []scannerFacts) scannerFacts {
	counts := func(get func(scannerFacts) count) count {
		out := make([]count, len(accounts))
		for i, a := range accounts {
			out[i] = get(a)
		}
		return sumOf(out...)
	}
	flags := func(get func(scannerFacts) truth) []truth {
		out := make([]truth, len(accounts))
		for i, a := range accounts {
			out[i] = get(a)
		}
		return out
	}
	return scannerFacts{
		enabled:          allOf(flags(func(s scannerFacts) truth { return s.enabled })...),
		resources:        counts(func(s scannerFacts) count { return s.resources }),
		resourcesPresent: anyOf(flags(func(s scannerFacts) truth { return s.resourcesPresent })...),
		scanned:          counts(func(s scannerFacts) count { return s.scanned }),
		critical:         counts(func(s scannerFacts) count { return s.critical }),
		high:             counts(func(s scannerFacts) count { return s.high }),
		medium:           counts(func(s scannerFacts) count { return s.medium }),
		low:              counts(func(s scannerFacts) count { return s.low }),
		overdueCritical:  counts(func(s scannerFacts) count { return s.overdueCritical }),
		overdueHigh:      counts(func(s scannerFacts) count { return s.overdueHigh }),
		criticalPresent:  anyOf(flags(func(s scannerFacts) truth { return s.criticalPresent })...),
		highPresent:      anyOf(flags(func(s scannerFacts) truth { return s.highPresent })...),
		overduePresent:   anyOf(flags(func(s scannerFacts) truth { return s.overduePresent })...),
	}
}

// vulnScanning builds the vuln-scanning artifact for output.
func (c *Collector) vulnScanning(o *Output) *VulnScanning {
	return toVulnScanning(o, c.gaps)
}

func toVulnScanning(o *Output, gaps *gapLog) *VulnScanning {
	audit := componentsdk.Level(o.CollectedAtLevel).AtLeast(componentsdk.LevelAudit)
	w := writer{gaps: gaps, path: vulnScanningPath, audit: audit}
	out := &VulnScanning{
		SchemaVersion: "1.0.0",
		CollectedAt:   o.CollectedAt,
		Provider:      "aws",
		Scanners:      make([]VulnScanner, 0, len(inspectorCategories)),
	}
	byCategory := make([][]scannerFacts, len(inspectorCategories))
	for i, acct := range o.Accounts {
		var scope VulnScope
		if audit {
			scope = VulnScope{ID: acct.AccountID, Kind: "account", Scanners: make([]VulnScanner, 0, len(inspectorCategories))}
		}
		for j, cat := range inspectorCategories {
			facts := scannerOf(acct, i, cat.resourceType, gaps)
			byCategory[j] = append(byCategory[j], facts)
			if audit {
				scope.Scanners = append(scope.Scanners, writeScanner(w, fmt.Sprintf("/scopes/%d/scanners/%d/", len(out.Scopes), j), cat.category, facts))
			}
		}
		if audit {
			out.Scopes = append(out.Scopes, scope)
		}
	}
	for _, failed := range o.FailedAccounts {
		for j := range inspectorCategories {
			byCategory[j] = append(byCategory[j], failedScanner(failed.err))
		}
	}
	for j, cat := range inspectorCategories {
		out.Scanners = append(out.Scanners, writeScanner(w, fmt.Sprintf("/scanners/%d/", j), cat.category, foldScanners(byCategory[j])))
	}
	return out
}

// writeScanner writes one category's entry at base, a pointer with a
// trailing slash. When the scanned count is above the resources it is taken
// of, the two reads disagree, so the count and the coverage are left out.
func writeScanner(w writer, base, category string, f scannerFacts) VulnScanner {
	w.gaps.rec.Helper()
	s := VulnScanner{Scanner: inspectorScanner, Category: category}
	at := func(field string) string { return base + field }
	if f.scanned.why == nil && f.resources.why == nil && f.scanned.n > f.resources.n {
		f.scanned = count{why: &reason{err: componentsdk.CodeError(componentsdk.CodeInvalidResponse,
			fmt.Errorf("%d %s are scanned in Inspector's coverage, more than the %d listed", f.scanned.n, category, f.resources.n))}}
	}
	s.Enabled = w.truth(f.enabled, at("enabled"))
	s.ResourcesPresent = w.truth(f.resourcesPresent, at("resources_present"))
	s.ResourceCount = w.count(f.resources, at("resource_count"))
	s.ScannedResourceCount = w.count(f.scanned, at("scanned_resource_count"))
	s.CoveragePct = w.pct(f.scanned, f.resources, componentsdk.RoundDown, at("coverage_pct"))
	s.OpenCriticalPresent = w.truth(f.criticalPresent, at("open_critical_present"))
	s.OpenHighPresent = w.truth(f.highPresent, at("open_high_present"))
	s.OverduePresent = w.truth(f.overduePresent, at("overdue_present"))
	s.OpenCriticalCount = w.count(f.critical, at("open_critical_count"))
	s.OpenHighCount = w.count(f.high, at("open_high_count"))
	s.OpenMediumCount = w.count(f.medium, at("open_medium_count"))
	s.OpenLowCount = w.count(f.low, at("open_low_count"))
	s.OverdueCriticalCount = w.count(f.overdueCritical, at("overdue_critical_count"))
	s.OverdueHighCount = w.count(f.overdueHigh, at("overdue_high_count"))
	return s
}
