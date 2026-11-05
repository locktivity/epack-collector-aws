package collector

import (
	"context"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

// inspectorReader is the slice of the AWS client collectInspectorScan uses,
// extracted so the failure paths can be tested without AWS.
type inspectorReader interface {
	GetInspectorAccountStatus(ctx context.Context, region, accountID string) (aws.InspectorAccountStatus, error)
	CountInspectorCoverage(ctx context.Context, region, accountID string, activeOnly bool) (map[string]int, error)
	ListInspectorFindings(ctx context.Context, region, accountID string, visit func(aws.InspectorFinding)) error
}

// Days a finding may stay open before it is overdue, by severity, as the
// vuln-scanning schema defines it.
const (
	overdueCriticalDays = 30
	overdueHighDays     = 90
)

// inspectorScan is Amazon Inspector's evidence for one account in each
// scanned region. err is why no region was read, such as a failed region
// list.
type inspectorScan struct {
	err     error
	regions []inspectorRegion
}

// inspectorRegion is Inspector's evidence in one region. Each error is why
// a read failed. The coverage and findings are read only where Inspector is
// on, and the ECR images only where ECR scanning is on.
type inspectorRegion struct {
	region    string
	status    aws.InspectorAccountStatus
	statusErr error

	// active counts the resources whose scan status is ACTIVE, by resource
	// type.
	active    map[string]int
	activeErr error

	// ecrImages counts the ECR images in Inspector's coverage.
	ecrImages    int
	ecrImagesErr error

	// findings counts the open findings by resource type.
	findings    map[string]*findingCounts
	findingsErr error
}

// findingCounts counts one resource type's open findings by severity, and
// the critical and high ones open long enough to be overdue.
type findingCounts struct {
	critical, high, medium, low  int
	overdueCritical, overdueHigh int
}

// collectInspectorScan reads Inspector's status in each region, and where
// Inspector is on, its coverage and open findings. A read that fails leaves
// out the values it feeds and never fails the run.
func (c *Collector) collectInspectorScan(ctx context.Context, client inspectorReader, regions []string, accountID string) inspectorScan {
	now := c.now()
	criticalBefore := now.AddDate(0, 0, -overdueCriticalDays)
	highBefore := now.AddDate(0, 0, -overdueHighDays)
	scan := inspectorScan{regions: make([]inspectorRegion, 0, len(regions))}
	for _, region := range regions {
		r := inspectorRegion{region: region}
		r.status, r.statusErr = client.GetInspectorAccountStatus(ctx, region, accountID)
		if r.statusErr != nil {
			c.warn("account %s region %s: failed to read the Inspector status: %v", accountID, region, r.statusErr)
		}
		if r.statusErr == nil && r.status.Enabled {
			c.readInspectorRegion(ctx, client, accountID, &r, criticalBefore, highBefore)
		}
		scan.regions = append(scan.regions, r)
	}
	return scan
}

// readInspectorRegion reads the coverage and open findings in a region where
// Inspector is on. A finding is overdue when it is critical and was first
// observed before criticalBefore, or high and first observed before
// highBefore.
func (c *Collector) readInspectorRegion(ctx context.Context, client inspectorReader, accountID string, r *inspectorRegion, criticalBefore, highBefore time.Time) {
	r.active, r.activeErr = client.CountInspectorCoverage(ctx, r.region, accountID, true)
	if r.activeErr != nil {
		c.warn("account %s region %s: failed to read Inspector coverage: %v", accountID, r.region, r.activeErr)
	}
	if r.status.ScanEnabled[aws.InspectorECRImage] {
		all, err := client.CountInspectorCoverage(ctx, r.region, accountID, false)
		r.ecrImages, r.ecrImagesErr = all[aws.InspectorECRImage], err
		if err != nil {
			c.warn("account %s region %s: failed to count the ECR images Inspector covers: %v", accountID, r.region, err)
		}
	}
	findings := map[string]*findingCounts{}
	r.findingsErr = client.ListInspectorFindings(ctx, r.region, accountID, func(f aws.InspectorFinding) {
		counts := findings[f.ResourceType]
		if counts == nil {
			counts = &findingCounts{}
			findings[f.ResourceType] = counts
		}
		switch f.Severity {
		case "CRITICAL":
			counts.critical++
			if f.FirstObservedAt.Before(criticalBefore) {
				counts.overdueCritical++
			}
		case "HIGH":
			counts.high++
			if f.FirstObservedAt.Before(highBefore) {
				counts.overdueHigh++
			}
		case "MEDIUM":
			counts.medium++
		case "LOW":
			counts.low++
		}
	})
	if r.findingsErr != nil {
		c.warn("account %s region %s: failed to list Inspector findings: %v", accountID, r.region, r.findingsErr)
		return
	}
	r.findings = findings
}
