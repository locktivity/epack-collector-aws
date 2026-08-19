package collector

import (
	"context"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// collectAccessAnalyzerStatus collects IAM Access Analyzer coverage across
// regions.
//
// Enablement is per region: an analyzer in one region analyzes nothing in
// another, and only an ACTIVE analyzer analyzes anything at all. In an
// organization the analyzer often lives in a delegated administrator account,
// so no analyzer here does not mean no coverage: enrolling that account is
// what makes it visible.
func (c *Collector) collectAccessAnalyzerStatus(ctx context.Context, client *aws.AWSClient, regions []string, accountID string, status *AccessAnalyzerStatus, level componentsdk.Level) {
	type regionAnalyzers struct {
		analyzers []aws.AccessAnalyzer
		err       error
	}
	scans := mapConcurrent(regions, regionConcurrency, func(region string) regionAnalyzers {
		analyzers, err := client.ListAccessAnalyzers(ctx, region)
		return regionAnalyzers{analyzers: analyzers, err: err}
	})

	byRegion := map[string][]aws.AccessAnalyzer{}
	for i, region := range regions {
		if scans[i].err != nil {
			status.RegionsUnresolvedCount++
			c.warn("account %s region %s: failed to list access analyzers; coverage there is unproven: %v", accountID, region, scans[i].err)
			continue
		}
		status.RegionsEvaluatedCount++
		byRegion[region] = scans[i].analyzers
	}

	aggregateAccessAnalyzers(byRegion, status)

	for _, analyzer := range status.analyzersUnresolved(regions, byRegion) {
		c.warn("account %s: failed to list findings for access analyzer %s; its findings are unknown, not zero", accountID, analyzer)
	}

	if level.AtLeast(componentsdk.LevelAudit) {
		for _, region := range regions {
			for _, a := range byRegion[region] {
				status.Analyzers = append(status.Analyzers, AccessAnalyzerRow{
					Name:                  a.Name,
					Region:                region,
					Type:                  a.Type,
					Status:                a.Status,
					ActiveFindingsCount:   a.ActiveFindingsCount,
					ArchivedFindingsCount: a.ArchivedFindingsCount,
					FindingsUnresolved:    a.FindingsUnresolved,
				})
			}
		}
	}
}

// aggregateAccessAnalyzers reduces per-region analyzers to coverage findings.
func aggregateAccessAnalyzers(byRegion map[string][]aws.AccessAnalyzer, status *AccessAnalyzerStatus) {
	for _, analyzers := range byRegion {
		regionActive := false
		for _, a := range analyzers {
			status.AnalyzerCount++
			if a.Type == "ORGANIZATION" {
				status.OrganizationAnalyzerPresent = true
			}
			if a.Status != "ACTIVE" {
				status.InactiveAnalyzerCount++
				continue
			}
			regionActive = true
			if a.FindingsUnresolved {
				status.AnalyzersWithUnresolvedFindingsCount++
				continue
			}
			status.ActiveFindingsCount += a.ActiveFindingsCount
			status.ArchivedFindingsCount += a.ArchivedFindingsCount
		}
		if regionActive {
			status.RegionsWithActiveAnalyzerCount++
		}
	}
	status.Enabled = status.RegionsWithActiveAnalyzerCount > 0
}

func (s *AccessAnalyzerStatus) analyzersUnresolved(regions []string, byRegion map[string][]aws.AccessAnalyzer) []string {
	var names []string
	for _, region := range regions {
		for _, a := range byRegion[region] {
			if a.Status == "ACTIVE" && a.FindingsUnresolved {
				names = append(names, a.Name)
			}
		}
	}
	return names
}
