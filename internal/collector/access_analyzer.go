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
	var firstErr error
	for i, region := range regions {
		if scans[i].err != nil {
			status.RegionsUnresolvedCount++
			c.warn("account %s region %s: failed to list access analyzers; coverage there is unproven: %v", accountID, region, scans[i].err)
			if firstErr == nil {
				firstErr = scans[i].err
			}
			continue
		}
		status.RegionsEvaluatedCount++
		byRegion[region] = scans[i].analyzers
	}

	aggregateAccessAnalyzers(regions, byRegion, status)
	if unresolved := status.RegionsUnresolvedCount; unresolved > 0 {
		status.missing.addPartial(firstErr, unresolved, "analyzer_count", "regions_with_active_analyzer_count", "inactive_analyzer_count",
			"active_findings_count", "archived_findings_count")
		if !status.Enabled {
			status.missing.addPartial(firstErr, unresolved, "enabled")
		}
		if !status.OrganizationAnalyzerPresent {
			status.missing.addPartial(firstErr, unresolved, "organization_analyzer_present")
		}
		if level.AtLeast(componentsdk.LevelAudit) {
			status.missing.add(firstErr, "analyzers")
		}
	}

	for _, analyzer := range status.analyzersUnresolved(regions, byRegion) {
		c.warn("account %s: failed to list findings for access analyzer %s; its findings are unknown, not zero", accountID, analyzer)
	}

	if level.AtLeast(componentsdk.LevelAudit) {
		status.Analyzers = []AccessAnalyzerRow{}
		for _, region := range regions {
			for _, a := range byRegion[region] {
				row := AccessAnalyzerRow{
					Name:                  a.Name,
					Region:                region,
					Type:                  a.Type,
					Status:                a.Status,
					ActiveFindingsCount:   a.ActiveFindingsCount,
					ArchivedFindingsCount: a.ArchivedFindingsCount,
					FindingsUnresolved:    a.FindingsUnresolved,
				}
				row.missing.add(a.FindingsErr, "active_findings_count", "archived_findings_count")
				status.Analyzers = append(status.Analyzers, row)
			}
		}
	}
}

// aggregateAccessAnalyzers reduces per-region analyzers to coverage findings.
// An IAM role is global, so the same role finding appears in every enabled
// region. The account totals count it once for each analyzer type. Unused
// access findings do not change by region, so the totals count each of them
// once for each analyzer type too.
func aggregateAccessAnalyzers(regions []string, byRegion map[string][]aws.AccessAnalyzer, status *AccessAnalyzerStatus) {
	roleFindings := map[string]bool{}
	unusedFindings := map[string]int{}
	for _, region := range regions {
		analyzers := byRegion[region]
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
				status.missing.addPartial(a.FindingsErr, 1, "active_findings_count", "archived_findings_count")
				continue
			}
			status.ActiveFindingsCount += a.ActiveFindingsCount
			status.ArchivedFindingsCount += a.ArchivedFindingsCount
			for key, findingStatus := range a.RoleFindings {
				if !roleFindings[a.Type+"|"+key] {
					roleFindings[a.Type+"|"+key] = true
					continue
				}
				status.uncountFindings(findingStatus, 1)
			}
			for key, tally := range a.UnusedFindings {
				seen := unusedFindings[a.Type+"|"+key]
				status.uncountFindings(tally.Status, min(seen, tally.Count))
				unusedFindings[a.Type+"|"+key] = max(seen, tally.Count)
			}
		}
		if regionActive {
			status.RegionsWithActiveAnalyzerCount++
		}
	}
	status.Enabled = status.RegionsWithActiveAnalyzerCount > 0
}

// uncountFindings takes n findings of findingStatus back out of the totals.
func (s *AccessAnalyzerStatus) uncountFindings(findingStatus string, n int) {
	switch findingStatus {
	case "ACTIVE":
		s.ActiveFindingsCount -= n
	case "ARCHIVED":
		s.ArchivedFindingsCount -= n
	}
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
