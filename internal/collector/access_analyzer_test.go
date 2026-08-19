package collector

import (
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

func TestAggregateAccessAnalyzers(t *testing.T) {
	t.Run("only an active analyzer covers its region", func(t *testing.T) {
		status := &AccessAnalyzerStatus{}
		aggregateAccessAnalyzers(map[string][]aws.AccessAnalyzer{
			"us-east-1":  {{Name: "main", Status: "ACTIVE", ActiveFindingsCount: 3, ArchivedFindingsCount: 12}},
			"eu-west-1":  {{Name: "stale", Status: "FAILED"}},
			"ap-south-1": {},
		}, status)

		if status.RegionsWithActiveAnalyzerCount != 1 {
			t.Errorf("RegionsWithActiveAnalyzerCount = %d, want 1: a failed analyzer covers nothing", status.RegionsWithActiveAnalyzerCount)
		}
		if status.InactiveAnalyzerCount != 1 {
			t.Errorf("InactiveAnalyzerCount = %d, want 1", status.InactiveAnalyzerCount)
		}
		if !status.Enabled {
			t.Error("Enabled = false, want true with one active analyzer")
		}
		if status.ActiveFindingsCount != 3 || status.ArchivedFindingsCount != 12 {
			t.Errorf("findings = %d and %d, want 3 and 12", status.ActiveFindingsCount, status.ArchivedFindingsCount)
		}
	})

	// The repaired client marks a failed findings listing instead of
	// reporting zero; the aggregate must keep that distinction.
	t.Run("unresolved findings are excluded, never counted as zero", func(t *testing.T) {
		status := &AccessAnalyzerStatus{}
		aggregateAccessAnalyzers(map[string][]aws.AccessAnalyzer{
			"us-east-1": {{Name: "main", Status: "ACTIVE", FindingsUnresolved: true}},
		}, status)

		if status.AnalyzersWithUnresolvedFindingsCount != 1 {
			t.Errorf("AnalyzersWithUnresolvedFindingsCount = %d, want 1", status.AnalyzersWithUnresolvedFindingsCount)
		}
		if status.ActiveFindingsCount != 0 || status.ArchivedFindingsCount != 0 {
			t.Errorf("findings = %d and %d, want both 0 and the analyzer flagged instead", status.ActiveFindingsCount, status.ArchivedFindingsCount)
		}
		// The region still counts as covered: the analyzer runs even though
		// its findings could not be read.
		if status.RegionsWithActiveAnalyzerCount != 1 {
			t.Errorf("RegionsWithActiveAnalyzerCount = %d, want 1", status.RegionsWithActiveAnalyzerCount)
		}
	})

	t.Run("an organization analyzer is visible as such", func(t *testing.T) {
		status := &AccessAnalyzerStatus{}
		aggregateAccessAnalyzers(map[string][]aws.AccessAnalyzer{
			"us-east-1": {{Name: "org", Type: "ORGANIZATION", Status: "ACTIVE"}},
		}, status)

		if !status.OrganizationAnalyzerPresent {
			t.Error("OrganizationAnalyzerPresent = false, want true")
		}
	})

	t.Run("no analyzers anywhere is disabled, not an error", func(t *testing.T) {
		status := &AccessAnalyzerStatus{}
		aggregateAccessAnalyzers(map[string][]aws.AccessAnalyzer{"us-east-1": {}}, status)

		if status.Enabled {
			t.Error("Enabled = true, want false")
		}
		if status.AnalyzerCount != 0 {
			t.Errorf("AnalyzerCount = %d, want 0", status.AnalyzerCount)
		}
	})
}
