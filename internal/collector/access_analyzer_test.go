package collector

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

// aggregate runs aggregateAccessAnalyzers over every region in byRegion.
func aggregate(byRegion map[string][]aws.AccessAnalyzer, status *AccessAnalyzerStatus) {
	regions := make([]string, 0, len(byRegion))
	for region := range byRegion {
		regions = append(regions, region)
	}
	sort.Strings(regions)
	aggregateAccessAnalyzers(regions, byRegion, status)
}

func TestAggregateAccessAnalyzers(t *testing.T) {
	t.Run("only an active analyzer covers its region", func(t *testing.T) {
		status := &AccessAnalyzerStatus{}
		aggregate(map[string][]aws.AccessAnalyzer{
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
		listFailed := errors.New("listing findings: AccessDenied")
		aggregate(map[string][]aws.AccessAnalyzer{
			"us-east-1": {{Name: "main", Status: "ACTIVE", FindingsUnresolved: true, FindingsErr: listFailed}},
		}, status)

		if status.AnalyzersWithUnresolvedFindingsCount != 1 {
			t.Errorf("AnalyzersWithUnresolvedFindingsCount = %d, want 1", status.AnalyzersWithUnresolvedFindingsCount)
		}
		if status.ActiveFindingsCount != 0 || status.ArchivedFindingsCount != 0 {
			t.Errorf("findings = %d and %d, want both 0 and the analyzer flagged instead", status.ActiveFindingsCount, status.ArchivedFindingsCount)
		}
		for _, field := range []string{"active_findings_count", "archived_findings_count"} {
			if !hasUnread(status.missing, field, 1) {
				t.Errorf("%s is not marked unread for the one analyzer: %+v", field, status.missing)
			}
		}
		// The region still counts as covered: the analyzer runs even though
		// its findings could not be read.
		if status.RegionsWithActiveAnalyzerCount != 1 {
			t.Errorf("RegionsWithActiveAnalyzerCount = %d, want 1", status.RegionsWithActiveAnalyzerCount)
		}
	})

	t.Run("an organization analyzer is visible as such", func(t *testing.T) {
		status := &AccessAnalyzerStatus{}
		aggregate(map[string][]aws.AccessAnalyzer{
			"us-east-1": {{Name: "org", Type: "ORGANIZATION", Status: "ACTIVE"}},
		}, status)

		if !status.OrganizationAnalyzerPresent {
			t.Error("OrganizationAnalyzerPresent = false, want true")
		}
	})

	t.Run("no analyzers anywhere is disabled, not an error", func(t *testing.T) {
		status := &AccessAnalyzerStatus{}
		aggregate(map[string][]aws.AccessAnalyzer{"us-east-1": {}}, status)

		if status.Enabled {
			t.Error("Enabled = true, want false")
		}
		if status.AnalyzerCount != 0 {
			t.Errorf("AnalyzerCount = %d, want 0", status.AnalyzerCount)
		}
	})
}

// ListFindings supports only external access analyzers, so an unused access
// analyzer's findings are listed with ListFindingsV2.
func TestAccessAnalyzer_UnusedAccessFindingsAreCounted(t *testing.T) {
	const (
		analyzerURL = "https://access-analyzer.us-east-1.amazonaws.com/"
		arn         = "arn:aws:access-analyzer:us-east-1:111122223333:analyzer/unused"
		path        = "/accounts/0/account_security/access_analyzer"
	)
	findings := func(status ...string) string {
		list := []any{}
		for i, s := range status {
			id := "f-" + strconv.Itoa(i)
			list = append(list, map[string]any{
				"id": id, "resourceType": "AWS::IAM::Role", "resource": "arn:aws:iam::111122223333:role/" + id,
				"status": s, "resourceOwnerAccount": kitAccountID, "analyzedAt": "2025-12-30T00:00:00Z", "createdAt": "2025-12-30T00:00:00Z",
				"updatedAt": "2025-12-30T00:00:00Z", "condition": map[string]any{}, "findingType": "UnusedIAMRole",
			})
		}
		return kitJSON(map[string]any{"findings": list})
	}
	for _, tc := range []struct {
		name, analyzerType string
		v1, v2             collectortest.Response
	}{
		{"unused access analyzer", "ACCOUNT_UNUSED_ACCESS",
			restResponse("aws.accessanalyzer.ListFindings", http.MethodPost, analyzerURL+"finding", http.StatusBadRequest, `{"message":"ListFindings is not supported for this analyzer type","reason":"other"}`),
			restResponse("aws.accessanalyzer.ListFindingsV2", http.MethodPost, analyzerURL+"findingv2", 0, findings("ACTIVE", "ACTIVE", "ARCHIVED"))},
		{"external access analyzer", "ACCOUNT",
			restResponse("aws.accessanalyzer.ListFindings", http.MethodPost, analyzerURL+"finding", 0, findings("ACTIVE", "ACTIVE", "ARCHIVED")),
			restResponse("aws.accessanalyzer.ListFindingsV2", http.MethodPost, analyzerURL+"findingv2", http.StatusBadRequest, `{"message":"not expected","reason":"other"}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			analyzers := restResponse("aws.accessanalyzer.ListAnalyzers", http.MethodGet, analyzerURL+"analyzer", 0, kitJSON(map[string]any{"analyzers": []any{
				map[string]any{"arn": arn, "name": "unused", "type": tc.analyzerType, "status": "ACTIVE", "createdAt": "2024-01-01T00:00:00Z"},
			}}))
			request := map[string]any{"analyzerArn": arn}
			responses := append(replaceResponses(kitResponses(), analyzers), withRequestBody(tc.v1, request), withRequestBody(tc.v2, request))
			doc := runDetailed(t, responses)
			expectValues(t, doc, map[string]any{
				path + "/analyzers/0/findings_unresolved":          nil,
				path + "/analyzers_with_unresolved_findings_count": nil,
				path + "/active_findings_count":                    2,
				path + "/archived_findings_count":                  1,
			})
		})
	}
}

const (
	eastAnalyzerURL = "https://access-analyzer.us-east-1.amazonaws.com/"
	westAnalyzerURL = "https://access-analyzer.us-west-2.amazonaws.com/"
	eastAnalyzerARN = "arn:aws:access-analyzer:us-east-1:111122223333:analyzer/northwind"
	westAnalyzerARN = "arn:aws:access-analyzer:us-west-2:111122223333:analyzer/northwind-west"
	vendorRoleARN   = "arn:aws:iam::111122223333:role/datadog-integration"
)

// analyzerFinding is one external access finding as ListFindings returns it.
func analyzerFinding(id, resourceType, resource, status string) map[string]any {
	return map[string]any{
		"id": id, "resourceType": resourceType, "resource": resource, "status": status,
		"resourceOwnerAccount": kitAccountID, "analyzedAt": "2025-12-30T00:00:00Z", "createdAt": "2025-12-30T00:00:00Z",
		"updatedAt": "2025-12-30T00:00:00Z", "condition": map[string]any{},
		"principal": map[string]any{"AWS": "999988887777"}, "isPublic": false,
	}
}

// analyzersInEastAndWest scans us-east-1 and us-west-2, each with one ACTIVE
// external access analyzer whose findings are east and west.
func analyzersInEastAndWest(east, west []any) []collectortest.Response {
	responses := append(replaceResponses(kitResponses(), eastAndWest()), emptyRegionResponses("us-west-2")...)
	return append(replaceResponses(responses,
		withRequestBody(restResponse("aws.accessanalyzer.ListFindings", http.MethodPost, eastAnalyzerURL+"finding", 0, kitJSON(map[string]any{"findings": east})), map[string]any{"analyzerArn": eastAnalyzerARN}),
		restResponse("aws.accessanalyzer.ListAnalyzers", http.MethodGet, westAnalyzerURL+"analyzer", 0, kitJSON(map[string]any{"analyzers": []any{
			map[string]any{"arn": westAnalyzerARN, "name": "northwind-west", "type": "ACCOUNT", "status": "ACTIVE", "createdAt": "2024-01-01T00:00:00Z"},
		}})),
	),
		withRequestBody(restResponse("aws.accessanalyzer.ListFindings", http.MethodPost, westAnalyzerURL+"finding", 0, kitJSON(map[string]any{"findings": west})), map[string]any{"analyzerArn": westAnalyzerARN}),
	)
}

// An IAM role is global, so each region's analyzer reports a finding for a
// role trusted from outside the account. The account totals count it once.
// Each analyzer row keeps its own count.
func TestAccessAnalyzer_RoleFindingCountsOnceAcrossRegions(t *testing.T) {
	const path = "/accounts/0/account_security/access_analyzer"
	for _, status := range []string{"ACTIVE", "ARCHIVED"} {
		t.Run(status, func(t *testing.T) {
			doc := runDetailed(t, analyzersInEastAndWest(
				[]any{analyzerFinding("east-role", "AWS::IAM::Role", vendorRoleARN, status)},
				[]any{analyzerFinding("west-role", "AWS::IAM::Role", vendorRoleARN, status)},
			))
			active, archived := 1, 0
			if status == "ARCHIVED" {
				active, archived = 0, 1
			}
			expectValues(t, doc, map[string]any{
				path + "/active_findings_count":               active,
				path + "/archived_findings_count":             archived,
				path + "/analyzers/0/active_findings_count":   active,
				path + "/analyzers/1/active_findings_count":   active,
				path + "/analyzers/0/archived_findings_count": archived,
				path + "/analyzers/1/archived_findings_count": archived,
			})
		})
	}
}

// A regional resource is analyzed only in its own region, so a bucket in
// each region is two findings.
func TestAccessAnalyzer_RegionalFindingsSumAcrossRegions(t *testing.T) {
	const path = "/accounts/0/account_security/access_analyzer"
	t.Run("a bucket in each region", func(t *testing.T) {
		doc := runDetailed(t, analyzersInEastAndWest(
			[]any{analyzerFinding("east-bucket", "AWS::S3::Bucket", "arn:aws:s3:::northwind-east", "ACTIVE")},
			[]any{analyzerFinding("west-bucket", "AWS::S3::Bucket", "arn:aws:s3:::northwind-west", "ACTIVE")},
		))
		expectValues(t, doc, map[string]any{path + "/active_findings_count": 2})
	})
	t.Run("a role finding in one region only", func(t *testing.T) {
		doc := runDetailed(t, analyzersInEastAndWest(
			[]any{analyzerFinding("east-role", "AWS::IAM::Role", vendorRoleARN, "ACTIVE")},
			[]any{},
		))
		expectValues(t, doc, map[string]any{path + "/active_findings_count": 1})
	})
	t.Run("roles trusting different accounts", func(t *testing.T) {
		other := analyzerFinding("west-role", "AWS::IAM::Role", vendorRoleARN, "ACTIVE")
		other["principal"] = map[string]any{"AWS": "444455556666"}
		doc := runDetailed(t, analyzersInEastAndWest(
			[]any{analyzerFinding("east-role", "AWS::IAM::Role", vendorRoleARN, "ACTIVE")},
			[]any{other},
		))
		expectValues(t, doc, map[string]any{path + "/active_findings_count": 2})
	})
}

const (
	eastUnusedAnalyzerARN = "arn:aws:access-analyzer:us-east-1:111122223333:analyzer/unused-east"
	westUnusedAnalyzerARN = "arn:aws:access-analyzer:us-west-2:111122223333:analyzer/unused-west"
)

// unusedRoleFinding is one unused access finding as ListFindingsV2 returns
// it.
func unusedRoleFinding(id, role, status string) map[string]any {
	return map[string]any{
		"id": id, "resourceType": "AWS::IAM::Role", "resource": "arn:aws:iam::111122223333:role/" + role,
		"status": status, "resourceOwnerAccount": kitAccountID, "analyzedAt": "2025-12-30T00:00:00Z", "createdAt": "2025-12-30T00:00:00Z",
		"updatedAt": "2025-12-30T00:00:00Z", "findingType": "UnusedIAMRole",
	}
}

// unusedAnalyzersInEastAndWest scans us-east-1 and us-west-2, each with one
// ACTIVE unused access analyzer whose findings are east and west.
func unusedAnalyzersInEastAndWest(east, west []any) []collectortest.Response {
	analyzer := func(arn, name string) string {
		return kitJSON(map[string]any{"analyzers": []any{
			map[string]any{"arn": arn, "name": name, "type": "ACCOUNT_UNUSED_ACCESS", "status": "ACTIVE", "createdAt": "2024-01-01T00:00:00Z"},
		}})
	}
	responses := append(replaceResponses(kitResponses(), eastAndWest()), emptyRegionResponses("us-west-2")...)
	responses = replaceResponses(responses,
		restResponse("aws.accessanalyzer.ListAnalyzers", http.MethodGet, eastAnalyzerURL+"analyzer", 0, analyzer(eastUnusedAnalyzerARN, "unused-east")),
		restResponse("aws.accessanalyzer.ListAnalyzers", http.MethodGet, westAnalyzerURL+"analyzer", 0, analyzer(westUnusedAnalyzerARN, "unused-west")),
	)
	return append(responses,
		withRequestBody(restResponse("aws.accessanalyzer.ListFindingsV2", http.MethodPost, eastAnalyzerURL+"findingv2", 0, kitJSON(map[string]any{"findings": east})), map[string]any{"analyzerArn": eastUnusedAnalyzerARN}),
		withRequestBody(restResponse("aws.accessanalyzer.ListFindingsV2", http.MethodPost, westAnalyzerURL+"findingv2", 0, kitJSON(map[string]any{"findings": west})), map[string]any{"analyzerArn": westUnusedAnalyzerARN}),
	)
}

// Unused access findings do not change by region, so unused access analyzers
// in two regions report the same findings. The account totals count each
// once. Each analyzer row keeps its own count.
func TestAccessAnalyzer_UnusedAccessFindingCountsOnceAcrossRegions(t *testing.T) {
	const path = "/accounts/0/account_security/access_analyzer"
	findings := func(prefix string) []any {
		return []any{
			unusedRoleFinding(prefix+"-1", "batch-runner", "ACTIVE"),
			unusedRoleFinding(prefix+"-2", "old-deployer", "ACTIVE"),
			unusedRoleFinding(prefix+"-3", "retired-etl", "ARCHIVED"),
		}
	}
	t.Run("the same findings in both regions", func(t *testing.T) {
		doc := runDetailed(t, unusedAnalyzersInEastAndWest(findings("east"), findings("west")))
		expectValues(t, doc, map[string]any{
			path + "/analyzer_count":                    2,
			path + "/active_findings_count":             2,
			path + "/archived_findings_count":           1,
			path + "/analyzers/0/active_findings_count": 2,
			path + "/analyzers/1/active_findings_count": 2,
		})
	})
	t.Run("different roles in each region", func(t *testing.T) {
		doc := runDetailed(t, unusedAnalyzersInEastAndWest(
			[]any{unusedRoleFinding("east-1", "batch-runner", "ACTIVE")},
			[]any{unusedRoleFinding("west-1", "old-deployer", "ACTIVE")},
		))
		expectValues(t, doc, map[string]any{path + "/active_findings_count": 2})
	})
}
