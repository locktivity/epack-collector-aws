package collector

import (
	"fmt"
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

func albHead(arn, scheme string) aws.LoadBalancerHead {
	return aws.LoadBalancerHead{Arn: arn, Type: "application", Scheme: scheme}
}

func rateRule(action string, limit int64) aws.WebACLRule {
	return aws.WebACLRule{Name: "rate-limit", Priority: 1, Action: action, IsRateBased: true, RateLimit: limit, AggregateKeyType: "IP"}
}

func regionalACL(name string, associated []string, rules ...aws.WebACLRule) aws.WebACL {
	return aws.WebACL{
		Name: name, Arn: "arn:aws:wafv2:us-east-1:1:regional/webacl/" + name,
		Scope: aws.WAFScopeRegional, Region: "us-east-1", DefaultAction: "allow",
		AssociatedALBArns: associated, Rules: rules, LoggingEvaluated: true,
	}
}

func cloudFrontACL(name string, rules ...aws.WebACLRule) aws.WebACL {
	return aws.WebACL{
		Name: name, Arn: "arn:aws:wafv2:us-east-1:1:global/webacl/" + name,
		Scope: aws.WAFScopeCloudFront, DefaultAction: "allow",
		Rules: rules, LoggingEvaluated: true,
	}
}

func TestAssembleWAFMetricsCoverageJoins(t *testing.T) {
	scan := wafScanWithCounts{
		wafRegionScan: wafRegionScan{
			acls: []aws.WebACL{regionalACL("edge", []string{"arn:alb/protected"}, rateRule("block", 500))},
			lbHeads: []aws.LoadBalancerHead{
				albHead("arn:alb/protected", "internet-facing"),
				albHead("arn:alb/naked", "internet-facing"),
				albHead("arn:alb/internal", "internal"),
				{Arn: "arn:nlb/edge", Type: "network", Scheme: "internet-facing"},
			},
		},
		RegionsEvaluatedCount: 2,
	}
	distributions := []aws.CloudFrontDistribution{
		{ID: "D1", Enabled: true, WebACLArn: "arn:aws:wafv2:us-east-1:1:global/webacl/cdn"},
		{ID: "D2", Enabled: true},
		{ID: "D3", Enabled: false, WebACLArn: "arn:aws:wafv2:us-east-1:1:global/webacl/cdn"},
	}

	out := assembleWAFMetrics(scan, cloudFrontScan{acls: []aws.WebACL{cloudFrontACL("cdn")}, distributions: distributions, evaluated: true}, componentsdk.LevelTrust)

	if out.InternetFacingALBCount != 2 {
		t.Errorf("internet-facing ALB count = %d, want 2 (internal ALBs and NLBs excluded)", out.InternetFacingALBCount)
	}
	if out.InternetFacingALBCoveragePct != 50 {
		t.Errorf("ALB coverage = %d%%, want 50%% (one of two internet-facing ALBs protected)", out.InternetFacingALBCoveragePct)
	}
	if out.EnabledDistributionCount != 2 || out.DistributionCoveragePct != 50 {
		t.Errorf("distribution coverage = %d%% of %d, want 50%% of 2", out.DistributionCoveragePct, out.EnabledDistributionCount)
	}
	if out.WebACLCount != 2 || out.RegionsEvaluatedCount != 2 || !out.CloudFrontScopeEvaluated {
		t.Errorf("acl count %d regions %d cfEvaluated %v, want 2, 2, true", out.WebACLCount, out.RegionsEvaluatedCount, out.CloudFrontScopeEvaluated)
	}
	if out.WebACLs != nil {
		t.Errorf("trust level must not emit web ACL rows, got %d", len(out.WebACLs))
	}
}

func TestAssembleWAFMetricsRateLimitingEnforced(t *testing.T) {
	protected := []string{"arn:alb/a"}
	cases := []struct {
		name string
		acls []aws.WebACL
		want bool
	}{
		{"block rule on associated acl", []aws.WebACL{regionalACL("a", protected, rateRule("block", 500))}, true},
		{"count rule on associated acl", []aws.WebACL{regionalACL("a", protected, rateRule("count", 500))}, false},
		{"block rule on unassociated acl", []aws.WebACL{regionalACL("a", nil, rateRule("block", 500))}, false},
		{"no rate rules", []aws.WebACL{regionalACL("a", protected)}, false},
	}
	for _, tc := range cases {
		scan := wafScanWithCounts{wafRegionScan: wafRegionScan{acls: tc.acls, lbHeads: []aws.LoadBalancerHead{albHead("arn:alb/a", "internet-facing")}}}
		out := assembleWAFMetrics(scan, cloudFrontScan{evaluated: true}, componentsdk.LevelTrust)
		if out.RateLimitingEnforced != tc.want {
			t.Errorf("%s: rate_limiting_enforced = %v, want %v", tc.name, out.RateLimitingEnforced, tc.want)
		}
	}
}

func TestAssembleWAFMetricsCloudFrontAssociationJoin(t *testing.T) {
	cdn := cloudFrontACL("cdn", rateRule("block", 2000))
	distributions := []aws.CloudFrontDistribution{
		{ID: "D1", Enabled: true, WebACLArn: cdn.Arn},
		{ID: "D2", Enabled: true, WebACLArn: cdn.Arn},
	}

	out := assembleWAFMetrics(wafScanWithCounts{}, cloudFrontScan{acls: []aws.WebACL{cdn}, distributions: distributions, evaluated: true}, componentsdk.LevelAudit)

	if !out.RateLimitingEnforced {
		t.Error("a blocking rate rule on a distribution-referenced CLOUDFRONT acl must count as enforced")
	}
	if len(out.WebACLs) != 1 || out.WebACLs[0].AssociatedResourceCount != 2 {
		t.Fatalf("cloudfront acl row associated_resource_count = %+v, want 2", out.WebACLs)
	}
}

func TestAssembleWAFMetricsLevelGating(t *testing.T) {
	acl := regionalACL("edge", []string{"arn:alb/a"}, rateRule("block", 500))
	acl.LoggingEnabled = true
	acl.LoggingDestinationArn = "arn:logs/dest"
	scan := wafScanWithCounts{wafRegionScan: wafRegionScan{acls: []aws.WebACL{acl}}}

	audit := assembleWAFMetrics(scan, cloudFrontScan{evaluated: true}, componentsdk.LevelAudit)
	row := audit.WebACLs[0]
	if row.Arn != "" || row.AssociatedResourceArns != nil || row.LoggingDestinationArn != "" {
		t.Errorf("audit row leaked internal fields: %+v", row)
	}
	if !row.LoggingEvaluated || !row.LoggingEnabled || len(row.Rules) != 1 || row.Rules[0].RateLimit != 500 {
		t.Errorf("audit row missing expected fields: %+v", row)
	}

	internal := assembleWAFMetrics(scan, cloudFrontScan{evaluated: true}, componentsdk.LevelInternal)
	irow := internal.WebACLs[0]
	if irow.Arn == "" || len(irow.AssociatedResourceArns) != 1 || irow.LoggingDestinationArn != "arn:logs/dest" {
		t.Errorf("internal row missing identifying fields: %+v", irow)
	}
}

func TestAssembleWAFMetricsSortAndTruncation(t *testing.T) {
	var acls []aws.WebACL
	acls = append(acls, regionalACL("zz-protecting", []string{"arn:alb/a"}))
	for i := 0; i < maxWebACLRows+1; i++ {
		acls = append(acls, regionalACL(fmt.Sprintf("idle-%04d", i), nil))
	}
	scan := wafScanWithCounts{wafRegionScan: wafRegionScan{acls: acls, lbHeads: []aws.LoadBalancerHead{albHead("arn:alb/a", "internet-facing")}}}

	out := assembleWAFMetrics(scan, cloudFrontScan{evaluated: true}, componentsdk.LevelAudit)

	if !out.WebACLsTruncated || out.WebACLsDroppedCount != 2 {
		t.Errorf("truncated=%v dropped=%d, want true, 2", out.WebACLsTruncated, out.WebACLsDroppedCount)
	}
	if len(out.WebACLs) != maxWebACLRows {
		t.Fatalf("rows = %d, want %d", len(out.WebACLs), maxWebACLRows)
	}
	if out.WebACLs[0].Name != "zz-protecting" {
		t.Errorf("first row = %s, want the protecting acl to survive truncation first", out.WebACLs[0].Name)
	}
}

func TestAssembleWAFMetricsUnevaluatedCloudFrontScope(t *testing.T) {
	out := assembleWAFMetrics(wafScanWithCounts{}, cloudFrontScan{}, componentsdk.LevelTrust)

	if out.CloudFrontScopeEvaluated {
		t.Error("cloudfront_scope_evaluated must be false when the scope was not readable")
	}
	if out.EnabledDistributionCount != 0 || out.DistributionCoveragePct != 0 {
		t.Errorf("unevaluated scope must report zero distribution metrics, got %+v", out)
	}
}

func TestMergeWAFScans(t *testing.T) {
	a := wafRegionScan{acls: []aws.WebACL{regionalACL("a", nil)}, lbHeads: []aws.LoadBalancerHead{albHead("arn:1", "internal")}}
	b := wafRegionScan{acls: []aws.WebACL{regionalACL("b", nil)}, lbHeads: []aws.LoadBalancerHead{albHead("arn:2", "internet-facing")}}

	merged := mergeWAFScans(a, b)

	if len(merged.acls) != 2 || len(merged.lbHeads) != 2 {
		t.Errorf("merged = %d acls %d heads, want 2 and 2", len(merged.acls), len(merged.lbHeads))
	}
}
