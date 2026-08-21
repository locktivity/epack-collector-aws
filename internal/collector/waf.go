package collector

import (
	"context"
	"sort"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// maxWebACLRows caps the audit-level web ACL inventory. ACL fleets are tiny
// in practice; the cap is a safety bound, sorted so protecting ACLs survive.
const maxWebACLRows = 1000

// wafRegionScan holds one region's raw WAF inputs: the REGIONAL-scope web
// ACLs and the load balancer identities the coverage join needs.
type wafRegionScan struct {
	acls    []aws.WebACL
	lbHeads []aws.LoadBalancerHead
}

// wafScanWithCounts carries the merged regional scans and how many regions
// answered.
type wafScanWithCounts struct {
	wafRegionScan
	RegionsEvaluatedCount int
}

// collectWAFRegion gathers the REGIONAL-scope raw inputs for one region. The
// load balancers are re-listed as identity rows here rather than shared from
// the load balancer surface, keeping the surfaces independent.
func (c *Collector) collectWAFRegion(ctx context.Context, client *aws.AWSClient, region string) (*wafRegionScan, error) {
	acls, err := client.ListWebACLs(ctx, aws.WAFScopeRegional, region)
	if err != nil {
		return nil, err
	}
	heads, err := client.ListLoadBalancerHeads(ctx, region)
	if err != nil {
		return nil, err
	}
	return &wafRegionScan{acls: acls, lbHeads: heads}, nil
}

func mergeWAFScans(a, b wafRegionScan) wafRegionScan {
	return wafRegionScan{
		acls:    append(append([]aws.WebACL(nil), a.acls...), b.acls...),
		lbHeads: append(append([]aws.LoadBalancerHead(nil), a.lbHeads...), b.lbHeads...),
	}
}

// cloudFrontScan holds the global CLOUDFRONT-scope inputs: the scope's web
// ACLs, the distributions they attach to, and whether both reads succeeded.
// An unevaluated scan carries no data at all, so partial global reads never
// masquerade as posture.
type cloudFrontScan struct {
	acls          []aws.WebACL
	distributions []aws.CloudFrontDistribution
	evaluated     bool
}

// collectWAFMetrics assembles the account's WAF posture: the CLOUDFRONT-scope
// pass plus the merged regional scans, joined against the entry points each
// web ACL protects.
func (c *Collector) collectWAFMetrics(ctx context.Context, client *aws.AWSClient, accountID string, regional wafScanWithCounts, level componentsdk.Level) *WAFMetrics {
	c.status("Collecting WAF metrics...")

	scan := cloudFrontScan{evaluated: true}
	if acls, err := client.ListWebACLs(ctx, aws.WAFScopeCloudFront, ""); err != nil {
		scan = cloudFrontScan{}
		c.warn("account %s: failed to list CloudFront-scope web ACLs: %v", accountID, err)
	} else {
		scan.acls = acls
	}
	if scan.evaluated {
		if distributions, err := client.ListCloudFrontDistributions(ctx); err != nil {
			scan = cloudFrontScan{}
			c.warn("account %s: failed to list distributions for WAF coverage: %v", accountID, err)
		} else {
			scan.distributions = distributions
		}
	}

	out := assembleWAFMetrics(regional, scan, level)
	if out.WebACLsTruncated {
		c.warn("account %s: web ACL inventory truncated to %d rows (%d dropped)", accountID, maxWebACLRows, out.WebACLsDroppedCount)
	}
	return out
}

// aclAssociation pairs a web ACL with how many resources it is attached to,
// the count both enforcement and row ordering read.
type aclAssociation struct {
	acl        aws.WebACL
	associated int
}

// assembleWAFMetrics reduces the raw scans to the account's WAF posture. Pure
// so the aggregation, coverage joins, and level gating are testable directly.
func assembleWAFMetrics(regional wafScanWithCounts, cloudfront cloudFrontScan, level componentsdk.Level) *WAFMetrics {
	out := &WAFMetrics{
		RegionsEvaluatedCount:    regional.RegionsEvaluatedCount,
		CloudFrontScopeEvaluated: cloudfront.evaluated,
	}

	albs := internetFacingALBArns(regional.lbHeads)
	out.InternetFacingALBCount = len(albs)
	out.InternetFacingALBCoveragePct = percent(len(protectedALBArns(regional.acls, albs)), len(albs))

	enabled, withWAF, byACL := distributionAttachments(cloudfront.distributions)
	out.EnabledDistributionCount = enabled
	out.DistributionCoveragePct = percent(withWAF, enabled)

	associations := aclAssociations(regional.acls, cloudfront.acls, byACL)
	out.WebACLCount = len(associations)
	out.RateLimitingEnforced = rateLimitingEnforced(associations)

	if !level.AtLeast(componentsdk.LevelAudit) {
		return out
	}
	out.WebACLs, out.WebACLsTruncated, out.WebACLsDroppedCount = webACLRows(associations, level)
	return out
}

func internetFacingALBArns(heads []aws.LoadBalancerHead) map[string]bool {
	albs := map[string]bool{}
	for _, head := range heads {
		if head.Type == "application" && head.Scheme == "internet-facing" && head.Arn != "" {
			albs[head.Arn] = true
		}
	}
	return albs
}

func protectedALBArns(acls []aws.WebACL, internetFacing map[string]bool) map[string]bool {
	protected := map[string]bool{}
	for _, acl := range acls {
		for _, arn := range acl.AssociatedALBArns {
			if internetFacing[arn] {
				protected[arn] = true
			}
		}
	}
	return protected
}

// distributionAttachments reduces the distribution fleet to its coverage
// inputs: how many enabled distributions exist, how many have a web ACL
// attached, and the attachment count per web ACL ARN.
func distributionAttachments(distributions []aws.CloudFrontDistribution) (enabled, withWAF int, byACL map[string]int) {
	byACL = map[string]int{}
	for _, dist := range distributions {
		if !dist.Enabled {
			continue
		}
		enabled++
		if dist.WebACLArn != "" {
			withWAF++
			byACL[dist.WebACLArn]++
		}
	}
	return enabled, withWAF, byACL
}

func aclAssociations(regionalACLs, cfACLs []aws.WebACL, distributionsByACL map[string]int) []aclAssociation {
	acls := append(append([]aws.WebACL(nil), regionalACLs...), cfACLs...)
	associations := make([]aclAssociation, 0, len(acls))
	for _, acl := range acls {
		associated := len(acl.AssociatedALBArns)
		if acl.Scope == aws.WAFScopeCloudFront {
			associated = distributionsByACL[acl.Arn]
		}
		associations = append(associations, aclAssociation{acl: acl, associated: associated})
	}
	return associations
}

func rateLimitingEnforced(associations []aclAssociation) bool {
	for _, assoc := range associations {
		if assoc.associated == 0 {
			continue
		}
		for _, rule := range assoc.acl.Rules {
			if rule.IsRateBased && rule.Action == "block" {
				return true
			}
		}
	}
	return false
}

// webACLRows orders the inventory so attached web ACLs survive the cap, then
// applies it.
func webACLRows(associations []aclAssociation, level componentsdk.Level) ([]WebACLRow, bool, int) {
	sorted := append([]aclAssociation(nil), associations...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].associated != sorted[j].associated {
			return sorted[i].associated > sorted[j].associated
		}
		return sorted[i].acl.Name < sorted[j].acl.Name
	})

	truncated := false
	dropped := 0
	if len(sorted) > maxWebACLRows {
		truncated = true
		dropped = len(sorted) - maxWebACLRows
		sorted = sorted[:maxWebACLRows]
	}
	rows := make([]WebACLRow, 0, len(sorted))
	for _, assoc := range sorted {
		rows = append(rows, webACLToRow(assoc.acl, assoc.associated, level))
	}
	return rows, truncated, dropped
}

func webACLToRow(acl aws.WebACL, associated int, level componentsdk.Level) WebACLRow {
	row := WebACLRow{
		Name:                    acl.Name,
		Scope:                   acl.Scope,
		Region:                  acl.Region,
		DefaultAction:           acl.DefaultAction,
		AssociatedResourceCount: associated,
		LoggingEvaluated:        acl.LoggingEvaluated,
		LoggingEnabled:          acl.LoggingEnabled,
		Rules:                   []WAFRuleRow{},
	}
	for _, rule := range acl.Rules {
		row.Rules = append(row.Rules, WAFRuleRow{
			Name:                 rule.Name,
			Priority:             rule.Priority,
			Action:               rule.Action,
			RateBased:            rule.IsRateBased,
			RateLimit:            rule.RateLimit,
			AggregateKeyType:     rule.AggregateKeyType,
			ManagedRuleGroupName: rule.ManagedRuleGroupName,
		})
	}
	if level.AtLeast(componentsdk.LevelInternal) {
		row.Arn = acl.Arn
		row.AssociatedResourceArns = append([]string{}, acl.AssociatedALBArns...)
		row.LoggingDestinationArn = acl.LoggingDestinationArn
	}
	return row
}
