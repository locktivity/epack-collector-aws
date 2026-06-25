package collector

import (
	"context"
	"errors"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// networkMetricsWithCounts is used internally to track counts for weighted averaging across regions.
type networkMetricsWithCounts struct {
	NetworkMetrics
	vpcCount           int
	securityGroupCount int
}

// collectNetworkMetrics collects network security metrics for a single region.
//
// At trust, only aggregate exposure percentages are populated. At audit,
// per-VPC and per-SG summary rows are surfaced. Flow log status is internal-only.
func (c *Collector) collectNetworkMetrics(ctx context.Context, client *aws.AWSClient, region string, accountID string, level componentsdk.Level) (*networkMetricsWithCounts, error) {
	result := &networkMetricsWithCounts{}

	// Collect VPC metrics
	if err := c.collectVPCMetrics(ctx, client, region, accountID, result, level); err != nil {
		return result, err
	}

	// Collect security group metrics
	if err := c.collectSecurityGroupMetrics(ctx, client, region, result, level); err != nil {
		return result, err
	}

	return result, nil
}

// collectVPCMetrics collects VPC-related metrics.
func (c *Collector) collectVPCMetrics(ctx context.Context, client *aws.AWSClient, region string, accountID string, result *networkMetricsWithCounts, level componentsdk.Level) error {
	includeFlowLogs := level.AtLeast(componentsdk.LevelInternal)
	vpcs, err := client.ListVPCs(ctx, region, includeFlowLogs)
	if err != nil {
		var flowLogsErr *aws.FlowLogsUnavailableError
		if !errors.As(err, &flowLogsErr) || len(vpcs) == 0 {
			return err
		}
		c.warn("account %s region %s: failed to collect VPC flow log status: %v", accountID, region, err)
	}

	result.vpcCount = len(vpcs)

	if level.AtLeast(componentsdk.LevelAudit) {
		result.VPCs = append(result.VPCs, vpcSummaries(vpcs, region, includeFlowLogs)...)
	}

	return nil
}

func vpcSummaries(vpcs []aws.VPC, region string, includeFlowLogs bool) []VPCSummary {
	rows := make([]VPCSummary, 0, len(vpcs))
	for _, vpc := range vpcs {
		row := VPCSummary{
			VPCID:     vpc.VPCID,
			Region:    region,
			IsDefault: vpc.IsDefault,
		}
		if includeFlowLogs {
			row.FlowLogsEvaluated = boolPtr(vpc.FlowLogsEvaluated)
			row.FlowLogsErrorCode = vpc.FlowLogsErrorCode
			if vpc.FlowLogsEvaluated {
				row.FlowLogsEnabled = boolPtr(vpc.FlowLogsEnabled)
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// collectSecurityGroupMetrics collects security group metrics.
func (c *Collector) collectSecurityGroupMetrics(ctx context.Context, client *aws.AWSClient, region string, result *networkMetricsWithCounts, level componentsdk.Level) error {
	sgs, err := client.ListSecurityGroups(ctx, region)
	if err != nil {
		return err
	}

	result.securityGroupCount = len(sgs)

	stats := analyzeSecurityGroups(sgs)

	result.OpenToWorldSSH = percent(stats.openSSH, len(sgs))
	result.OpenToWorldRDP = percent(stats.openRDP, len(sgs))

	if level.AtLeast(componentsdk.LevelAudit) {
		for _, sg := range sgs {
			exposure := analyzeSecurityGroupExposure(sg)
			row := SecurityGroupSummary{
				GroupID:        sg.GroupID,
				GroupName:      sg.GroupName,
				Region:         region,
				VPCID:          sg.VPCID,
				IsDefault:      sg.IsDefault,
				OpenToWorldSSH: exposure.hasOpenSSH,
				OpenToWorldRDP: exposure.hasOpenRDP,
			}
			if level.AtLeast(componentsdk.LevelInternal) {
				row.IngressRules = sgIngressRulesToInternal(sg.IngressRules)
			}
			result.SecurityGroups = append(result.SecurityGroups, row)
		}
	}

	return nil
}

// sgIngressRulesToInternal projects per-SG ingress rules onto the internal-level
// emission. Both CIDR-based and source-SG-based ingress are surfaced; rules
// with neither set (degenerate config) still emit as a row so the absence of
// allowed sources is visible.
func sgIngressRulesToInternal(in []aws.SecurityGroupRule) []SGIngressRule {
	if len(in) == 0 {
		return nil
	}
	out := make([]SGIngressRule, 0, len(in))
	for _, r := range in {
		row := SGIngressRule{
			Protocol: r.Protocol,
			FromPort: r.FromPort,
			ToPort:   r.ToPort,
		}
		if len(r.CIDRBlocks) > 0 {
			row.CIDRBlocks = append([]string(nil), r.CIDRBlocks...)
		}
		if len(r.SourceSGIDs) > 0 {
			row.SourceSGIDs = append([]string(nil), r.SourceSGIDs...)
		}
		out = append(out, row)
	}
	return out
}

// sgStats holds security group analysis results.
type sgStats struct {
	openSSH int
	openRDP int
}

// analyzeSecurityGroups analyzes all security groups and returns statistics.
func analyzeSecurityGroups(sgs []aws.SecurityGroup) sgStats {
	var stats sgStats

	for _, sg := range sgs {
		exposure := analyzeSecurityGroupExposure(sg)

		if exposure.hasOpenSSH {
			stats.openSSH++
		}
		if exposure.hasOpenRDP {
			stats.openRDP++
		}
	}

	return stats
}

// sgExposure represents what a security group exposes to the world.
type sgExposure struct {
	hasOpenSSH bool
	hasOpenRDP bool
}

// analyzeSecurityGroupExposure checks what a single security group exposes.
func analyzeSecurityGroupExposure(sg aws.SecurityGroup) sgExposure {
	var exposure sgExposure

	for _, rule := range sg.IngressRules {
		if !rule.IsOpenToWorld() {
			continue
		}
		if rule.IsSSH() {
			exposure.hasOpenSSH = true
		}
		if rule.IsRDP() {
			exposure.hasOpenRDP = true
		}
	}

	return exposure
}

// mergeNetworkMetrics merges network metrics from multiple regions.
//
// Trust-level exposure aggregates are weighted-averaged across regions;
// audit-level per-VPC and per-SG inventories are concatenated.
func mergeNetworkMetrics(a, b networkMetricsWithCounts) networkMetricsWithCounts {
	result := a
	result.vpcCount += b.vpcCount
	result.securityGroupCount += b.securityGroupCount

	// Audit-level slices: concatenate across regions.
	if len(b.VPCs) > 0 {
		result.VPCs = append(result.VPCs, b.VPCs...)
	}
	if len(b.SecurityGroups) > 0 {
		result.SecurityGroups = append(result.SecurityGroups, b.SecurityGroups...)
	}

	sgAll := a.securityGroupCount + b.securityGroupCount
	if sgAll > 0 {
		result.OpenToWorldSSH = weightedAverage(a.OpenToWorldSSH, a.securityGroupCount, b.OpenToWorldSSH, b.securityGroupCount)
		result.OpenToWorldRDP = weightedAverage(a.OpenToWorldRDP, a.securityGroupCount, b.OpenToWorldRDP, b.securityGroupCount)
	}

	return result
}

func boolPtr(v bool) *bool {
	return &v
}

// weightedAverage computes a weighted average of two values.
func weightedAverage(val1, weight1, val2, weight2 int) int {
	total := weight1 + weight2
	if total == 0 {
		return 0
	}
	return (val1*weight1 + val2*weight2) / total
}
