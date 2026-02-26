package collector

import (
	"context"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

// networkMetricsWithCounts is used internally to track counts for weighted averaging across regions.
type networkMetricsWithCounts struct {
	NetworkMetrics
	vpcCount           int
	securityGroupCount int
}

// collectNetworkMetrics collects network security metrics for a single region.
func (c *Collector) collectNetworkMetrics(ctx context.Context, client *aws.AWSClient, region string) (*networkMetricsWithCounts, error) {
	result := &networkMetricsWithCounts{}

	// Collect VPC metrics
	if err := c.collectVPCMetrics(ctx, client, region, result); err != nil {
		return result, err
	}

	// Collect security group metrics
	if err := c.collectSecurityGroupMetrics(ctx, client, region, result); err != nil {
		return result, err
	}

	return result, nil
}

// collectVPCMetrics collects VPC-related metrics.
func (c *Collector) collectVPCMetrics(ctx context.Context, client *aws.AWSClient, region string, result *networkMetricsWithCounts) error {
	vpcs, err := client.ListVPCs(ctx, region)
	if err != nil {
		return err
	}

	result.vpcCount = len(vpcs)

	flowLogsEnabled := 0
	for _, vpc := range vpcs {
		if vpc.FlowLogsEnabled {
			flowLogsEnabled++
		}
	}
	result.FlowLogsEnabled = percent(flowLogsEnabled, len(vpcs))

	return nil
}

// collectSecurityGroupMetrics collects security group metrics.
func (c *Collector) collectSecurityGroupMetrics(ctx context.Context, client *aws.AWSClient, region string, result *networkMetricsWithCounts) error {
	sgs, err := client.ListSecurityGroups(ctx, region)
	if err != nil {
		return err
	}

	result.securityGroupCount = len(sgs)

	stats := analyzeSecurityGroups(sgs)

	result.OpenToWorldSSH = percent(stats.openSSH, len(sgs))
	result.OpenToWorldRDP = percent(stats.openRDP, len(sgs))

	return nil
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
func mergeNetworkMetrics(a, b networkMetricsWithCounts) networkMetricsWithCounts {
	result := a
	result.vpcCount += b.vpcCount
	result.securityGroupCount += b.securityGroupCount

	// Weighted averages for percentages
	if a.vpcCount+b.vpcCount > 0 {
		result.FlowLogsEnabled = weightedAverage(a.FlowLogsEnabled, a.vpcCount, b.FlowLogsEnabled, b.vpcCount)
	}

	sgAll := a.securityGroupCount + b.securityGroupCount
	if sgAll > 0 {
		result.OpenToWorldSSH = weightedAverage(a.OpenToWorldSSH, a.securityGroupCount, b.OpenToWorldSSH, b.securityGroupCount)
		result.OpenToWorldRDP = weightedAverage(a.OpenToWorldRDP, a.securityGroupCount, b.OpenToWorldRDP, b.securityGroupCount)
	}

	return result
}

// weightedAverage computes a weighted average of two values.
func weightedAverage(val1, weight1, val2, weight2 int) int {
	total := weight1 + weight2
	if total == 0 {
		return 0
	}
	return (val1*weight1 + val2*weight2) / total
}
