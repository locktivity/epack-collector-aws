package collector

import (
	"context"
	"strings"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// collectAutoScalingMetrics collects EC2 auto scaling posture for a region.
func (c *Collector) collectAutoScalingMetrics(ctx context.Context, client *aws.AWSClient, region, accountID string, level componentsdk.Level) (*AutoScalingMetrics, error) {
	groups, err := client.ListAutoScalingGroups(ctx, region)
	if err != nil {
		return nil, err
	}

	out := aggregateAutoScalingGroups(groups)
	if level.AtLeast(componentsdk.LevelAudit) {
		out.Groups = make([]AutoScalingGroupRow, 0, len(groups))
		for _, g := range groups {
			out.Groups = append(out.Groups, AutoScalingGroupRow{
				Name:                          g.Name,
				Region:                        region,
				MinSize:                       g.MinSize,
				MaxSize:                       g.MaxSize,
				DesiredCapacity:               g.DesiredCapacity,
				AvailabilityZoneCount:         g.AvailabilityZoneCount,
				HealthCheckType:               g.HealthCheckType,
				HealthCheckGracePeriodSeconds: g.HealthCheckGracePeriodSeconds,
				UsesLaunchTemplate:            g.UsesLaunchTemplate,
				LoadBalanced:                  g.LoadBalanced,
				SuspendedProcessCount:         g.SuspendedProcessCount,
				PolicyCount:                   g.PolicyCount,
			})
		}
	}
	return out, nil
}

// aggregateAutoScalingGroups reduces a region's groups to the capacity
// findings, with the same floor semantics as ECS: the minimum is what the
// group can drop to, whatever the desired capacity says today.
func aggregateAutoScalingGroups(groups []aws.AutoScalingGroup) *AutoScalingMetrics {
	out := &AutoScalingMetrics{GroupCount: len(groups)}
	for _, g := range groups {
		if g.MinInstances <= 1 {
			out.SingleInstanceGroupCount++
		}
		if g.AvailabilityZoneCount == 1 {
			out.SingleZoneGroupCount++
		}
		if g.PolicyCount > 0 {
			out.GroupsWithScalingPolicyCount++
		}
		if g.SuspendedProcessCount > 0 {
			out.GroupsWithSuspendedProcessesCount++
		}
		if hasELBHealthCheck(g.HealthCheckType) {
			out.GroupsWithELBHealthCheckCount++
		}
		// Detection without response: the target group stops routing to a hung
		// application, but the group never replaces the instance because the
		// VM itself reports healthy. With VPC Lattice health checks on, Auto
		// Scaling also replaces an instance that Lattice reports unhealthy.
		if g.LoadBalanced && !hasELBHealthCheck(g.HealthCheckType) && !hasHealthCheckType(g.HealthCheckType, "VPC_LATTICE") {
			out.LoadBalancedGroupsWithoutELBHealthCheckCount++
		}
		if !g.UsesLaunchTemplate {
			out.GroupsOnLaunchConfigurationsCount++
		}
	}
	return out
}

// mergeAutoScalingMetrics combines per-region results.
func mergeAutoScalingMetrics(a, b AutoScalingMetrics) AutoScalingMetrics {
	return AutoScalingMetrics{
		GroupCount:                                   a.GroupCount + b.GroupCount,
		SingleInstanceGroupCount:                     a.SingleInstanceGroupCount + b.SingleInstanceGroupCount,
		SingleZoneGroupCount:                         a.SingleZoneGroupCount + b.SingleZoneGroupCount,
		GroupsWithScalingPolicyCount:                 a.GroupsWithScalingPolicyCount + b.GroupsWithScalingPolicyCount,
		GroupsWithSuspendedProcessesCount:            a.GroupsWithSuspendedProcessesCount + b.GroupsWithSuspendedProcessesCount,
		GroupsWithELBHealthCheckCount:                a.GroupsWithELBHealthCheckCount + b.GroupsWithELBHealthCheckCount,
		LoadBalancedGroupsWithoutELBHealthCheckCount: a.LoadBalancedGroupsWithoutELBHealthCheckCount + b.LoadBalancedGroupsWithoutELBHealthCheckCount,
		GroupsOnLaunchConfigurationsCount:            a.GroupsOnLaunchConfigurationsCount + b.GroupsOnLaunchConfigurationsCount,
		Groups:                                       appendRows(a.Groups, b.Groups),
	}
}

// hasELBHealthCheck reports whether a group's health check types, a
// comma-separated list such as EBS,ELB, include ELB.
func hasELBHealthCheck(types string) bool {
	return hasHealthCheckType(types, "ELB")
}

// hasHealthCheckType reports whether a group's health check types, a
// comma-separated list, include want.
func hasHealthCheckType(types, want string) bool {
	for _, t := range strings.Split(types, ",") {
		if strings.TrimSpace(t) == want {
			return true
		}
	}
	return false
}
