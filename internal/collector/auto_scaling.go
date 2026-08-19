package collector

import (
	"context"

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
		if g.MinSize <= 1 {
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
		if g.HealthCheckType == "ELB" {
			out.GroupsWithELBHealthCheckCount++
		}
		// Detection without response: the target group stops routing to a hung
		// application, but the group never replaces the instance because the
		// VM itself reports healthy.
		if g.LoadBalanced && g.HealthCheckType != "ELB" {
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
		Groups:                                       append(append([]AutoScalingGroupRow(nil), a.Groups...), b.Groups...),
	}
}
