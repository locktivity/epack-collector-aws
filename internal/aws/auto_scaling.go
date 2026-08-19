package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
)

// AutoScalingGroup is one EC2 auto scaling group's capacity posture.
type AutoScalingGroup struct {
	Name            string
	MinSize         int32
	MaxSize         int32
	DesiredCapacity int32

	AvailabilityZoneCount int

	// HealthCheckType is EC2 or ELB. ELB means an instance is replaced when
	// the application stops answering, not only when the VM dies.
	HealthCheckType string

	// HealthCheckGracePeriodSeconds is how long a new instance is exempt from
	// health replacement while it boots.
	HealthCheckGracePeriodSeconds int32

	UsesLaunchTemplate bool
	LoadBalanced       bool

	// SuspendedProcessCount counts scaling processes switched off. A group
	// with Launch or Terminate suspended holds its configuration but will not
	// act on it.
	SuspendedProcessCount int

	PolicyCount int
}

// ListAutoScalingGroups returns the region's groups with their scaling policy
// counts. Two paginated calls per region, no per-group fan-out.
func (c *AWSClient) ListAutoScalingGroups(ctx context.Context, region string) ([]AutoScalingGroup, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := autoscaling.NewFromConfig(cfg)

	policyCounts := map[string]int{}
	policyPaginator := autoscaling.NewDescribePoliciesPaginator(client, &autoscaling.DescribePoliciesInput{})
	for policyPaginator.HasMorePages() {
		page, err := policyPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing auto scaling policies in %s: %w", region, err)
		}
		for _, p := range page.ScalingPolicies {
			policyCounts[aws.ToString(p.AutoScalingGroupName)]++
		}
	}

	var groups []AutoScalingGroup
	groupPaginator := autoscaling.NewDescribeAutoScalingGroupsPaginator(client, &autoscaling.DescribeAutoScalingGroupsInput{})
	for groupPaginator.HasMorePages() {
		page, err := groupPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing auto scaling groups in %s: %w", region, err)
		}
		for _, g := range page.AutoScalingGroups {
			name := aws.ToString(g.AutoScalingGroupName)
			groups = append(groups, AutoScalingGroup{
				Name:                          name,
				MinSize:                       aws.ToInt32(g.MinSize),
				MaxSize:                       aws.ToInt32(g.MaxSize),
				DesiredCapacity:               aws.ToInt32(g.DesiredCapacity),
				AvailabilityZoneCount:         len(g.AvailabilityZones),
				HealthCheckType:               aws.ToString(g.HealthCheckType),
				HealthCheckGracePeriodSeconds: aws.ToInt32(g.HealthCheckGracePeriod),
				UsesLaunchTemplate:            g.LaunchTemplate != nil || g.MixedInstancesPolicy != nil,
				LoadBalanced:                  len(g.TargetGroupARNs) > 0 || len(g.LoadBalancerNames) > 0,
				SuspendedProcessCount:         len(g.SuspendedProcesses),
				PolicyCount:                   policyCounts[name],
			})
		}
	}
	return groups, nil
}
