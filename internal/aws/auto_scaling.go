package aws

import (
	"context"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	autoscalingtypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
)

// AutoScalingGroup is one EC2 auto scaling group's capacity posture.
type AutoScalingGroup struct {
	Name            string
	MinSize         int32
	MaxSize         int32
	DesiredCapacity int32

	// MinInstances is how many instances MinSize keeps. With instance
	// weights, the sizes are in weight units, so a MinSize of 4 over types
	// that each weigh 4 keeps one instance. It equals MinSize unless every
	// instance type has the same weight.
	MinInstances int32

	AvailabilityZoneCount int

	// HealthCheckType is a comma-separated list of EC2, EBS, ELB and
	// VPC_LATTICE. ELB means an instance is replaced when the application
	// stops answering, not only when the VM dies.
	HealthCheckType string

	// HealthCheckGracePeriodSeconds is how long a new instance is exempt from
	// health replacement while it boots, nil when the API leaves it out.
	HealthCheckGracePeriodSeconds *int32

	UsesLaunchTemplate bool
	// LoadBalanced is true when the group has a load balancer, an Elastic
	// Load Balancing target group, or a traffic source such as a VPC Lattice
	// target group.
	LoadBalanced bool

	// SuspendedProcessCount counts scaling processes switched off. A group
	// with Launch or Terminate suspended holds its configuration but will not
	// act on it.
	SuspendedProcessCount int

	// PolicyCount counts the group's enabled scaling policies. A disabled
	// policy, or a predictive policy that only forecasts, does not change the
	// group's capacity.
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
			if p.Enabled != nil && !*p.Enabled {
				continue
			}
			// A predictive policy scales only in ForecastAndScale mode. Its
			// mode defaults to ForecastOnly.
			if aws.ToString(p.PolicyType) == "PredictiveScaling" &&
				(p.PredictiveScalingConfiguration == nil || p.PredictiveScalingConfiguration.Mode != autoscalingtypes.PredictiveScalingModeForecastAndScale) {
				continue
			}
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
				MinInstances:                  minInstances(g),
				MaxSize:                       aws.ToInt32(g.MaxSize),
				DesiredCapacity:               aws.ToInt32(g.DesiredCapacity),
				AvailabilityZoneCount:         len(g.AvailabilityZones),
				HealthCheckType:               aws.ToString(g.HealthCheckType),
				HealthCheckGracePeriodSeconds: g.HealthCheckGracePeriod,
				UsesLaunchTemplate:            g.LaunchTemplate != nil || g.MixedInstancesPolicy != nil,
				LoadBalanced:                  len(g.TargetGroupARNs) > 0 || len(g.LoadBalancerNames) > 0 || len(g.TrafficSources) > 0,
				SuspendedProcessCount:         len(g.SuspendedProcesses),
				PolicyCount:                   policyCounts[name],
			})
		}
	}
	return groups, nil
}

// minInstances is how many instances a group's MinSize keeps. A mixed
// instances policy can weigh each instance type, and the group's sizes are
// then in those units. When every type has the same weight, MinSize divided
// by that weight and rounded up is the instance count. Otherwise, and for a
// group sized in vCPUs or memory, MinSize is taken as it is.
func minInstances(g autoscalingtypes.AutoScalingGroup) int32 {
	minSize := aws.ToInt32(g.MinSize)
	if units := aws.ToString(g.DesiredCapacityType); units != "" && units != "units" {
		return minSize
	}
	if g.MixedInstancesPolicy == nil || g.MixedInstancesPolicy.LaunchTemplate == nil {
		return minSize
	}
	weight := int64(0)
	for _, o := range g.MixedInstancesPolicy.LaunchTemplate.Overrides {
		w, err := strconv.ParseInt(aws.ToString(o.WeightedCapacity), 10, 32)
		if err != nil || w < 1 || (weight != 0 && w != weight) {
			return minSize
		}
		weight = w
	}
	if weight <= 1 {
		return minSize
	}
	return int32((int64(minSize) + weight - 1) / weight)
}
