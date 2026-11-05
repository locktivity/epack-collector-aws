package collector

import (
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

func TestAggregateAutoScalingGroups(t *testing.T) {
	web := aws.AutoScalingGroup{
		Name: "web", MinSize: 2, MinInstances: 2, MaxSize: 10, DesiredCapacity: 4,
		AvailabilityZoneCount: 3, HealthCheckType: "ELB",
		UsesLaunchTemplate: true, LoadBalanced: true, PolicyCount: 2,
	}
	// The bastion pattern: a deliberate single-instance group in one zone,
	// using the ASG for self-healing rather than capacity.
	bastion := aws.AutoScalingGroup{
		Name: "bastion", MinSize: 1, MinInstances: 1, MaxSize: 1, DesiredCapacity: 1,
		AvailabilityZoneCount: 1, HealthCheckType: "EC2", UsesLaunchTemplate: true,
	}
	suspended := aws.AutoScalingGroup{
		Name: "batch", MinSize: 2, MinInstances: 2, MaxSize: 8, DesiredCapacity: 2,
		AvailabilityZoneCount: 2, PolicyCount: 1, SuspendedProcessCount: 2,
	}

	got := aggregateAutoScalingGroups([]aws.AutoScalingGroup{web, bastion, suspended})

	if got.GroupCount != 3 {
		t.Errorf("GroupCount = %d, want 3", got.GroupCount)
	}
	if got.SingleInstanceGroupCount != 1 {
		t.Errorf("SingleInstanceGroupCount = %d, want 1: the bastion", got.SingleInstanceGroupCount)
	}
	if got.SingleZoneGroupCount != 1 {
		t.Errorf("SingleZoneGroupCount = %d, want 1", got.SingleZoneGroupCount)
	}
	if got.GroupsWithScalingPolicyCount != 2 {
		t.Errorf("GroupsWithScalingPolicyCount = %d, want 2", got.GroupsWithScalingPolicyCount)
	}
	// Suspended processes leave the configuration present but inert, so the
	// group must surface even though it holds a policy.
	if got.GroupsWithSuspendedProcessesCount != 1 {
		t.Errorf("GroupsWithSuspendedProcessesCount = %d, want 1", got.GroupsWithSuspendedProcessesCount)
	}
	if got.GroupsWithELBHealthCheckCount != 1 {
		t.Errorf("GroupsWithELBHealthCheckCount = %d, want 1", got.GroupsWithELBHealthCheckCount)
	}
	if got.GroupsOnLaunchConfigurationsCount != 1 {
		t.Errorf("GroupsOnLaunchConfigurationsCount = %d, want 1: the suspended group carries no launch template", got.GroupsOnLaunchConfigurationsCount)
	}
}

func TestMergeAutoScalingMetricsSumsAcrossRegions(t *testing.T) {
	a := AutoScalingMetrics{GroupCount: 2, SingleInstanceGroupCount: 1, Groups: []AutoScalingGroupRow{{Name: "web", Region: "us-east-1"}}}
	b := AutoScalingMetrics{GroupCount: 1, GroupsWithScalingPolicyCount: 1, Groups: []AutoScalingGroupRow{{Name: "eu", Region: "eu-west-1"}}}

	got := mergeAutoScalingMetrics(a, b)

	if got.GroupCount != 3 || got.SingleInstanceGroupCount != 1 || got.GroupsWithScalingPolicyCount != 1 {
		t.Errorf("counts = %+v, want sums preserved", got)
	}
	if len(got.Groups) != 2 {
		t.Errorf("len(Groups) = %d, want 2", len(got.Groups))
	}
}

// The zombie-instance gap: the target group stops routing to a hung
// application, but an EC2-only health check never replaces the instance
// because the VM reports healthy.
func TestAggregateAutoScalingGroupsFlagsDetectionWithoutResponse(t *testing.T) {
	tests := []struct {
		name  string
		group aws.AutoScalingGroup
		want  int
	}{
		{
			name:  "load balanced on EC2-only checks is the gap",
			group: aws.AutoScalingGroup{Name: "web", LoadBalanced: true, HealthCheckType: "EC2"},
			want:  1,
		},
		{
			name:  "load balanced on ELB checks responds",
			group: aws.AutoScalingGroup{Name: "web", LoadBalanced: true, HealthCheckType: "ELB"},
			want:  0,
		},
		{
			name:  "VPC Lattice checks respond",
			group: aws.AutoScalingGroup{Name: "lattice", LoadBalanced: true, HealthCheckType: "EC2,VPC_LATTICE"},
			want:  0,
		},
		{
			name:  "the bastion is not load balanced, so EC2 checks are correct",
			group: aws.AutoScalingGroup{Name: "bastion", LoadBalanced: false, HealthCheckType: "EC2"},
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := aggregateAutoScalingGroups([]aws.AutoScalingGroup{tt.group})
			if got.LoadBalancedGroupsWithoutELBHealthCheckCount != tt.want {
				t.Fatalf("LoadBalancedGroupsWithoutELBHealthCheckCount = %d, want %d", got.LoadBalancedGroupsWithoutELBHealthCheckCount, tt.want)
			}
		})
	}
}

// asgResponse is a one-group DescribeAutoScalingGroups answer. extra goes
// inside the group's member element.
func asgResponse(extra string) collectortest.Response {
	return queryResponse("aws.autoscaling.DescribeAutoScalingGroups", regional("autoscaling"), "<AutoScalingGroups><member>"+
		"<AutoScalingGroupName>kit-asg</AutoScalingGroupName><MinSize>2</MinSize><MaxSize>4</MaxSize><DesiredCapacity>2</DesiredCapacity>"+
		"<AvailabilityZones><member>us-east-1a</member><member>us-east-1b</member></AvailabilityZones>"+
		"<HealthCheckGracePeriod>300</HealthCheckGracePeriod>"+
		"<LaunchTemplate><LaunchTemplateName>workers</LaunchTemplateName><Version>$Latest</Version></LaunchTemplate>"+
		"<SuspendedProcesses/><CreatedTime>2025-01-01T00:00:00Z</CreatedTime>"+extra+"</member></AutoScalingGroups>")
}

const asgTargetGroup = "<TargetGroupARNs><member>arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/web/73e2d6bc24d8a067</member></TargetGroupARNs>"

// HealthCheckType is a comma-separated list, and a group whose list includes
// ELB replaces instances on the load balancer's health.
func TestCollectAutoScalingMetrics_ELBHealthCheckAmongSeveralTypes(t *testing.T) {
	for _, healthCheckType := range []string{"ELB", "EBS,ELB", "ELB,EBS", "ELB,VPC_LATTICE"} {
		t.Run(healthCheckType, func(t *testing.T) {
			doc := runDetailed(t, replaceResponses(kitResponses(), asgResponse("<HealthCheckType>"+healthCheckType+"</HealthCheckType>"+asgTargetGroup)))
			expectValues(t, doc, map[string]any{
				"/accounts/0/auto_scaling/groups_with_elb_health_check_count":                  1,
				"/accounts/0/auto_scaling/load_balanced_groups_without_elb_health_check_count": 0,
			})
		})
	}
}

// A VPC Lattice target group is attached as a traffic source, and a group
// with one is load balanced.
func TestCollectAutoScalingMetrics_TrafficSourceIsLoadBalanced(t *testing.T) {
	lattice := "<TrafficSources><member><Identifier>arn:aws:vpc-lattice:us-east-1:111122223333:targetgroup/tg-0e2f2665eEXAMPLE</Identifier>" +
		"<Type>vpc-lattice</Type></member></TrafficSources>"
	for name, attachment := range map[string]string{"target group": asgTargetGroup, "VPC Lattice traffic source": lattice} {
		t.Run(name, func(t *testing.T) {
			doc := runDetailed(t, replaceResponses(kitResponses(), asgResponse("<HealthCheckType>EC2</HealthCheckType>"+attachment)))
			expectValues(t, doc, map[string]any{
				"/accounts/0/auto_scaling/groups/0/load_balanced":                              true,
				"/accounts/0/auto_scaling/load_balanced_groups_without_elb_health_check_count": 1,
			})
		})
	}
}

// A disabled scaling policy does not change the group's capacity, so it does
// not count.
func TestCollectAutoScalingMetrics_DisabledPolicyDoesNotCount(t *testing.T) {
	for enabled, want := range map[string]int{"true": 1, "false": 0} {
		t.Run("enabled "+enabled, func(t *testing.T) {
			policy := queryResponse("aws.autoscaling.DescribePolicies", regional("autoscaling"), "<ScalingPolicies><member><AutoScalingGroupName>kit-asg</AutoScalingGroupName>"+
				"<PolicyName>cpu</PolicyName><PolicyType>TargetTrackingScaling</PolicyType><PolicyARN>arn:aws:autoscaling:us-east-1:111122223333:scalingPolicy:kit</PolicyARN>"+
				"<Enabled>"+enabled+"</Enabled></member></ScalingPolicies>")
			doc := runDetailed(t, replaceResponses(kitResponses(), asgResponse("<HealthCheckType>EC2</HealthCheckType>"), policy))
			expectValues(t, doc, map[string]any{"/accounts/0/auto_scaling/groups_with_scaling_policy_count": want})
		})
	}
}

// predictivePolicy answers DescribePolicies with one enabled predictive
// scaling policy on kit-asg in mode.
func predictivePolicy(mode string) collectortest.Response {
	return queryResponse("aws.autoscaling.DescribePolicies", regional("autoscaling"), "<ScalingPolicies><member><AutoScalingGroupName>kit-asg</AutoScalingGroupName>"+
		"<PolicyName>forecast</PolicyName><PolicyType>PredictiveScaling</PolicyType><PolicyARN>arn:aws:autoscaling:us-east-1:111122223333:scalingPolicy:forecast</PolicyARN>"+
		"<Enabled>true</Enabled><PredictiveScalingConfiguration><MetricSpecifications><member><TargetValue>40</TargetValue><PredefinedMetricPairSpecification>"+
		"<PredefinedMetricType>ASGCPUUtilization</PredefinedMetricType></PredefinedMetricPairSpecification></member></MetricSpecifications>"+
		"<Mode>"+mode+"</Mode></PredictiveScalingConfiguration></member></ScalingPolicies>")
}

// A predictive scaling policy in ForecastOnly mode makes forecasts and does
// not scale, so it does not count.
func TestCollectAutoScalingMetrics_ForecastOnlyPolicyDoesNotCount(t *testing.T) {
	for mode, want := range map[string]int{"ForecastOnly": 0, "ForecastAndScale": 1} {
		t.Run(mode, func(t *testing.T) {
			doc := runDetailed(t, replaceResponses(kitResponses(), asgResponse("<HealthCheckType>EC2</HealthCheckType>"), predictivePolicy(mode)))
			expectValues(t, doc, map[string]any{
				"/accounts/0/auto_scaling/groups_with_scaling_policy_count": want,
				"/accounts/0/auto_scaling/groups/0/policy_count":            want,
			})
		})
	}
}

// sizedGroup is a one-group DescribeAutoScalingGroups answer with the sizes
// and grace period given. extra goes inside the group's member element.
func sizedGroup(grace, minSize, maxSize, desired, extra string) collectortest.Response {
	return queryResponse("aws.autoscaling.DescribeAutoScalingGroups", regional("autoscaling"), "<AutoScalingGroups><member>"+
		"<AutoScalingGroupName>kit-asg</AutoScalingGroupName><MinSize>"+minSize+"</MinSize><MaxSize>"+maxSize+"</MaxSize><DesiredCapacity>"+desired+"</DesiredCapacity>"+
		"<AvailabilityZones><member>us-east-1a</member><member>us-east-1b</member></AvailabilityZones>"+
		"<HealthCheckType>EC2</HealthCheckType><HealthCheckGracePeriod>"+grace+"</HealthCheckGracePeriod>"+
		"<SuspendedProcesses/><CreatedTime>2025-01-01T00:00:00Z</CreatedTime>"+extra+"</member></AutoScalingGroups>")
}

// weightedTypes is a mixed instances policy whose two instance types each
// weigh weight.
func weightedTypes(weight string) string {
	return "<MixedInstancesPolicy><LaunchTemplate><LaunchTemplateSpecification><LaunchTemplateName>workers</LaunchTemplateName><Version>$Latest</Version></LaunchTemplateSpecification>" +
		"<Overrides><member><InstanceType>m5.xlarge</InstanceType><WeightedCapacity>" + weight + "</WeightedCapacity></member>" +
		"<member><InstanceType>m5a.xlarge</InstanceType><WeightedCapacity>" + weight + "</WeightedCapacity></member></Overrides></LaunchTemplate></MixedInstancesPolicy>"
}

// With instance weights, MinSize is in weight units. A MinSize of 4 over
// types that each weigh 4 keeps one instance.
func TestCollectAutoScalingMetrics_WeightedMinSize(t *testing.T) {
	for _, tc := range []struct {
		name, minSize, weight string
		want                  int
	}{
		{"min 4 at weight 4", "4", "4", 1},
		{"min 8 at weight 4", "8", "4", 0},
		{"min 1 at weight 1", "1", "1", 1},
		{"min 4 at weight 1", "4", "1", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := runDetailed(t, replaceResponses(kitResponses(), sizedGroup("300", tc.minSize, "16", "8", weightedTypes(tc.weight))))
			expectValues(t, doc, map[string]any{
				"/accounts/0/auto_scaling/groups/0/min_size":           tc.minSize,
				"/accounts/0/auto_scaling/single_instance_group_count": tc.want,
			})
		})
	}
}

// A grace period of 0 seconds is the API default, and the row keeps it.
func TestCollectAutoScalingMetrics_ZeroGracePeriodIsKept(t *testing.T) {
	const template = "<LaunchTemplate><LaunchTemplateName>workers</LaunchTemplateName><Version>$Latest</Version></LaunchTemplate>"
	for _, grace := range []string{"0", "300"} {
		t.Run(grace, func(t *testing.T) {
			doc := runDetailed(t, replaceResponses(kitResponses(), sizedGroup(grace, "2", "4", "2", template)))
			expectValues(t, doc, map[string]any{"/accounts/0/auto_scaling/groups/0/health_check_grace_period_seconds": grace})
		})
	}
}
