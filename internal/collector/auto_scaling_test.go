package collector

import (
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

func TestAggregateAutoScalingGroups(t *testing.T) {
	web := aws.AutoScalingGroup{
		Name: "web", MinSize: 2, MaxSize: 10, DesiredCapacity: 4,
		AvailabilityZoneCount: 3, HealthCheckType: "ELB",
		UsesLaunchTemplate: true, LoadBalanced: true, PolicyCount: 2,
	}
	// The bastion pattern: a deliberate single-instance group in one zone,
	// using the ASG for self-healing rather than capacity.
	bastion := aws.AutoScalingGroup{
		Name: "bastion", MinSize: 1, MaxSize: 1, DesiredCapacity: 1,
		AvailabilityZoneCount: 1, HealthCheckType: "EC2", UsesLaunchTemplate: true,
	}
	suspended := aws.AutoScalingGroup{
		Name: "batch", MinSize: 2, MaxSize: 8, DesiredCapacity: 2,
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
