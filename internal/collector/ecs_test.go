package collector

import (
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

func TestAggregateECS(t *testing.T) {
	api := aws.ECSService{Cluster: "prod", Name: "api", LaunchType: "FARGATE", DesiredCount: 3, LoadBalanced: true, CircuitBreakerEnabled: true}
	jobs := aws.ECSService{Cluster: "prod", Name: "jobs", LaunchType: "FARGATE", DesiredCount: 1}

	scaled := aws.ECSServiceScaling{
		Cluster: "prod", Service: "api",
		MinCapacity: 2, MaxCapacity: 10,
		PolicyTypes: []string{"TargetTrackingScaling"},
		Metrics:     []string{"PendingJobsPerTask"},
	}

	t.Run("the chain needs bounds and a policy that moves the service", func(t *testing.T) {
		registeredOnly := aws.ECSServiceScaling{Cluster: "prod", Service: "jobs", MinCapacity: 1, MaxCapacity: 4}
		got := aggregateECS([]aws.ECSService{api, jobs}, []aws.ECSServiceScaling{scaled, registeredOnly}, true)

		if got.ServicesWithAutoscalingCount != 2 {
			t.Errorf("ServicesWithAutoscalingCount = %d, want 2", got.ServicesWithAutoscalingCount)
		}
		if got.ServicesWithScalingPolicyCount != 1 {
			t.Errorf("ServicesWithScalingPolicyCount = %d, want 1: bounds without a policy scale nothing", got.ServicesWithScalingPolicyCount)
		}
	})

	// The capacity floor is the scaling minimum where registered, the desired
	// count otherwise. One task means no redundancy in either reading.
	t.Run("the single-task floor follows scaling where it exists", func(t *testing.T) {
		got := aggregateECS([]aws.ECSService{api, jobs}, []aws.ECSServiceScaling{scaled}, true)

		if got.SingleTaskServiceCount != 1 {
			t.Errorf("SingleTaskServiceCount = %d, want 1: api floors at 2 via scaling, jobs at its desired count of 1", got.SingleTaskServiceCount)
		}
	})

	t.Run("a scaled-down minimum beats a comfortable desired count", func(t *testing.T) {
		floorOne := aws.ECSServiceScaling{Cluster: "prod", Service: "api", MinCapacity: 1, MaxCapacity: 10, PolicyTypes: []string{"TargetTrackingScaling"}}
		got := aggregateECS([]aws.ECSService{api}, []aws.ECSServiceScaling{floorOne}, true)

		if got.SingleTaskServiceCount != 1 {
			t.Errorf("SingleTaskServiceCount = %d, want 1: desired 3 but scaling may take it to 1", got.SingleTaskServiceCount)
		}
	})

	t.Run("unresolved scaling suppresses capacity findings without hiding services", func(t *testing.T) {
		got := aggregateECS([]aws.ECSService{api, jobs}, nil, false)

		if got.ServiceCount != 2 || got.FargateServiceCount != 2 {
			t.Errorf("counts = %d and %d, want services still counted", got.ServiceCount, got.FargateServiceCount)
		}
		if got.ScalingUnresolvedServiceCount != 2 {
			t.Errorf("ScalingUnresolvedServiceCount = %d, want 2", got.ScalingUnresolvedServiceCount)
		}
		if got.ServicesWithAutoscalingCount != 0 || got.SingleTaskServiceCount != 0 {
			t.Errorf("scaling findings = %d and %d, want 0 when unproven", got.ServicesWithAutoscalingCount, got.SingleTaskServiceCount)
		}
	})

	t.Run("deployment and network posture count independently of scaling", func(t *testing.T) {
		public := aws.ECSService{Cluster: "prod", Name: "edge", AssignsPublicIP: true, DesiredCount: 2}
		got := aggregateECS([]aws.ECSService{api, public}, nil, true)

		if got.ServicesWithCircuitBreakerCount != 1 {
			t.Errorf("ServicesWithCircuitBreakerCount = %d, want 1", got.ServicesWithCircuitBreakerCount)
		}
		if got.ServicesWithPublicIPCount != 1 {
			t.Errorf("ServicesWithPublicIPCount = %d, want 1", got.ServicesWithPublicIPCount)
		}
		if got.LoadBalancedServiceCount != 1 {
			t.Errorf("LoadBalancedServiceCount = %d, want 1", got.LoadBalancedServiceCount)
		}
		if got.ClusterCount != 1 {
			t.Errorf("ClusterCount = %d, want 1", got.ClusterCount)
		}
	})
}

func TestMergeECSMetricsSumsAcrossRegions(t *testing.T) {
	a := ECSMetrics{ServiceCount: 2, ServicesWithScalingPolicyCount: 1, Services: []ECSServiceRow{{Name: "api", Region: "us-east-1"}}}
	b := ECSMetrics{ServiceCount: 1, ScalingUnresolvedServiceCount: 1, Services: []ECSServiceRow{{Name: "eu", Region: "eu-west-1"}}}

	got := mergeECSMetrics(a, b)

	if got.ServiceCount != 3 || got.ServicesWithScalingPolicyCount != 1 || got.ScalingUnresolvedServiceCount != 1 {
		t.Errorf("counts = %+v, want sums preserved", got)
	}
	if len(got.Services) != 2 {
		t.Errorf("len(Services) = %d, want 2", len(got.Services))
	}
}
