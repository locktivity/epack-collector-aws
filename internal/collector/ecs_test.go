package collector

import (
	"errors"
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

func TestAggregateECS(t *testing.T) {
	api := aws.ECSService{Cluster: "prod", Name: "api", LaunchType: "FARGATE", Fargate: true, DesiredCount: 3, LoadBalanced: true, CircuitBreakerEnabled: true}
	jobs := aws.ECSService{Cluster: "prod", Name: "jobs", LaunchType: "FARGATE", Fargate: true, DesiredCount: 1}

	scaled := aws.ECSServiceScaling{
		Cluster: "prod", Service: "api",
		MinCapacity: 2, MaxCapacity: 10,
		PolicyTypes:  []string{"TargetTrackingScaling"},
		Metrics:      []string{"PendingJobsPerTask"},
		PolicyScales: true,
	}

	t.Run("the chain needs bounds and a policy that moves the service", func(t *testing.T) {
		registeredOnly := aws.ECSServiceScaling{Cluster: "prod", Service: "jobs", MinCapacity: 1, MaxCapacity: 4}
		got := aggregateECS(1, []aws.ECSService{api, jobs}, []aws.ECSServiceScaling{scaled, registeredOnly}, true)

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
		got := aggregateECS(1, []aws.ECSService{api, jobs}, []aws.ECSServiceScaling{scaled}, true)

		if got.SingleTaskServiceCount != 1 {
			t.Errorf("SingleTaskServiceCount = %d, want 1: api floors at 2 via scaling, jobs at its desired count of 1", got.SingleTaskServiceCount)
		}
	})

	t.Run("a scaled-down minimum beats a comfortable desired count", func(t *testing.T) {
		floorOne := aws.ECSServiceScaling{Cluster: "prod", Service: "api", MinCapacity: 1, MaxCapacity: 10, PolicyTypes: []string{"TargetTrackingScaling"}, PolicyScales: true}
		got := aggregateECS(1, []aws.ECSService{api}, []aws.ECSServiceScaling{floorOne}, true)

		if got.SingleTaskServiceCount != 1 {
			t.Errorf("SingleTaskServiceCount = %d, want 1: desired 3 but scaling may take it to 1", got.SingleTaskServiceCount)
		}
	})

	t.Run("unresolved scaling suppresses capacity findings without hiding services", func(t *testing.T) {
		got := aggregateECS(1, []aws.ECSService{api, jobs}, nil, false)

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
		got := aggregateECS(1, []aws.ECSService{api, public}, nil, true)

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

	t.Run("a service with no launch type or strategy leaves the Fargate count out", func(t *testing.T) {
		unknown := aws.ECSService{Cluster: "prod", Name: "worker", FargateErr: errors.New("no launchType")}
		got := aggregateECS(1, []aws.ECSService{api, unknown}, nil, true)

		if got.FargateServiceCount != 1 || !hasUnread(got.missing, "fargate_service_count", 1) {
			t.Errorf("FargateServiceCount = %d, missing = %+v, want 1 counted and the count left out over 1 service", got.FargateServiceCount, got.missing)
		}
	})

	t.Run("a cluster with no service counts", func(t *testing.T) {
		got := aggregateECS(2, []aws.ECSService{api}, nil, true)

		if got.ClusterCount != 2 {
			t.Errorf("ClusterCount = %d, want 2", got.ClusterCount)
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

func TestAggregateECS_CountsExecEnabledServices(t *testing.T) {
	shell := aws.ECSService{Cluster: "prod", Name: "debug", EnableExecuteCommand: true}
	quiet := aws.ECSService{Cluster: "prod", Name: "api"}

	got := aggregateECS(1, []aws.ECSService{shell, quiet}, nil, true)

	if got.ExecEnabledServiceCount != 1 {
		t.Errorf("ExecEnabledServiceCount = %d, want 1", got.ExecEnabledServiceCount)
	}
}

func TestMergeECSMetrics_SumsExecEnabledCount(t *testing.T) {
	got := mergeECSMetrics(ECSMetrics{ExecEnabledServiceCount: 1}, ECSMetrics{ExecEnabledServiceCount: 2})

	if got.ExecEnabledServiceCount != 3 {
		t.Errorf("ExecEnabledServiceCount = %d, want 3", got.ExecEnabledServiceCount)
	}
}

// ecsServiceRow runs the kit's account with responses and returns its one
// ECS service row.
func ecsServiceRow(t *testing.T, responses []collectortest.Response) ECSServiceRow {
	t.Helper()
	services := runOutput(t, responses).Accounts[0].ECS.Services
	if len(services) != 1 {
		t.Fatalf("services = %d, want 1", len(services))
	}
	return services[0]
}

// A service can scale in to zero tasks, a scheduled shutdown can register a
// range of 0 to 0, a deployment can let every old task stop first, and a
// load-balanced service's grace period defaults to 0. A setting of 0 stays in
// the row.
func TestCollectECSMetrics_ZeroSettingsStayInTheRow(t *testing.T) {
	responses := func(minimumHealthyPercent, minCapacity, maxCapacity, grace int) []collectortest.Response {
		service := kitECSService()
		service["healthCheckGracePeriodSeconds"] = grace
		service["deploymentConfiguration"] = map[string]any{
			"minimumHealthyPercent": minimumHealthyPercent, "maximumPercent": 200,
			"deploymentCircuitBreaker": map[string]any{"enable": true, "rollback": true},
		}
		return replaceResponses(kitResponses(),
			ecsDescribeServicesResponse(service),
			jsonResponse("aws.applicationautoscaling.DescribeScalableTargets", regional("application-autoscaling"), map[string]any{"ScalableTargets": []any{map[string]any{
				"ServiceNamespace": "ecs", "ResourceId": "service/northwind/api", "ScalableDimension": "ecs:service:DesiredCount",
				"MinCapacity": minCapacity, "MaxCapacity": maxCapacity, "RoleARN": "arn:aws:iam::111122223333:role/ecs-autoscaling", "CreationTime": 1735689600,
			}}}))
	}
	row := ecsServiceRow(t, responses(0, 0, 0, 0))
	if !row.AutoScaled || row.MinCapacity == nil || *row.MinCapacity != 0 || row.MinimumHealthyPercent == nil || *row.MinimumHealthyPercent != 0 {
		t.Errorf("auto_scaled = %v, min_capacity = %v, minimum_healthy_percent = %v; want true, 0 and 0", row.AutoScaled, row.MinCapacity, row.MinimumHealthyPercent)
	}
	if row.MaxCapacity == nil || *row.MaxCapacity != 0 || row.HealthCheckGracePeriodSeconds == nil || *row.HealthCheckGracePeriodSeconds != 0 {
		t.Errorf("max_capacity = %v, health_check_grace_period_seconds = %v; want 0 and 0", row.MaxCapacity, row.HealthCheckGracePeriodSeconds)
	}
	row = ecsServiceRow(t, responses(50, 2, 10, 60))
	if row.MinCapacity == nil || *row.MinCapacity != 2 || row.MinimumHealthyPercent == nil || *row.MinimumHealthyPercent != 50 {
		t.Errorf("min_capacity = %v, minimum_healthy_percent = %v; want 2 and 50", row.MinCapacity, row.MinimumHealthyPercent)
	}
	if row.MaxCapacity == nil || *row.MaxCapacity != 10 || row.HealthCheckGracePeriodSeconds == nil || *row.HealthCheckGracePeriodSeconds != 60 {
		t.Errorf("max_capacity = %v, health_check_grace_period_seconds = %v; want 10 and 60", row.MaxCapacity, row.HealthCheckGracePeriodSeconds)
	}
}

// A scaling policy moves the service only when it can change the capacity. A
// predictive policy defaults to ForecastOnly, which forecasts and does not
// scale. A target tracking policy does not scale while the target suspends
// dynamic scaling in both directions. No policy scales outside the target's
// range, so a range of 2 to 2 moves nothing. A step scaling policy runs only
// when an alarm invokes it.
func TestCollectECSMetrics_PolicyThatScalesTheService(t *testing.T) {
	predictive := func(mode any) collectortest.Response {
		config := map[string]any{"MetricSpecifications": []any{map[string]any{
			"TargetValue": 50, "PredefinedMetricPairSpecification": map[string]any{"PredefinedMetricType": "ECSServiceCPUUtilization"},
		}}}
		if mode != nil {
			config["Mode"] = mode
		}
		return jsonResponse("aws.applicationautoscaling.DescribeScalingPolicies", regional("application-autoscaling"), map[string]any{"ScalingPolicies": []any{map[string]any{
			"PolicyARN": "arn:aws:autoscaling:us-east-1:111122223333:scalingPolicy:kit", "PolicyName": "predict", "ServiceNamespace": "ecs", "ResourceId": "service/northwind/api",
			"ScalableDimension": "ecs:service:DesiredCount", "PolicyType": "PredictiveScaling", "CreationTime": 1735689600,
			"PredictiveScalingPolicyConfiguration": config,
		}}})
	}
	targetRange := func(min, max int, suspended bool) collectortest.Response {
		return jsonResponse("aws.applicationautoscaling.DescribeScalableTargets", regional("application-autoscaling"), map[string]any{"ScalableTargets": []any{map[string]any{
			"ServiceNamespace": "ecs", "ResourceId": "service/northwind/api", "ScalableDimension": "ecs:service:DesiredCount",
			"MinCapacity": min, "MaxCapacity": max, "RoleARN": "arn:aws:iam::111122223333:role/ecs-autoscaling", "CreationTime": 1735689600,
			"SuspendedState": map[string]any{"DynamicScalingInSuspended": suspended, "DynamicScalingOutSuspended": suspended, "ScheduledScalingSuspended": false},
		}}})
	}
	target := func(suspended bool) collectortest.Response { return targetRange(2, 10, suspended) }
	step := func(alarms ...string) collectortest.Response {
		policy := map[string]any{
			"PolicyARN": "arn:aws:autoscaling:us-east-1:111122223333:scalingPolicy:kit", "PolicyName": "step-out", "ServiceNamespace": "ecs", "ResourceId": "service/northwind/api",
			"ScalableDimension": "ecs:service:DesiredCount", "PolicyType": "StepScaling", "CreationTime": 1735689600,
			"StepScalingPolicyConfiguration": map[string]any{
				"AdjustmentType": "ChangeInCapacity", "Cooldown": 60,
				"StepAdjustments": []any{map[string]any{"MetricIntervalLowerBound": 0, "ScalingAdjustment": 1}},
			},
		}
		if len(alarms) > 0 {
			list := []any{}
			for _, name := range alarms {
				list = append(list, map[string]any{"AlarmName": name, "AlarmARN": "arn:aws:cloudwatch:us-east-1:111122223333:alarm:" + name})
			}
			policy["Alarms"] = list
		}
		return jsonResponse("aws.applicationautoscaling.DescribeScalingPolicies", regional("application-autoscaling"), map[string]any{"ScalingPolicies": []any{policy}})
	}
	for _, tc := range []struct {
		name      string
		responses []collectortest.Response
		want      int
	}{
		{"predictive, ForecastOnly", []collectortest.Response{predictive("ForecastOnly")}, 0},
		{"predictive, mode left out", []collectortest.Response{predictive(nil)}, 0},
		{"predictive, ForecastAndScale", []collectortest.Response{predictive("ForecastAndScale")}, 1},
		{"target tracking, dynamic scaling suspended", []collectortest.Response{target(true)}, 0},
		{"target tracking, nothing suspended", []collectortest.Response{target(false)}, 1},
		{"target tracking, range of 2 to 2", []collectortest.Response{targetRange(2, 2, false)}, 0},
		{"step scaling, no alarm", []collectortest.Response{step()}, 0},
		{"step scaling, invoked by an alarm", []collectortest.Response{step("api-cpu-high")}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := runDetailed(t, replaceResponses(kitResponses(), tc.responses...))
			expectValues(t, doc, map[string]any{
				"/accounts/0/ecs/services_with_autoscaling_count":    1,
				"/accounts/0/ecs/services_with_scaling_policy_count": tc.want,
			})
		})
	}
}

// A customized target tracking metric built with metric math is named by the
// metric its queries read.
func TestCollectECSMetrics_ScalingMetricsNameTheirMetrics(t *testing.T) {
	policy := func(config map[string]any) []collectortest.Response {
		return replaceResponses(kitResponses(),
			jsonResponse("aws.applicationautoscaling.DescribeScalingPolicies", regional("application-autoscaling"), map[string]any{"ScalingPolicies": []any{map[string]any{
				"PolicyARN": "arn:aws:autoscaling:us-east-1:111122223333:scalingPolicy:kit", "PolicyName": "queue", "ServiceNamespace": "ecs", "ResourceId": "service/northwind/api",
				"ScalableDimension": "ecs:service:DesiredCount", "PolicyType": "TargetTrackingScaling", "CreationTime": 1735689600,
				"TargetTrackingScalingPolicyConfiguration": config,
			}}}))
	}
	named := ecsServiceRow(t, policy(map[string]any{"TargetValue": 10,
		"CustomizedMetricSpecification": map[string]any{"MetricName": "BacklogPerTask", "Namespace": "Northwind", "Statistic": "Average"}}))
	if len(named.ScalingMetrics) != 1 || named.ScalingMetrics[0] != "BacklogPerTask" {
		t.Errorf("scaling_metrics = %q, want [BacklogPerTask]", named.ScalingMetrics)
	}
	math := ecsServiceRow(t, policy(map[string]any{"TargetValue": 10, "CustomizedMetricSpecification": map[string]any{"Metrics": []any{
		map[string]any{"Id": "visible", "ReturnData": false, "MetricStat": map[string]any{
			"Metric": map[string]any{"MetricName": "ApproximateNumberOfMessagesVisible", "Namespace": "AWS/SQS", "Dimensions": []any{map[string]any{"Name": "QueueName", "Value": "jobs"}}},
			"Stat":   "Sum",
		}},
		map[string]any{"Id": "backlog", "Expression": "visible / 2", "Label": "Backlog per task", "ReturnData": true},
	}}}))
	if len(math.ScalingMetrics) != 1 || math.ScalingMetrics[0] != "ApproximateNumberOfMessagesVisible" {
		t.Errorf("scaling_metrics = %q, want [ApproximateNumberOfMessagesVisible]", math.ScalingMetrics)
	}
}
