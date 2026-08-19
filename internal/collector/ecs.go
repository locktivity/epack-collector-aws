package collector

import (
	"context"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// collectECSMetrics collects service capacity and scaling posture for a region.
// A failed scaling lookup suppresses every scaling-dependent finding rather
// than reporting the services as unscaled.
func (c *Collector) collectECSMetrics(ctx context.Context, client *aws.AWSClient, region, accountID string, level componentsdk.Level) (*ECSMetrics, error) {
	services, err := client.ListECSServices(ctx, region)
	if err != nil {
		return nil, err
	}

	scaling, scalingErr := client.ListECSServiceScaling(ctx, region)
	if scalingErr != nil {
		c.warn("account %s region %s: failed to read ECS service scaling; capacity findings for %d service(s) are unproven: %v", accountID, region, len(services), scalingErr)
	}

	out := aggregateECS(services, scaling, scalingErr == nil)
	if level.AtLeast(componentsdk.LevelAudit) {
		byService := scalingByService(scaling)
		for _, s := range services {
			row := ECSServiceRow{
				Cluster:                       s.Cluster,
				Name:                          s.Name,
				Region:                        region,
				LaunchType:                    s.LaunchType,
				DesiredCount:                  s.DesiredCount,
				RunningCount:                  s.RunningCount,
				CircuitBreakerEnabled:         s.CircuitBreakerEnabled,
				CircuitBreakerRollback:        s.CircuitBreakerRollback,
				MinimumHealthyPercent:         s.MinimumHealthyPercent,
				MaximumPercent:                s.MaximumPercent,
				AssignsPublicIP:               s.AssignsPublicIP,
				SubnetCount:                   s.SubnetCount,
				LoadBalanced:                  s.LoadBalanced,
				HealthCheckGracePeriodSeconds: s.HealthCheckGracePeriodSeconds,
				ScalingUnresolved:             scalingErr != nil,
			}
			if sc, ok := byService[s.Cluster+"/"+s.Name]; ok {
				row.AutoScaled = true
				row.MinCapacity = sc.MinCapacity
				row.MaxCapacity = sc.MaxCapacity
				row.ScalingPolicyTypes = sc.PolicyTypes
				row.ScalingMetrics = sc.Metrics
			}
			out.Services = append(out.Services, row)
		}
	}
	return out, nil
}

func scalingByService(scaling []aws.ECSServiceScaling) map[string]aws.ECSServiceScaling {
	out := make(map[string]aws.ECSServiceScaling, len(scaling))
	for _, s := range scaling {
		out[s.Cluster+"/"+s.Service] = s
	}
	return out
}

// aggregateECS reduces a region's services and scaling registrations to the
// capacity findings.
func aggregateECS(services []aws.ECSService, scaling []aws.ECSServiceScaling, scalingResolved bool) *ECSMetrics {
	out := &ECSMetrics{ServiceCount: len(services)}
	byService := scalingByService(scaling)

	clusters := map[string]bool{}
	for _, s := range services {
		clusters[s.Cluster] = true

		if s.LaunchType == "FARGATE" {
			out.FargateServiceCount++
		}
		if s.CircuitBreakerEnabled {
			out.ServicesWithCircuitBreakerCount++
		}
		if s.AssignsPublicIP {
			out.ServicesWithPublicIPCount++
		}
		if s.LoadBalanced {
			out.LoadBalancedServiceCount++
		}

		if !scalingResolved {
			out.ScalingUnresolvedServiceCount++
			continue
		}

		sc, scaled := byService[s.Cluster+"/"+s.Name]
		floor := s.DesiredCount
		if scaled {
			out.ServicesWithAutoscalingCount++
			if len(sc.PolicyTypes) > 0 {
				// The chain complete: capacity bounds registered and a policy
				// that actually moves the service between them.
				out.ServicesWithScalingPolicyCount++
			}
			floor = sc.MinCapacity
		}
		// One task is a categorical boundary, not a tuned threshold: a floor of
		// one means zero redundancy while anything above it means some.
		if floor <= 1 {
			out.SingleTaskServiceCount++
		}
	}
	out.ClusterCount = len(clusters)
	return out
}

// mergeECSMetrics combines per-region results. Aggregates sum; audit rows
// concatenate.
func mergeECSMetrics(a, b ECSMetrics) ECSMetrics {
	return ECSMetrics{
		ClusterCount:                    a.ClusterCount + b.ClusterCount,
		ServiceCount:                    a.ServiceCount + b.ServiceCount,
		FargateServiceCount:             a.FargateServiceCount + b.FargateServiceCount,
		ServicesWithAutoscalingCount:    a.ServicesWithAutoscalingCount + b.ServicesWithAutoscalingCount,
		ServicesWithScalingPolicyCount:  a.ServicesWithScalingPolicyCount + b.ServicesWithScalingPolicyCount,
		SingleTaskServiceCount:          a.SingleTaskServiceCount + b.SingleTaskServiceCount,
		ServicesWithCircuitBreakerCount: a.ServicesWithCircuitBreakerCount + b.ServicesWithCircuitBreakerCount,
		ServicesWithPublicIPCount:       a.ServicesWithPublicIPCount + b.ServicesWithPublicIPCount,
		LoadBalancedServiceCount:        a.LoadBalancedServiceCount + b.LoadBalancedServiceCount,
		ScalingUnresolvedServiceCount:   a.ScalingUnresolvedServiceCount + b.ScalingUnresolvedServiceCount,
		Services:                        append(append([]ECSServiceRow(nil), a.Services...), b.Services...),
	}
}
