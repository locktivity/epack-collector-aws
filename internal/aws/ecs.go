package aws

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	appautoscaling "github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"
	appautoscalingtypes "github.com/aws/aws-sdk-go-v2/service/applicationautoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/locktivity/epack/componentsdk"
)

// ECSService is one service's capacity and deployment posture. Task
// definitions are deliberately never fetched: container definitions embed
// environment variables, which routinely hold credentials.
type ECSService struct {
	Cluster    string
	Name       string
	LaunchType string

	// CapacityProviders names the providers of the service's capacity
	// provider strategy, which DescribeServices returns in place of a launch
	// type.
	CapacityProviders []string

	// Fargate is whether the service runs on Fargate: its launch type is
	// FARGATE, or its strategy uses the FARGATE or FARGATE_SPOT provider.
	// FargateErr is why it is unknown.
	Fargate    bool
	FargateErr error

	DesiredCount           int32
	RunningCount           int32
	CircuitBreakerEnabled  bool
	CircuitBreakerRollback bool
	MinimumHealthyPercent  *int32 // nil when the service has no deployment configuration
	MaximumPercent         int32
	AssignsPublicIP        bool
	SubnetCount            int
	LoadBalanced           bool

	// EnableExecuteCommand is whether tasks this service launches accept ECS
	// Exec, which opens an interactive shell in a running container.
	EnableExecuteCommand bool

	// HealthCheckGracePeriodSeconds is nil when DescribeServices leaves it
	// out.
	HealthCheckGracePeriodSeconds *int32
}

// ECSServiceScaling is a service's Application Auto Scaling registration:
// capacity bounds plus the policies that move it.
type ECSServiceScaling struct {
	Cluster     string
	Service     string
	MinCapacity int32
	MaxCapacity int32
	PolicyTypes []string
	Metrics     []string

	// PolicyScales is true when one of the policies can change the
	// service's capacity. No policy scales when MinCapacity equals
	// MaxCapacity. A predictive policy scales only in ForecastAndScale mode.
	// A target tracking or step scaling policy does not scale while dynamic
	// scaling in and out is suspended on the target. A step scaling policy
	// also needs an alarm that invokes it.
	PolicyScales bool

	// dynamicScalingSuspended is true when the target's SuspendedState has
	// dynamic scaling suspended in both directions.
	dynamicScalingSuspended bool
}

// ListECSServices returns the number of the region's clusters and their
// services. DescribeServices accepts ten services per call, so the fan-out
// is one list per cluster plus one describe per ten services.
func (c *AWSClient) ListECSServices(ctx context.Context, region string) (int, []ECSService, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := ecs.NewFromConfig(cfg)

	var clusters []string
	clusterPaginator := ecs.NewListClustersPaginator(client, &ecs.ListClustersInput{})
	for clusterPaginator.HasMorePages() {
		page, err := clusterPaginator.NextPage(ctx)
		if err != nil {
			return 0, nil, fmt.Errorf("listing ECS clusters in %s: %w", region, err)
		}
		clusters = append(clusters, page.ClusterArns...)
	}

	var services []ECSService
	for _, clusterARN := range clusters {
		clusterName := nameFromARN(clusterARN)

		var serviceARNs []string
		servicePaginator := ecs.NewListServicesPaginator(client, &ecs.ListServicesInput{Cluster: aws.String(clusterARN)})
		for servicePaginator.HasMorePages() {
			page, err := servicePaginator.NextPage(ctx)
			if err != nil {
				return 0, nil, fmt.Errorf("listing ECS services in %s: %w", region, err)
			}
			serviceARNs = append(serviceARNs, page.ServiceArns...)
		}

		for start := 0; start < len(serviceARNs); start += 10 {
			end := min(start+10, len(serviceARNs))
			out, err := client.DescribeServices(ctx, &ecs.DescribeServicesInput{
				Cluster:  aws.String(clusterARN),
				Services: serviceARNs[start:end],
			})
			if err != nil {
				return 0, nil, fmt.Errorf("describing ECS services in %s: %w", region, err)
			}
			if len(out.Failures) > 0 {
				return 0, nil, inResponse(out.ResultMetadata, componentsdk.CodeError(componentsdk.CodeVendorError, fmt.Errorf("describing ECS services in %s: %d services could not be described: %s", region, len(out.Failures), aws.ToString(out.Failures[0].Reason))))
			}
			// ECS answers each service asked for, as a service or a failure.
			if len(out.Services) < end-start {
				return 0, nil, errIncomplete(out.ResultMetadata, "describing ECS services in "+region, "services", len(out.Services), end-start)
			}
			for _, s := range out.Services {
				service := ECSService{
					Cluster:              clusterName,
					Name:                 aws.ToString(s.ServiceName),
					LaunchType:           string(s.LaunchType),
					DesiredCount:         s.DesiredCount,
					RunningCount:         s.RunningCount,
					LoadBalanced:         len(s.LoadBalancers) > 0,
					EnableExecuteCommand: s.EnableExecuteCommand,

					HealthCheckGracePeriodSeconds: s.HealthCheckGracePeriodSeconds,
				}
				for _, p := range s.CapacityProviderStrategy {
					service.CapacityProviders = append(service.CapacityProviders, aws.ToString(p.CapacityProvider))
				}
				switch {
				case s.LaunchType != "":
					service.Fargate = s.LaunchType == ecstypes.LaunchTypeFargate
				case len(service.CapacityProviders) > 0:
					// ECS rejects a strategy that mixes Fargate providers
					// with others, so one Fargate provider makes them all.
					service.Fargate = slices.ContainsFunc(service.CapacityProviders, isFargateProvider)
				default:
					service.FargateErr = errMissing(out.ResultMetadata, "describing ECS services in "+region, "launchType or capacityProviderStrategy for a service")
				}
				if s.DeploymentConfiguration != nil {
					service.MinimumHealthyPercent = s.DeploymentConfiguration.MinimumHealthyPercent
					service.MaximumPercent = aws.ToInt32(s.DeploymentConfiguration.MaximumPercent)
					if cb := s.DeploymentConfiguration.DeploymentCircuitBreaker; cb != nil {
						service.CircuitBreakerEnabled = cb.Enable
						service.CircuitBreakerRollback = cb.Rollback
					}
				}
				if s.NetworkConfiguration != nil && s.NetworkConfiguration.AwsvpcConfiguration != nil {
					vpc := s.NetworkConfiguration.AwsvpcConfiguration
					service.AssignsPublicIP = string(vpc.AssignPublicIp) == "ENABLED"
					service.SubnetCount = len(vpc.Subnets)
				}
				services = append(services, service)
			}
		}
	}
	return len(clusters), services, nil
}

// isFargateProvider reports whether a capacity provider is one of the two
// AWS provides for Fargate.
func isFargateProvider(name string) bool {
	return name == "FARGATE" || name == "FARGATE_SPOT"
}

// ListECSServiceScaling returns the region's Application Auto Scaling state for
// ECS services: registered capacity bounds joined with their policies.
func (c *AWSClient) ListECSServiceScaling(ctx context.Context, region string) ([]ECSServiceScaling, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := appautoscaling.NewFromConfig(cfg)

	byResource := map[string]*ECSServiceScaling{}
	targetPaginator := appautoscaling.NewDescribeScalableTargetsPaginator(client, &appautoscaling.DescribeScalableTargetsInput{
		ServiceNamespace: appautoscalingtypes.ServiceNamespaceEcs,
	})
	for targetPaginator.HasMorePages() {
		page, err := targetPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing scalable targets in %s: %w", region, err)
		}
		for _, target := range page.ScalableTargets {
			resource := aws.ToString(target.ResourceId)
			cluster, service, ok := splitECSResourceID(resource)
			if !ok {
				continue
			}
			suspended := target.SuspendedState
			byResource[resource] = &ECSServiceScaling{
				Cluster:     cluster,
				Service:     service,
				MinCapacity: aws.ToInt32(target.MinCapacity),
				MaxCapacity: aws.ToInt32(target.MaxCapacity),
				dynamicScalingSuspended: suspended != nil &&
					aws.ToBool(suspended.DynamicScalingInSuspended) && aws.ToBool(suspended.DynamicScalingOutSuspended),
			}
		}
	}

	policyPaginator := appautoscaling.NewDescribeScalingPoliciesPaginator(client, &appautoscaling.DescribeScalingPoliciesInput{
		ServiceNamespace: appautoscalingtypes.ServiceNamespaceEcs,
	})
	for policyPaginator.HasMorePages() {
		page, err := policyPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing scaling policies in %s: %w", region, err)
		}
		for _, policy := range page.ScalingPolicies {
			scaling, ok := byResource[aws.ToString(policy.ResourceId)]
			if !ok {
				continue
			}
			scaling.PolicyTypes = append(scaling.PolicyTypes, string(policy.PolicyType))
			// A policy never scales outside the target's range, so on a
			// range whose minimum equals its maximum no policy moves the
			// service.
			roomToScale := scaling.MinCapacity < scaling.MaxCapacity
			switch policy.PolicyType {
			case appautoscalingtypes.PolicyTypePredictiveScaling:
				// The mode defaults to ForecastOnly, which forecasts and
				// does not scale.
				if p := policy.PredictiveScalingPolicyConfiguration; p != nil && p.Mode == appautoscalingtypes.PredictiveScalingModeForecastAndScale && roomToScale {
					scaling.PolicyScales = true
				}
			case appautoscalingtypes.PolicyTypeTargetTrackingScaling:
				if !scaling.dynamicScalingSuspended && roomToScale {
					scaling.PolicyScales = true
				}
			case appautoscalingtypes.PolicyTypeStepScaling:
				// A step scaling policy runs only when a CloudWatch alarm
				// invokes it.
				if !scaling.dynamicScalingSuspended && roomToScale && len(policy.Alarms) > 0 {
					scaling.PolicyScales = true
				}
			default:
				if roomToScale {
					scaling.PolicyScales = true
				}
			}
			if tt := policy.TargetTrackingScalingPolicyConfiguration; tt != nil {
				if tt.PredefinedMetricSpecification != nil {
					scaling.Metrics = append(scaling.Metrics, string(tt.PredefinedMetricSpecification.PredefinedMetricType))
				}
				if tt.CustomizedMetricSpecification != nil {
					scaling.Metrics = append(scaling.Metrics, customizedMetricNames(tt.CustomizedMetricSpecification)...)
				}
			}
		}
	}

	out := make([]ECSServiceScaling, 0, len(byResource))
	for _, scaling := range byResource {
		out = append(out, *scaling)
	}
	return out, nil
}

// splitECSResourceID parses "service/<cluster>/<service>".
func splitECSResourceID(resource string) (cluster, service string, ok bool) {
	parts := strings.Split(resource, "/")
	if len(parts) != 3 || parts[0] != "service" {
		return "", "", false
	}
	return parts[1], parts[2], true
}

func nameFromARN(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

// customizedMetricNames names the metrics a customized target tracking metric
// reads: its MetricName, or for one built with metric math, the metric of each
// query that reads one.
func customizedMetricNames(spec *appautoscalingtypes.CustomizedMetricSpecification) []string {
	if name := aws.ToString(spec.MetricName); name != "" {
		return []string{name}
	}
	var names []string
	for _, q := range spec.Metrics {
		if q.MetricStat == nil || q.MetricStat.Metric == nil {
			continue
		}
		if name := aws.ToString(q.MetricStat.Metric.MetricName); name != "" && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names
}
