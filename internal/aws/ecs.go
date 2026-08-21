package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	appautoscaling "github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"
	appautoscalingtypes "github.com/aws/aws-sdk-go-v2/service/applicationautoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
)

// ECSService is one service's capacity and deployment posture. Task
// definitions are deliberately never fetched: container definitions embed
// environment variables, which routinely hold credentials.
type ECSService struct {
	Cluster                string
	Name                   string
	LaunchType             string
	DesiredCount           int32
	RunningCount           int32
	CircuitBreakerEnabled  bool
	CircuitBreakerRollback bool
	MinimumHealthyPercent  int32
	MaximumPercent         int32
	AssignsPublicIP        bool
	SubnetCount            int
	LoadBalanced           bool

	// EnableExecuteCommand is whether tasks this service launches accept ECS
	// Exec, which opens an interactive shell in a running container.
	EnableExecuteCommand bool

	HealthCheckGracePeriodSeconds int32
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
}

// ListECSServices returns the region's services across every cluster.
// DescribeServices accepts ten services per call, so the fan-out is one list
// per cluster plus one describe per ten services.
func (c *AWSClient) ListECSServices(ctx context.Context, region string) ([]ECSService, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := ecs.NewFromConfig(cfg)

	var clusters []string
	clusterPaginator := ecs.NewListClustersPaginator(client, &ecs.ListClustersInput{})
	for clusterPaginator.HasMorePages() {
		page, err := clusterPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing ECS clusters in %s: %w", region, err)
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
				return nil, fmt.Errorf("listing ECS services in %s: %w", region, err)
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
				return nil, fmt.Errorf("describing ECS services in %s: %w", region, err)
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

					HealthCheckGracePeriodSeconds: aws.ToInt32(s.HealthCheckGracePeriodSeconds),
				}
				if s.DeploymentConfiguration != nil {
					service.MinimumHealthyPercent = aws.ToInt32(s.DeploymentConfiguration.MinimumHealthyPercent)
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
	return services, nil
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
			byResource[resource] = &ECSServiceScaling{
				Cluster:     cluster,
				Service:     service,
				MinCapacity: aws.ToInt32(target.MinCapacity),
				MaxCapacity: aws.ToInt32(target.MaxCapacity),
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
			if tt := policy.TargetTrackingScalingPolicyConfiguration; tt != nil {
				if tt.PredefinedMetricSpecification != nil {
					scaling.Metrics = append(scaling.Metrics, string(tt.PredefinedMetricSpecification.PredefinedMetricType))
				}
				if tt.CustomizedMetricSpecification != nil {
					scaling.Metrics = append(scaling.Metrics, aws.ToString(tt.CustomizedMetricSpecification.MetricName))
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
