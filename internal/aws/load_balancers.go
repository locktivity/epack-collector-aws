package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

// LoadBalancer is an elastic load balancer and its listeners' transport
// configuration.
type LoadBalancer struct {
	Name   string
	Type   string // application, network, gateway
	Scheme string // internet-facing, internal

	// AvailabilityZoneCount is how many zones the load balancer spans. One
	// zone means no zone redundancy; ALBs require at least two by AWS rule,
	// so the single-zone case is in practice a network load balancer.
	AvailabilityZoneCount int

	Listeners []LoadBalancerListener

	// ListenersUnresolved marks a load balancer whose listeners could not be
	// read. It stays in the result so its transport posture can be reported as
	// unproven rather than silently dropped.
	ListenersUnresolved bool
}

// LoadBalancerListener is one listener's transport configuration.
type LoadBalancerListener struct {
	Port             int32
	Protocol         string
	SSLPolicy        string
	RedirectsToHTTPS bool
}

// ListLoadBalancers returns the region's load balancers with their listeners.
// One DescribeListeners call per load balancer; the fan-out is bounded by fleet
// size, which is dozens at most rather than the thousands a snapshot listing
// can reach.
func (c *AWSClient) ListLoadBalancers(ctx context.Context, region string) ([]LoadBalancer, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := elbv2.NewFromConfig(cfg)

	var lbs []LoadBalancer
	paginator := elbv2.NewDescribeLoadBalancersPaginator(client, &elbv2.DescribeLoadBalancersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing load balancers in %s: %w", region, err)
		}
		for _, lb := range page.LoadBalancers {
			row := LoadBalancer{
				Name:                  aws.ToString(lb.LoadBalancerName),
				Type:                  string(lb.Type),
				Scheme:                string(lb.Scheme),
				AvailabilityZoneCount: len(lb.AvailabilityZones),
			}
			listeners, err := c.listListeners(ctx, client, aws.ToString(lb.LoadBalancerArn), region)
			if err != nil {
				row.ListenersUnresolved = true
			} else {
				row.Listeners = listeners
			}
			lbs = append(lbs, row)
		}
	}
	return lbs, nil
}

func (c *AWSClient) listListeners(ctx context.Context, client *elbv2.Client, lbARN, region string) ([]LoadBalancerListener, error) {
	var out []LoadBalancerListener
	paginator := elbv2.NewDescribeListenersPaginator(client, &elbv2.DescribeListenersInput{
		LoadBalancerArn: aws.String(lbARN),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing listeners in %s: %w", region, err)
		}
		for _, l := range page.Listeners {
			out = append(out, LoadBalancerListener{
				Port:             aws.ToInt32(l.Port),
				Protocol:         string(l.Protocol),
				SSLPolicy:        aws.ToString(l.SslPolicy),
				RedirectsToHTTPS: redirectsToHTTPS(l.DefaultActions),
			})
		}
	}
	return out, nil
}

// redirectsToHTTPS reports whether a listener's default action redirects to
// HTTPS. The redirect protocol can be the literal "#{protocol}", which keeps
// the request's original scheme and therefore enforces nothing, so only an
// exact HTTPS counts. Listener rules beyond the default action are not
// inspected.
func redirectsToHTTPS(actions []elbv2types.Action) bool {
	for _, a := range actions {
		if a.Type != elbv2types.ActionTypeEnumRedirect || a.RedirectConfig == nil {
			continue
		}
		if aws.ToString(a.RedirectConfig.Protocol) == "HTTPS" {
			return true
		}
	}
	return false
}

// TargetGroup is a target group's health check configuration: how the load
// balancer decides a backend is dead.
type TargetGroup struct {
	Name                       string
	Protocol                   string
	TargetType                 string
	HealthCheckEnabled         bool
	HealthCheckIntervalSeconds int32
	HealthyThresholdCount      int32
	UnhealthyThresholdCount    int32
	Attached                   bool
}

// ListTargetGroups returns the region's target groups.
func (c *AWSClient) ListTargetGroups(ctx context.Context, region string) ([]TargetGroup, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := elbv2.NewFromConfig(cfg)

	var groups []TargetGroup
	paginator := elbv2.NewDescribeTargetGroupsPaginator(client, &elbv2.DescribeTargetGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing target groups in %s: %w", region, err)
		}
		for _, tg := range page.TargetGroups {
			groups = append(groups, TargetGroup{
				Name:                       aws.ToString(tg.TargetGroupName),
				Protocol:                   string(tg.Protocol),
				TargetType:                 string(tg.TargetType),
				HealthCheckEnabled:         aws.ToBool(tg.HealthCheckEnabled),
				HealthCheckIntervalSeconds: aws.ToInt32(tg.HealthCheckIntervalSeconds),
				HealthyThresholdCount:      aws.ToInt32(tg.HealthyThresholdCount),
				UnhealthyThresholdCount:    aws.ToInt32(tg.UnhealthyThresholdCount),
				Attached:                   len(tg.LoadBalancerArns) > 0,
			})
		}
	}
	return groups, nil
}
