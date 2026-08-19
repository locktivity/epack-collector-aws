package collector

import (
	"context"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// collectLoadBalancerMetrics collects load balancer transport enforcement for a
// region: which hops force TLS and which accept plaintext.
func (c *Collector) collectLoadBalancerMetrics(ctx context.Context, client *aws.AWSClient, region, accountID string, level componentsdk.Level) (*LoadBalancerMetrics, error) {
	lbs, err := client.ListLoadBalancers(ctx, region)
	if err != nil {
		return nil, err
	}

	for _, lb := range lbs {
		if lb.ListenersUnresolved {
			c.warn("account %s region %s: failed to read listeners for load balancer %s; its transport posture is unproven", accountID, region, lb.Name)
		}
	}

	out := aggregateLoadBalancers(lbs)

	groups, tgErr := client.ListTargetGroups(ctx, region)
	if tgErr != nil {
		c.warn("account %s region %s: failed to list target groups: %v", accountID, region, tgErr)
		out.TargetGroupListingFailedRegionCount = 1
	} else {
		out.TargetGroupCount = len(groups)
		for _, tg := range groups {
			if !tg.HealthCheckEnabled {
				out.TargetGroupsWithoutHealthCheckCount++
			}
		}
	}

	if level.AtLeast(componentsdk.LevelAudit) {
		for _, lb := range lbs {
			out.LoadBalancers = append(out.LoadBalancers, loadBalancerToRow(lb, region))
		}
		for _, tg := range groups {
			out.TargetGroups = append(out.TargetGroups, TargetGroupRow{
				Name:                       tg.Name,
				Region:                     region,
				Protocol:                   tg.Protocol,
				TargetType:                 tg.TargetType,
				HealthCheckEnabled:         tg.HealthCheckEnabled,
				HealthCheckIntervalSeconds: tg.HealthCheckIntervalSeconds,
				HealthyThresholdCount:      tg.HealthyThresholdCount,
				UnhealthyThresholdCount:    tg.UnhealthyThresholdCount,
				Attached:                   tg.Attached,
			})
		}
	}
	return out, nil
}

// aggregateLoadBalancers reduces a region's load balancers to the transport
// findings. An unresolved load balancer contributes to no finding in either
// direction: it is neither plaintext nor proven clean.
func aggregateLoadBalancers(lbs []aws.LoadBalancer) *LoadBalancerMetrics {
	out := &LoadBalancerMetrics{LoadBalancerCount: len(lbs)}

	for _, lb := range lbs {
		if lb.ListenersUnresolved {
			out.ListenersUnresolvedCount++
		}
		if lb.AvailabilityZoneCount == 1 {
			out.SingleZoneLoadBalancerCount++
		}

		switch lb.Type {
		case "application":
			out.ALBCount++
			if albServesPlaintext(lb) {
				out.ALBsServingPlaintextCount++
				if lb.Scheme == "internet-facing" {
					out.InternetFacingALBsServingPlaintextCount++
				}
			}
			if !lb.ListenersUnresolved && !hasListenerWithProtocol(lb, "HTTPS") {
				out.ALBsWithoutHTTPSListenerCount++
			}
		case "network":
			out.NLBCount++
			for _, l := range lb.Listeners {
				switch l.Protocol {
				case "TLS":
					out.NLBTLSListenerCount++
				case "TCP", "UDP", "TCP_UDP":
					out.NLBTCPPassthroughListenerCount++
				}
			}
		}

		for _, l := range lb.Listeners {
			if l.SSLPolicy == "" {
				continue
			}
			if out.TLSListenersByPolicy == nil {
				out.TLSListenersByPolicy = map[string]int{}
			}
			out.TLSListenersByPolicy[l.SSLPolicy]++
		}
	}
	return out
}

// albServesPlaintext reports whether an application load balancer answers HTTP
// with anything other than a redirect to HTTPS, judged by each HTTP listener's
// default action.
func albServesPlaintext(lb aws.LoadBalancer) bool {
	for _, l := range lb.Listeners {
		if l.Protocol == "HTTP" && !l.RedirectsToHTTPS {
			return true
		}
	}
	return false
}

func hasListenerWithProtocol(lb aws.LoadBalancer, protocol string) bool {
	for _, l := range lb.Listeners {
		if l.Protocol == protocol {
			return true
		}
	}
	return false
}

func loadBalancerToRow(lb aws.LoadBalancer, region string) LoadBalancerRow {
	row := LoadBalancerRow{
		Name:                  lb.Name,
		Region:                region,
		Type:                  lb.Type,
		Scheme:                lb.Scheme,
		AvailabilityZoneCount: lb.AvailabilityZoneCount,
		ListenersUnresolved:   lb.ListenersUnresolved,
	}
	for _, l := range lb.Listeners {
		row.Listeners = append(row.Listeners, ListenerRow{
			Port:             l.Port,
			Protocol:         l.Protocol,
			SSLPolicy:        l.SSLPolicy,
			RedirectsToHTTPS: l.RedirectsToHTTPS,
		})
	}
	return row
}

// mergeLoadBalancerMetrics combines per-region results. Aggregates sum; audit
// rows concatenate.
func mergeLoadBalancerMetrics(a, b LoadBalancerMetrics) LoadBalancerMetrics {
	merged := LoadBalancerMetrics{
		LoadBalancerCount:                       a.LoadBalancerCount + b.LoadBalancerCount,
		ALBCount:                                a.ALBCount + b.ALBCount,
		ALBsServingPlaintextCount:               a.ALBsServingPlaintextCount + b.ALBsServingPlaintextCount,
		InternetFacingALBsServingPlaintextCount: a.InternetFacingALBsServingPlaintextCount + b.InternetFacingALBsServingPlaintextCount,
		ALBsWithoutHTTPSListenerCount:           a.ALBsWithoutHTTPSListenerCount + b.ALBsWithoutHTTPSListenerCount,
		NLBCount:                                a.NLBCount + b.NLBCount,
		NLBTLSListenerCount:                     a.NLBTLSListenerCount + b.NLBTLSListenerCount,
		NLBTCPPassthroughListenerCount:          a.NLBTCPPassthroughListenerCount + b.NLBTCPPassthroughListenerCount,
		ListenersUnresolvedCount:                a.ListenersUnresolvedCount + b.ListenersUnresolvedCount,
		SingleZoneLoadBalancerCount:             a.SingleZoneLoadBalancerCount + b.SingleZoneLoadBalancerCount,
		TargetGroupCount:                        a.TargetGroupCount + b.TargetGroupCount,
		TargetGroupsWithoutHealthCheckCount:     a.TargetGroupsWithoutHealthCheckCount + b.TargetGroupsWithoutHealthCheckCount,
		TargetGroupListingFailedRegionCount:     a.TargetGroupListingFailedRegionCount + b.TargetGroupListingFailedRegionCount,
		TargetGroups:                            append(append([]TargetGroupRow(nil), a.TargetGroups...), b.TargetGroups...),
		LoadBalancers:                           append(append([]LoadBalancerRow(nil), a.LoadBalancers...), b.LoadBalancers...),
	}
	for _, src := range []map[string]int{a.TLSListenersByPolicy, b.TLSListenersByPolicy} {
		for policy, count := range src {
			if merged.TLSListenersByPolicy == nil {
				merged.TLSListenersByPolicy = map[string]int{}
			}
			merged.TLSListenersByPolicy[policy] += count
		}
	}
	return merged
}
