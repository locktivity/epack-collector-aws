package collector

import (
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

func alb(scheme string, listeners ...aws.LoadBalancerListener) aws.LoadBalancer {
	return aws.LoadBalancer{Type: "application", Scheme: scheme, Listeners: listeners}
}

func TestAggregateLoadBalancers(t *testing.T) {
	httpForward := aws.LoadBalancerListener{Port: 80, Protocol: "HTTP"}
	httpRedirect := aws.LoadBalancerListener{Port: 80, Protocol: "HTTP", RedirectsToHTTPS: true}
	https := aws.LoadBalancerListener{Port: 443, Protocol: "HTTPS", SSLPolicy: "ELBSecurityPolicy-TLS13-1-2-2021-06"}

	t.Run("redirecting ALB is clean, forwarding ALB is plaintext", func(t *testing.T) {
		got := aggregateLoadBalancers([]aws.LoadBalancer{
			alb("internet-facing", httpRedirect, https),
			alb("internet-facing", httpForward, https),
			alb("internal", httpForward, https),
		})

		if got.ALBCount != 3 {
			t.Errorf("ALBCount = %d, want 3", got.ALBCount)
		}
		if got.ALBsServingPlaintextCount != 2 {
			t.Errorf("ALBsServingPlaintextCount = %d, want 2", got.ALBsServingPlaintextCount)
		}
		if got.InternetFacingALBsServingPlaintextCount != 1 {
			t.Errorf("InternetFacingALBsServingPlaintextCount = %d, want 1", got.InternetFacingALBsServingPlaintextCount)
		}
		if got.TLSListenersByPolicy["ELBSecurityPolicy-TLS13-1-2-2021-06"] != 3 {
			t.Errorf("TLSListenersByPolicy = %v, want the policy counted 3 times", got.TLSListenersByPolicy)
		}
	})

	t.Run("an ALB with no HTTPS listener is its own finding", func(t *testing.T) {
		got := aggregateLoadBalancers([]aws.LoadBalancer{alb("internal", httpForward)})

		if got.ALBsWithoutHTTPSListenerCount != 1 {
			t.Errorf("ALBsWithoutHTTPSListenerCount = %d, want 1", got.ALBsWithoutHTTPSListenerCount)
		}
	})

	// A load balancer whose listeners could not be read is neither plaintext
	// nor proven clean, so it lands in no finding except the unresolved count.
	t.Run("unresolved listeners contribute to no finding", func(t *testing.T) {
		got := aggregateLoadBalancers([]aws.LoadBalancer{
			{Type: "application", Scheme: "internet-facing", ListenersUnresolved: true},
		})

		if got.ListenersUnresolvedCount != 1 {
			t.Errorf("ListenersUnresolvedCount = %d, want 1", got.ListenersUnresolvedCount)
		}
		if got.ALBsServingPlaintextCount != 0 {
			t.Errorf("ALBsServingPlaintextCount = %d, want 0 for an unreadable ALB", got.ALBsServingPlaintextCount)
		}
		if got.ALBsWithoutHTTPSListenerCount != 0 {
			t.Errorf("ALBsWithoutHTTPSListenerCount = %d, want 0 for an unreadable ALB", got.ALBsWithoutHTTPSListenerCount)
		}
	})

	t.Run("NLB listeners split into terminating and pass-through", func(t *testing.T) {
		got := aggregateLoadBalancers([]aws.LoadBalancer{{
			Type: "network",
			Listeners: []aws.LoadBalancerListener{
				{Protocol: "TLS", SSLPolicy: "ELBSecurityPolicy-TLS13-1-2-2021-06"},
				{Protocol: "TCP"},
				{Protocol: "UDP"},
			},
		}})

		if got.NLBTLSListenerCount != 1 {
			t.Errorf("NLBTLSListenerCount = %d, want 1", got.NLBTLSListenerCount)
		}
		if got.NLBTCPPassthroughListenerCount != 2 {
			t.Errorf("NLBTCPPassthroughListenerCount = %d, want 2", got.NLBTCPPassthroughListenerCount)
		}
	})
}

func TestMergeLoadBalancerMetricsSumsAcrossRegions(t *testing.T) {
	a := LoadBalancerMetrics{
		LoadBalancerCount:         2,
		ALBsServingPlaintextCount: 1,
		TLSListenersByPolicy:      map[string]int{"ELBSecurityPolicy-2016-08": 1},
		LoadBalancers:             []LoadBalancerRow{{Name: "a", Region: "us-east-1"}},
	}
	b := LoadBalancerMetrics{
		LoadBalancerCount:        1,
		ListenersUnresolvedCount: 1,
		TLSListenersByPolicy:     map[string]int{"ELBSecurityPolicy-2016-08": 2, "ELBSecurityPolicy-TLS13-1-2-2021-06": 1},
		LoadBalancers:            []LoadBalancerRow{{Name: "b", Region: "eu-west-1"}},
	}

	got := mergeLoadBalancerMetrics(a, b)

	if got.LoadBalancerCount != 3 || got.ALBsServingPlaintextCount != 1 || got.ListenersUnresolvedCount != 1 {
		t.Errorf("counts = %+v, want sums preserved", got)
	}
	if got.TLSListenersByPolicy["ELBSecurityPolicy-2016-08"] != 3 {
		t.Errorf("TLSListenersByPolicy = %v, want the shared policy summed to 3", got.TLSListenersByPolicy)
	}
	if len(got.LoadBalancers) != 2 {
		t.Errorf("len(LoadBalancers) = %d, want 2", len(got.LoadBalancers))
	}
}

// A single zone is no zone redundancy. ALBs cannot be single-zone by AWS rule,
// so this is in practice the NLB case.
func TestAggregateLoadBalancersCountsSingleZone(t *testing.T) {
	got := aggregateLoadBalancers([]aws.LoadBalancer{
		{Type: "network", AvailabilityZoneCount: 1},
		{Type: "application", Scheme: "internal", AvailabilityZoneCount: 2},
	})

	if got.SingleZoneLoadBalancerCount != 1 {
		t.Fatalf("SingleZoneLoadBalancerCount = %d, want 1", got.SingleZoneLoadBalancerCount)
	}
}
