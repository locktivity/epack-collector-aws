package aws

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

// The redirect protocol can be the literal "#{protocol}", which preserves the
// request's scheme and enforces nothing. Counting it as a redirect to HTTPS
// would report a plaintext listener as safe.
func TestRedirectsToHTTPS(t *testing.T) {
	redirect := func(protocol string) elbv2types.Action {
		return elbv2types.Action{
			Type:           elbv2types.ActionTypeEnumRedirect,
			RedirectConfig: &elbv2types.RedirectActionConfig{Protocol: aws.String(protocol)},
		}
	}
	forward := elbv2types.Action{Type: elbv2types.ActionTypeEnumForward}

	tests := []struct {
		name    string
		actions []elbv2types.Action
		want    bool
	}{
		{name: "redirect to HTTPS", actions: []elbv2types.Action{redirect("HTTPS")}, want: true},
		{name: "forward serves the request in plaintext", actions: []elbv2types.Action{forward}, want: false},
		{name: "scheme-preserving redirect enforces nothing", actions: []elbv2types.Action{redirect("#{protocol}")}, want: false},
		{name: "redirect with no config", actions: []elbv2types.Action{{Type: elbv2types.ActionTypeEnumRedirect}}, want: false},
		{name: "no actions", actions: nil, want: false},
		{name: "redirect after a forward still counts", actions: []elbv2types.Action{forward, redirect("HTTPS")}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redirectsToHTTPS(tt.actions); got != tt.want {
				t.Fatalf("redirectsToHTTPS() = %v, want %v", got, tt.want)
			}
		})
	}
}
