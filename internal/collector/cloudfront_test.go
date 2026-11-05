package collector

import (
	"net/http"
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

func TestAggregateCloudFrontDistributions(t *testing.T) {
	t.Run("a path behavior allowing plaintext marks the distribution even when the default redirects", func(t *testing.T) {
		got := aggregateCloudFrontDistributions([]aws.CloudFrontDistribution{{
			Enabled:                true,
			ViewerProtocolPolicies: []string{"redirect-to-https", "allow-all"},
		}})

		if got.DistributionsAllowingPlaintextViewersCount != 1 {
			t.Errorf("DistributionsAllowingPlaintextViewersCount = %d, want 1", got.DistributionsAllowingPlaintextViewersCount)
		}
	})

	t.Run("redirect and https-only both count as enforced", func(t *testing.T) {
		got := aggregateCloudFrontDistributions([]aws.CloudFrontDistribution{{
			Enabled:                true,
			ViewerProtocolPolicies: []string{"redirect-to-https", "https-only"},
			MinimumProtocolVersion: "TLSv1.2_2021",
		}})

		if got.DistributionsAllowingPlaintextViewersCount != 0 {
			t.Errorf("DistributionsAllowingPlaintextViewersCount = %d, want 0", got.DistributionsAllowingPlaintextViewersCount)
		}
		if got.DistributionsByMinimumTLS["TLSv1.2_2021"] != 1 {
			t.Errorf("DistributionsByMinimumTLS = %v, want the version counted", got.DistributionsByMinimumTLS)
		}
	})

	// A switched-off distribution serves nothing, so its plaintext policy is
	// latent rather than live. It must appear in the disabled count and no
	// finding, or the pack would report exposure that cannot occur.
	t.Run("disabled distributions are counted and excluded from findings", func(t *testing.T) {
		got := aggregateCloudFrontDistributions([]aws.CloudFrontDistribution{{
			Enabled:                false,
			ViewerProtocolPolicies: []string{"allow-all"},
			OriginsHTTPOnly:        1,
		}})

		if got.DisabledDistributionCount != 1 {
			t.Errorf("DisabledDistributionCount = %d, want 1", got.DisabledDistributionCount)
		}
		if got.DistributionsAllowingPlaintextViewersCount != 0 || got.DistributionsWithHTTPOnlyOriginCount != 0 {
			t.Errorf("findings = %d and %d, want 0 for a disabled distribution", got.DistributionsAllowingPlaintextViewersCount, got.DistributionsWithHTTPOnlyOriginCount)
		}
	})

	t.Run("origin hops are classified only where config declares them", func(t *testing.T) {
		got := aggregateCloudFrontDistributions([]aws.CloudFrontDistribution{{
			Enabled:                true,
			ViewerProtocolPolicies: []string{"https-only"},
			OriginsHTTPOnly:        1,
			OriginsMatchViewer:     1,
			S3OriginCount:          2,
		}})

		if got.DistributionsWithHTTPOnlyOriginCount != 1 {
			t.Errorf("DistributionsWithHTTPOnlyOriginCount = %d, want 1", got.DistributionsWithHTTPOnlyOriginCount)
		}
		if got.DistributionsWithMatchViewerOriginCount != 1 {
			t.Errorf("DistributionsWithMatchViewerOriginCount = %d, want 1", got.DistributionsWithMatchViewerOriginCount)
		}
	})

	t.Run("an empty account is evaluated, not unknown", func(t *testing.T) {
		got := aggregateCloudFrontDistributions(nil)

		if !got.DistributionsEvaluated {
			t.Error("DistributionsEvaluated = false, want true for a successful empty listing")
		}
		if got.DistributionCount != 0 {
			t.Errorf("DistributionCount = %d, want 0", got.DistributionCount)
		}
	})
}

// distributionListWithOrigin answers ListDistributions with one enabled
// distribution whose only origin is origin, an <Origin> element.
func distributionListWithOrigin(origin string) string {
	return "<DistributionList><Marker></Marker><MaxItems>100</MaxItems><IsTruncated>false</IsTruncated><Quantity>1</Quantity><Items><DistributionSummary>" +
		"<Id>E3VPC0000001</Id><ARN>arn:aws:cloudfront::111122223333:distribution/E3VPC0000001</ARN><Status>Deployed</Status>" +
		"<DomainName>d222222abcdef8.cloudfront.net</DomainName><Aliases><Quantity>0</Quantity></Aliases>" +
		"<Origins><Quantity>1</Quantity><Items>" + origin + "</Items></Origins>" +
		"<DefaultCacheBehavior><TargetOriginId>only</TargetOriginId><ViewerProtocolPolicy>redirect-to-https</ViewerProtocolPolicy></DefaultCacheBehavior>" +
		"<ViewerCertificate><MinimumProtocolVersion>TLSv1.2_2021</MinimumProtocolVersion><SSLSupportMethod>sni-only</SSLSupportMethod></ViewerCertificate>" +
		"<Enabled>true</Enabled></DistributionSummary></Items></DistributionList>"
}

// A VPC origin's protocol policy is on the VPC origin resource, which
// GetVpcOrigin reads. When that read fails, the origin counts are left out.
func TestCloudFront_VPCOriginProtocolPolicy(t *testing.T) {
	const (
		listURL      = "https://cloudfront.amazonaws.com/2020-05-31/distribution"
		vpcOriginURL = "https://cloudfront.amazonaws.com/2020-05-31/vpc-origin/vo_internal01"
		path         = "/accounts/0/cloudfront"
	)
	origin := "<Origin><Id>only</Id><DomainName>internal-alb-123.us-east-1.elb.amazonaws.com</DomainName>" +
		"<VpcOriginConfig><VpcOriginId>vo_internal01</VpcOriginId><OriginReadTimeout>30</OriginReadTimeout></VpcOriginConfig></Origin>"
	vpcOrigin := func(policy string) collectortest.Response {
		return restResponse("aws.cloudfront.GetVpcOrigin", http.MethodGet, vpcOriginURL, 0,
			"<VpcOrigin><Id>vo_internal01</Id><Arn>arn:aws:cloudfront::111122223333:vpcorigin/vo_internal01</Arn><Status>Deployed</Status>"+
				"<CreatedTime>2025-01-01T00:00:00Z</CreatedTime><LastModifiedTime>2025-01-01T00:00:00Z</LastModifiedTime>"+
				"<VpcOriginEndpointConfig><Name>internal-alb</Name><Arn>arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/internal/0123456789abcdef</Arn>"+
				"<HTTPPort>80</HTTPPort><HTTPSPort>443</HTTPSPort><OriginProtocolPolicy>"+policy+"</OriginProtocolPolicy></VpcOriginEndpointConfig></VpcOrigin>")
	}
	denied := restResponse("aws.cloudfront.GetVpcOrigin", http.MethodGet, vpcOriginURL, http.StatusForbidden,
		"<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>User is not authorized to perform: cloudfront:GetVpcOrigin</Message></Error></ErrorResponse>")
	for _, tc := range []struct {
		name      string
		vpcOrigin collectortest.Response
		want      map[string]any
	}{
		{"http-only", vpcOrigin("http-only"), map[string]any{
			path + "/distributions_with_http_only_origin_count":    1,
			path + "/distributions_with_match_viewer_origin_count": 0,
			path + "/distributions/0/http_only_origin_count":       1,
		}},
		{"match-viewer", vpcOrigin("match-viewer"), map[string]any{
			path + "/distributions_with_http_only_origin_count":    0,
			path + "/distributions_with_match_viewer_origin_count": 1,
			path + "/distributions/0/match_viewer_origin_count":    1,
		}},
		{"read denied", denied, map[string]any{
			path + "/distribution_count": 1,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			responses := append(replaceResponses(kitResponses(),
				restResponse("aws.cloudfront.ListDistributions", http.MethodGet, listURL, 0, distributionListWithOrigin(origin))), tc.vpcOrigin)
			doc := runDetailed(t, responses)
			expectValues(t, doc, tc.want)
			if tc.name != "read denied" {
				return
			}
			for _, pointer := range []string{"/distributions_with_http_only_origin_count", "/distributions_with_match_viewer_origin_count", "/distributions/0/http_only_origin_count"} {
				if got, _ := valueAt(doc, path+pointer); got != nil {
					t.Errorf("%s = %v, want it left out", path+pointer, got)
				}
			}
		})
	}
}
