package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
)

// CloudFrontDistribution is one distribution's transport configuration, both
// hops: viewer to edge, and edge to origin.
type CloudFrontDistribution struct {
	ID      string
	Domain  string
	Aliases []string
	Enabled bool

	// ViewerProtocolPolicies holds the policy of the default cache behavior and
	// every additional behavior. The whole list matters: a distribution whose
	// default redirects to HTTPS can still allow plaintext on a path behavior,
	// and unlike ALB listener rules these arrive in the listing itself.
	ViewerProtocolPolicies []string

	MinimumProtocolVersion string

	// Origin hops. Only custom origins declare a protocol policy; S3 REST
	// origins carry no protocol field in config, so they are counted rather
	// than classified.
	OriginsHTTPOnly    int
	OriginsMatchViewer int
	OriginsHTTPSOnly   int
	S3OriginCount      int
}

// ListCloudFrontDistributions returns the account's distributions. CloudFront
// is a global service, so this runs once per account, not per region.
func (c *AWSClient) ListCloudFrontDistributions(ctx context.Context) ([]CloudFrontDistribution, error) {
	client := cloudfront.NewFromConfig(c.cfg)

	var out []CloudFrontDistribution
	paginator := cloudfront.NewListDistributionsPaginator(client, &cloudfront.ListDistributionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing CloudFront distributions: %w", err)
		}
		if page.DistributionList == nil {
			continue
		}
		for _, d := range page.DistributionList.Items {
			dist := CloudFrontDistribution{
				ID:      aws.ToString(d.Id),
				Domain:  aws.ToString(d.DomainName),
				Enabled: aws.ToBool(d.Enabled),
			}
			if d.Aliases != nil {
				dist.Aliases = d.Aliases.Items
			}
			if d.DefaultCacheBehavior != nil {
				dist.ViewerProtocolPolicies = append(dist.ViewerProtocolPolicies, string(d.DefaultCacheBehavior.ViewerProtocolPolicy))
			}
			if d.CacheBehaviors != nil {
				for _, b := range d.CacheBehaviors.Items {
					dist.ViewerProtocolPolicies = append(dist.ViewerProtocolPolicies, string(b.ViewerProtocolPolicy))
				}
			}
			if d.ViewerCertificate != nil {
				dist.MinimumProtocolVersion = string(d.ViewerCertificate.MinimumProtocolVersion)
			}
			if d.Origins != nil {
				for _, o := range d.Origins.Items {
					switch {
					case o.S3OriginConfig != nil:
						dist.S3OriginCount++
					case o.CustomOriginConfig != nil:
						switch string(o.CustomOriginConfig.OriginProtocolPolicy) {
						case "http-only":
							dist.OriginsHTTPOnly++
						case "match-viewer":
							dist.OriginsMatchViewer++
						case "https-only":
							dist.OriginsHTTPSOnly++
						}
					}
				}
			}
			out = append(out, dist)
		}
	}
	return out, nil
}
