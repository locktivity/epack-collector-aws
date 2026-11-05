package aws

import (
	"cmp"
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

// CloudFrontDistribution is one distribution's transport configuration, both
// hops: viewer to edge, and edge to origin.
type CloudFrontDistribution struct {
	ID      string
	Domain  string
	Aliases []string
	Enabled bool

	// WebACLArn is the WAFv2 web ACL protecting this distribution, empty when
	// none is attached. (The listing's WebACLId field carries the full ARN for
	// WAFv2 web ACLs.)
	WebACLArn string

	// ViewerProtocolPolicies holds the policy of the default cache behavior and
	// every additional behavior. The whole list matters: a distribution whose
	// default redirects to HTTPS can still allow plaintext on a path behavior,
	// and unlike ALB listener rules these arrive in the listing itself.
	ViewerProtocolPolicies []string

	MinimumProtocolVersion string

	// Origin hops. Custom origins declare a protocol policy, and a VPC
	// origin's policy is on the VPC origin resource. S3 REST origins carry no
	// protocol field in config, so they are counted rather than classified.
	OriginsHTTPOnly    int
	OriginsMatchViewer int
	OriginsHTTPSOnly   int
	S3OriginCount      int

	// VPCOriginErr is why a VPC origin's protocol policy could not be read.
	// That origin is in none of the origin counts.
	VPCOriginErr error
}

// ListCloudFrontDistributions returns the account's distributions. CloudFront
// is a global service, so this runs once per account, not per region.
func (c *AWSClient) ListCloudFrontDistributions(ctx context.Context) ([]CloudFrontDistribution, error) {
	client := cloudfront.NewFromConfig(c.cfg)

	var out []CloudFrontDistribution
	vpcOrigins := map[string]vpcOriginPolicy{}
	paginator := cloudfront.NewListDistributionsPaginator(client, &cloudfront.ListDistributionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing CloudFront distributions: %w", err)
		}
		// CloudFront leaves Items out of an empty list, so Quantity is what
		// says the list was read.
		if page.DistributionList == nil || page.DistributionList.Quantity == nil {
			return nil, errMissing(page.ResultMetadata, "listing CloudFront distributions", "DistributionList")
		}
		if page.DistributionList.Items == nil && *page.DistributionList.Quantity > 0 {
			return nil, errMissing(page.ResultMetadata, "listing CloudFront distributions", "Items")
		}
		for _, d := range page.DistributionList.Items {
			dist := CloudFrontDistribution{
				ID:        aws.ToString(d.Id),
				Domain:    aws.ToString(d.DomainName),
				Enabled:   aws.ToBool(d.Enabled),
				WebACLArn: aws.ToString(d.WebACLId),
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
						dist.countOrigin(o.CustomOriginConfig.OriginProtocolPolicy)
					case o.VpcOriginConfig != nil:
						id := aws.ToString(o.VpcOriginConfig.VpcOriginId)
						read, ok := vpcOrigins[id]
						if !ok {
							read.policy, read.err = getVPCOriginProtocolPolicy(ctx, client, id)
							vpcOrigins[id] = read
						}
						if read.err != nil {
							dist.VPCOriginErr = cmp.Or(dist.VPCOriginErr, read.err)
							continue
						}
						dist.countOrigin(read.policy)
					}
				}
			}
			out = append(out, dist)
		}
	}
	return out, nil
}

// countOrigin counts an origin fetched with policy.
func (d *CloudFrontDistribution) countOrigin(policy cloudfronttypes.OriginProtocolPolicy) {
	switch policy {
	case cloudfronttypes.OriginProtocolPolicyHttpOnly:
		d.OriginsHTTPOnly++
	case cloudfronttypes.OriginProtocolPolicyMatchViewer:
		d.OriginsMatchViewer++
	case cloudfronttypes.OriginProtocolPolicyHttpsOnly:
		d.OriginsHTTPSOnly++
	}
}

// vpcOriginPolicy is a VPC origin's protocol policy, or why it could not be
// read.
type vpcOriginPolicy struct {
	policy cloudfronttypes.OriginProtocolPolicy
	err    error
}

// getVPCOriginProtocolPolicy reads the protocol policy CloudFront uses to
// reach the VPC origin id. A distribution's VPC origin config holds only the
// ID, and the policy is on the VPC origin resource.
func getVPCOriginProtocolPolicy(ctx context.Context, client *cloudfront.Client, id string) (cloudfronttypes.OriginProtocolPolicy, error) {
	out, err := client.GetVpcOrigin(ctx, &cloudfront.GetVpcOriginInput{Id: aws.String(id)})
	if err != nil {
		return "", fmt.Errorf("getting CloudFront VPC origin %s: %w", id, err)
	}
	if out.VpcOrigin == nil || out.VpcOrigin.VpcOriginEndpointConfig == nil || out.VpcOrigin.VpcOriginEndpointConfig.OriginProtocolPolicy == "" {
		return "", errMissing(out.ResultMetadata, "getting CloudFront VPC origin "+id, "OriginProtocolPolicy")
	}
	return out.VpcOrigin.VpcOriginEndpointConfig.OriginProtocolPolicy, nil
}
