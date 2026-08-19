package collector

import (
	"context"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// collectCloudFrontMetrics collects distribution transport enforcement for the
// account. CloudFront is global, so this runs once alongside IAM rather than in
// the regional loop, and a failure marks the surface unevaluated rather than
// zeroed.
func (c *Collector) collectCloudFrontMetrics(ctx context.Context, client *aws.AWSClient, accountID string, level componentsdk.Level) *CloudFrontMetrics {
	distributions, err := client.ListCloudFrontDistributions(ctx)
	if err != nil {
		c.warn("account %s: failed to collect CloudFront distributions: %v", accountID, err)
		return &CloudFrontMetrics{DistributionsErrorCode: apiErrorCode(err)}
	}

	out := aggregateCloudFrontDistributions(distributions)
	if level.AtLeast(componentsdk.LevelAudit) {
		for _, d := range distributions {
			out.Distributions = append(out.Distributions, cloudFrontDistributionToRow(d))
		}
	}
	return out
}

// aggregateCloudFrontDistributions reduces distributions to the transport
// findings. Disabled distributions serve nothing, so they are counted but
// excluded from findings: a plaintext policy on a switched-off distribution is
// latent, not live.
func aggregateCloudFrontDistributions(distributions []aws.CloudFrontDistribution) *CloudFrontMetrics {
	out := &CloudFrontMetrics{
		DistributionsEvaluated: true,
		DistributionCount:      len(distributions),
	}

	for _, d := range distributions {
		if !d.Enabled {
			out.DisabledDistributionCount++
			continue
		}

		if distributionAllowsPlaintextViewers(d) {
			out.DistributionsAllowingPlaintextViewersCount++
		}
		if d.OriginsHTTPOnly > 0 {
			out.DistributionsWithHTTPOnlyOriginCount++
		}
		if d.OriginsMatchViewer > 0 {
			out.DistributionsWithMatchViewerOriginCount++
		}

		if d.MinimumProtocolVersion != "" {
			if out.DistributionsByMinimumTLS == nil {
				out.DistributionsByMinimumTLS = map[string]int{}
			}
			out.DistributionsByMinimumTLS[d.MinimumProtocolVersion]++
		}
	}
	return out
}

// distributionAllowsPlaintextViewers reports whether any cache behavior serves
// plaintext to viewers. Both redirect-to-https and https-only deliver content
// over TLS only, so allow-all is the single policy that does not.
func distributionAllowsPlaintextViewers(d aws.CloudFrontDistribution) bool {
	for _, policy := range d.ViewerProtocolPolicies {
		if policy == "allow-all" {
			return true
		}
	}
	return false
}

func cloudFrontDistributionToRow(d aws.CloudFrontDistribution) CloudFrontDistributionRow {
	return CloudFrontDistributionRow{
		ID:                     d.ID,
		Domain:                 d.Domain,
		Aliases:                d.Aliases,
		Enabled:                d.Enabled,
		AllowsPlaintextViewers: distributionAllowsPlaintextViewers(d),
		MinimumProtocolVersion: d.MinimumProtocolVersion,
		HTTPOnlyOriginCount:    d.OriginsHTTPOnly,
		MatchViewerOriginCount: d.OriginsMatchViewer,
		HTTPSOnlyOriginCount:   d.OriginsHTTPSOnly,
		S3OriginCount:          d.S3OriginCount,
	}
}
