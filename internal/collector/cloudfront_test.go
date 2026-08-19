package collector

import (
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
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
