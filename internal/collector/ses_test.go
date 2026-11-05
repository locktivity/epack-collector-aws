package collector

import (
	"slices"
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

func TestAggregateSES(t *testing.T) {
	require := aws.SESConfigurationSet{Name: "outbound", TLSPolicy: "REQUIRE"}
	optional := aws.SESConfigurationSet{Name: "marketing", TLSPolicy: "OPTIONAL"}
	unset := aws.SESConfigurationSet{Name: "legacy"}

	t.Run("only REQUIRE counts as enforced", func(t *testing.T) {
		got := aggregateSES([]aws.SESConfigurationSet{require, optional, unset}, nil)

		if got.ConfigurationSetsRequiringTLSCount != 1 {
			t.Errorf("ConfigurationSetsRequiringTLSCount = %d, want 1", got.ConfigurationSetsRequiringTLSCount)
		}
		// OPTIONAL and no delivery options behave identically: SES attempts
		// TLS and falls back to plaintext.
		if got.ConfigurationSetsOpportunisticTLSCount != 2 {
			t.Errorf("ConfigurationSetsOpportunisticTLSCount = %d, want 2", got.ConfigurationSetsOpportunisticTLSCount)
		}
	})

	t.Run("an identity is covered only through a requiring default set", func(t *testing.T) {
		got := aggregateSES(
			[]aws.SESConfigurationSet{require, optional},
			[]aws.SESIdentity{
				{Name: "wattcarbon.com", SendingEnabled: true, DefaultConfigurationSet: "outbound"},
				{Name: "staging.wattcarbon.com", SendingEnabled: true, DefaultConfigurationSet: "marketing"},
				{Name: "no-default.example", SendingEnabled: true},
			},
		)

		if got.IdentityCount != 3 {
			t.Errorf("IdentityCount = %d, want 3", got.IdentityCount)
		}
		if got.IdentitiesRequiringTLSCount != 1 {
			t.Errorf("IdentitiesRequiringTLSCount = %d, want 1: only the identity defaulting to the requiring set", got.IdentitiesRequiringTLSCount)
		}
	})

	t.Run("a sending-disabled identity is latent, not a finding either way", func(t *testing.T) {
		got := aggregateSES(
			[]aws.SESConfigurationSet{require},
			[]aws.SESIdentity{{Name: "old.example", SendingEnabled: false, DefaultConfigurationSet: "outbound"}},
		)

		if got.SendingDisabledIdentityCount != 1 {
			t.Errorf("SendingDisabledIdentityCount = %d, want 1", got.SendingDisabledIdentityCount)
		}
		if got.IdentitiesRequiringTLSCount != 0 {
			t.Errorf("IdentitiesRequiringTLSCount = %d, want 0 for a disabled identity", got.IdentitiesRequiringTLSCount)
		}
	})

	// An unresolved set must not count as requiring even if an identity
	// defaults to it, and an unresolved identity lands in no finding.
	t.Run("unresolved reads stay unproven", func(t *testing.T) {
		got := aggregateSES(
			[]aws.SESConfigurationSet{{Name: "outbound", Unresolved: true}},
			[]aws.SESIdentity{
				{Name: "wattcarbon.com", SendingEnabled: true, DefaultConfigurationSet: "outbound"},
				{Name: "unknown.example", SendingEnabled: true, Unresolved: true},
			},
		)

		if got.ConfigurationSetsUnresolvedCount != 1 {
			t.Errorf("ConfigurationSetsUnresolvedCount = %d, want 1", got.ConfigurationSetsUnresolvedCount)
		}
		if got.IdentitiesRequiringTLSCount != 0 {
			t.Errorf("IdentitiesRequiringTLSCount = %d, want 0 when the set is unproven", got.IdentitiesRequiringTLSCount)
		}
		if got.IdentitiesUnresolvedCount != 1 {
			t.Errorf("IdentitiesUnresolvedCount = %d, want 1", got.IdentitiesUnresolvedCount)
		}
	})
}

func TestMergeSESMetricsSumsAcrossRegions(t *testing.T) {
	a := SESMetrics{
		ConfigurationSetCount:              2,
		ConfigurationSetsRequiringTLSCount: 1,
		IdentityCount:                      1,
		IdentitiesRequiringTLSCount:        1,
		ConfigurationSets:                  []SESConfigurationSetRow{{Name: "outbound", Region: "us-east-1"}},
	}
	b := SESMetrics{
		ConfigurationSetCount:     1,
		IdentityCount:             2,
		IdentitiesUnresolvedCount: 1,
		Identities:                []SESIdentityRow{{Name: "eu.example", Region: "eu-west-1"}},
	}

	got := mergeSESMetrics(a, b)

	if got.ConfigurationSetCount != 3 || got.IdentityCount != 3 || got.IdentitiesRequiringTLSCount != 1 {
		t.Errorf("counts = %+v, want sums preserved", got)
	}
	if len(got.ConfigurationSets) != 1 || len(got.Identities) != 1 {
		t.Errorf("rows = %d sets and %d identities, want 1 each", len(got.ConfigurationSets), len(got.Identities))
	}
}

// runWithSecondRegion runs the kit account over its own region and region,
// answering every surface in region except the operations in unanswered.
func runWithSecondRegion(t *testing.T, region string, unanswered ...string) (Output, componentsdk.InProcessResult) {
	t.Helper()
	isolateAWSEnvironment(t)
	var second []collectortest.Response
	for _, r := range emptyRegionResponses(region) {
		if !slices.Contains(unanswered, r.Operation) {
			second = append(second, r)
		}
	}
	cfg := kitConfig()
	cfg["regions"] = []any{kitRegion, region}
	res := runKit(t, cfg, kitSecrets(), append(noIdentityCenterResponses(kitCredentialReport), second...))
	if res.ExitCode != 0 {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	var out Output
	decodeArtifact(t, res, awsPath, &out)
	if len(out.Accounts) != 1 {
		t.Fatalf("accounts = %d, want 1", len(out.Accounts))
	}
	return out, res
}

// SES has no endpoint in some regions an account can enable, and holds no
// configuration sets or identities there. The other regions' sets and
// identities still count.
func TestSES_RegionWithoutEndpointKeepsOtherRegions(t *testing.T) {
	for _, tc := range []struct {
		region     string
		unanswered []string
	}{
		{"ap-east-1", []string{"aws.sesv2.ListConfigurationSets", "aws.sesv2.ListEmailIdentities"}},
		{"ap-east-2", []string{"aws.sesv2.ListConfigurationSets", "aws.sesv2.ListEmailIdentities"}},
		{"ap-southeast-6", []string{"aws.sesv2.ListConfigurationSets", "aws.sesv2.ListEmailIdentities"}},
		{"mx-central-1", []string{"aws.sesv2.ListConfigurationSets", "aws.sesv2.ListEmailIdentities"}},
		{"eu-west-1", nil},
	} {
		t.Run(tc.region, func(t *testing.T) {
			out, res := runWithSecondRegion(t, tc.region, tc.unanswered...)
			ses := out.Accounts[0].SES
			if ses.ConfigurationSetCount != 1 || ses.ConfigurationSetsRequiringTLSCount != 1 || ses.IdentityCount != 1 || ses.IdentitiesRequiringTLSCount != 1 {
				t.Errorf("configuration_set_count = %d, configuration_sets_requiring_tls_count = %d, identity_count = %d, identities_requiring_tls_count = %d; want 1 each",
					ses.ConfigurationSetCount, ses.ConfigurationSetsRequiringTLSCount, ses.IdentityCount, ses.IdentitiesRequiringTLSCount)
			}
			if g := gapAt(res, awsPath, "/accounts/0/ses"); g != nil {
				t.Errorf("/accounts/0/ses is left out as %s", g.Code)
			}
		})
	}
}
