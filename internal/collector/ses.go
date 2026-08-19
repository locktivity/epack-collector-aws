package collector

import (
	"context"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// collectSESMetrics collects outbound mail transport enforcement for a region.
// Both listings are cheap in regions where SES is unused.
func (c *Collector) collectSESMetrics(ctx context.Context, client *aws.AWSClient, region, accountID string, level componentsdk.Level) (*SESMetrics, error) {
	sets, err := client.ListSESConfigurationSets(ctx, region)
	if err != nil {
		return nil, err
	}
	identities, err := client.ListSESIdentities(ctx, region)
	if err != nil {
		return nil, err
	}

	for _, s := range sets {
		if s.Unresolved {
			c.warn("account %s region %s: failed to read SES configuration set %s; its TLS policy is unproven", accountID, region, s.Name)
		}
	}
	for _, i := range identities {
		if i.Unresolved {
			c.warn("account %s region %s: failed to read SES identity %s; its default configuration set is unknown", accountID, region, i.Name)
		}
	}

	out := aggregateSES(sets, identities)
	if level.AtLeast(componentsdk.LevelAudit) {
		for _, s := range sets {
			out.ConfigurationSets = append(out.ConfigurationSets, SESConfigurationSetRow{
				Name:       s.Name,
				Region:     region,
				TLSPolicy:  s.TLSPolicy,
				Unresolved: s.Unresolved,
			})
		}
		requiring := requiringSetNames(sets)
		for _, i := range identities {
			out.Identities = append(out.Identities, SESIdentityRow{
				Name:                    i.Name,
				Region:                  region,
				Type:                    i.Type,
				SendingEnabled:          i.SendingEnabled,
				DefaultConfigurationSet: i.DefaultConfigurationSet,
				DefaultRequiresTLS:      identityRequiresTLS(i, requiring),
				Unresolved:              i.Unresolved,
			})
		}
	}
	return out, nil
}

// aggregateSES reduces a region's configuration sets and identities to the
// transport findings. Only REQUIRE enforces: OPTIONAL and an absent delivery
// options block both mean SES attempts TLS and falls back to plaintext.
func aggregateSES(sets []aws.SESConfigurationSet, identities []aws.SESIdentity) *SESMetrics {
	out := &SESMetrics{ConfigurationSetCount: len(sets)}

	for _, s := range sets {
		switch {
		case s.Unresolved:
			out.ConfigurationSetsUnresolvedCount++
		case s.TLSPolicy == "REQUIRE":
			out.ConfigurationSetsRequiringTLSCount++
		default:
			out.ConfigurationSetsOpportunisticTLSCount++
		}
	}

	requiring := requiringSetNames(sets)
	for _, i := range identities {
		out.IdentityCount++
		if !i.SendingEnabled {
			out.SendingDisabledIdentityCount++
			continue
		}
		if i.Unresolved {
			out.IdentitiesUnresolvedCount++
			continue
		}
		if identityRequiresTLS(i, requiring) {
			out.IdentitiesRequiringTLSCount++
		}
	}
	return out
}

func requiringSetNames(sets []aws.SESConfigurationSet) map[string]bool {
	out := map[string]bool{}
	for _, s := range sets {
		if !s.Unresolved && s.TLSPolicy == "REQUIRE" {
			out[s.Name] = true
		}
	}
	return out
}

// identityRequiresTLS reports whether mail from this identity requires TLS by
// default: the identity names a default configuration set and that set's
// delivery policy is REQUIRE. A send that names its own configuration set can
// still override this; that choice is per message and not visible in config.
func identityRequiresTLS(identity aws.SESIdentity, requiring map[string]bool) bool {
	return identity.DefaultConfigurationSet != "" && requiring[identity.DefaultConfigurationSet]
}

// mergeSESMetrics combines per-region results. Aggregates sum; audit rows
// concatenate.
func mergeSESMetrics(a, b SESMetrics) SESMetrics {
	return SESMetrics{
		ConfigurationSetCount:                  a.ConfigurationSetCount + b.ConfigurationSetCount,
		ConfigurationSetsRequiringTLSCount:     a.ConfigurationSetsRequiringTLSCount + b.ConfigurationSetsRequiringTLSCount,
		ConfigurationSetsOpportunisticTLSCount: a.ConfigurationSetsOpportunisticTLSCount + b.ConfigurationSetsOpportunisticTLSCount,
		ConfigurationSetsUnresolvedCount:       a.ConfigurationSetsUnresolvedCount + b.ConfigurationSetsUnresolvedCount,
		IdentityCount:                          a.IdentityCount + b.IdentityCount,
		IdentitiesRequiringTLSCount:            a.IdentitiesRequiringTLSCount + b.IdentitiesRequiringTLSCount,
		SendingDisabledIdentityCount:           a.SendingDisabledIdentityCount + b.SendingDisabledIdentityCount,
		IdentitiesUnresolvedCount:              a.IdentitiesUnresolvedCount + b.IdentitiesUnresolvedCount,
		ConfigurationSets:                      append(append([]SESConfigurationSetRow(nil), a.ConfigurationSets...), b.ConfigurationSets...),
		Identities:                             append(append([]SESIdentityRow(nil), a.Identities...), b.Identities...),
	}
}
