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
		unresolvedSets := unresolvedSetErrors(sets)
		out.ConfigurationSets = make([]SESConfigurationSetRow, 0, len(sets))
		for _, s := range sets {
			row := SESConfigurationSetRow{
				Name:       s.Name,
				Region:     region,
				TLSPolicy:  s.TLSPolicy,
				Unresolved: s.Unresolved,
			}
			row.missing.add(s.Err, "tls_policy")
			out.ConfigurationSets = append(out.ConfigurationSets, row)
		}
		requiring := requiringSetNames(sets)
		out.Identities = make([]SESIdentityRow, 0, len(identities))
		for _, i := range identities {
			row := SESIdentityRow{
				Name:                    i.Name,
				Region:                  region,
				Type:                    i.Type,
				SendingEnabled:          i.SendingEnabled,
				DefaultConfigurationSet: i.DefaultConfigurationSet,
				DefaultRequiresTLS:      identityRequiresTLS(i, requiring),
				Unresolved:              i.Unresolved,
			}
			row.missing.add(i.Err, "default_configuration_set", "default_requires_tls")
			row.missing.add(unresolvedSets[i.DefaultConfigurationSet], "default_requires_tls")
			out.Identities = append(out.Identities, row)
		}
	}
	return out, nil
}

// unresolvedSetErrors maps each configuration set whose detail could not be
// read to why.
func unresolvedSetErrors(sets []aws.SESConfigurationSet) map[string]error {
	out := map[string]error{}
	for _, s := range sets {
		if s.Unresolved {
			out[s.Name] = s.Err
		}
	}
	return out
}

func aggregateSES(sets []aws.SESConfigurationSet, identities []aws.SESIdentity) *SESMetrics {
	out := &SESMetrics{ConfigurationSetCount: len(sets)}

	for _, s := range sets {
		switch {
		case s.Unresolved:
			out.ConfigurationSetsUnresolvedCount++
			out.missing.addPartial(s.Err, 1, "configuration_sets_requiring_tls_count", "configuration_sets_opportunistic_tls_count")
		case s.TLSPolicy == "REQUIRE":
			out.ConfigurationSetsRequiringTLSCount++
		default:
			out.ConfigurationSetsOpportunisticTLSCount++
		}
	}

	requiring := requiringSetNames(sets)
	unresolvedSets := unresolvedSetErrors(sets)
	for _, i := range identities {
		out.IdentityCount++
		if !i.SendingEnabled {
			out.SendingDisabledIdentityCount++
			continue
		}
		if i.Unresolved {
			out.IdentitiesUnresolvedCount++
			out.missing.addPartial(i.Err, 1, "identities_requiring_tls_count")
			continue
		}
		if err, unknown := unresolvedSets[i.DefaultConfigurationSet]; unknown {
			out.missing.addPartial(err, 1, "identities_requiring_tls_count")
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
	merged := SESMetrics{
		missing:                                a.missing,
		ConfigurationSetCount:                  a.ConfigurationSetCount + b.ConfigurationSetCount,
		ConfigurationSetsRequiringTLSCount:     a.ConfigurationSetsRequiringTLSCount + b.ConfigurationSetsRequiringTLSCount,
		ConfigurationSetsOpportunisticTLSCount: a.ConfigurationSetsOpportunisticTLSCount + b.ConfigurationSetsOpportunisticTLSCount,
		ConfigurationSetsUnresolvedCount:       a.ConfigurationSetsUnresolvedCount + b.ConfigurationSetsUnresolvedCount,
		IdentityCount:                          a.IdentityCount + b.IdentityCount,
		IdentitiesRequiringTLSCount:            a.IdentitiesRequiringTLSCount + b.IdentitiesRequiringTLSCount,
		SendingDisabledIdentityCount:           a.SendingDisabledIdentityCount + b.SendingDisabledIdentityCount,
		IdentitiesUnresolvedCount:              a.IdentitiesUnresolvedCount + b.IdentitiesUnresolvedCount,
		ConfigurationSets:                      appendRows(a.ConfigurationSets, b.ConfigurationSets),
		Identities:                             appendRows(a.Identities, b.Identities),
	}
	merged.missing.merge(b.missing)
	return merged
}
