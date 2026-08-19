package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
)

// SESConfigurationSet is one configuration set's transport policy.
type SESConfigurationSet struct {
	Name string

	// TLSPolicy is REQUIRE, OPTIONAL, or empty when the set declares no
	// delivery options. SES treats the last two identically: it attempts TLS
	// and falls back to plaintext, so only REQUIRE enforces.
	TLSPolicy string

	// Unresolved marks a set whose details could not be read; its policy is
	// unproven rather than opportunistic.
	Unresolved bool
}

// SESIdentity is one sending identity and the configuration set its mail uses
// by default.
type SESIdentity struct {
	Name           string
	Type           string
	SendingEnabled bool

	// DefaultConfigurationSet applies to mail that names no set at send time.
	// Empty means sends fall back to SES defaults, which do not require TLS.
	DefaultConfigurationSet string

	Unresolved bool
}

// ListSESConfigurationSets returns the region's configuration sets with their
// delivery TLS policy. One GetConfigurationSet call per set; accounts hold a
// handful of sets, not fleets.
func (c *AWSClient) ListSESConfigurationSets(ctx context.Context, region string) ([]SESConfigurationSet, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := sesv2.NewFromConfig(cfg)

	var sets []SESConfigurationSet
	paginator := sesv2.NewListConfigurationSetsPaginator(client, &sesv2.ListConfigurationSetsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing SES configuration sets in %s: %w", region, err)
		}
		for _, name := range page.ConfigurationSets {
			set := SESConfigurationSet{Name: name}
			detail, err := client.GetConfigurationSet(ctx, &sesv2.GetConfigurationSetInput{
				ConfigurationSetName: aws.String(name),
			})
			if err != nil {
				set.Unresolved = true
			} else if detail.DeliveryOptions != nil {
				set.TLSPolicy = string(detail.DeliveryOptions.TlsPolicy)
			}
			sets = append(sets, set)
		}
	}
	return sets, nil
}

// ListSESIdentities returns the region's sending identities and their default
// configuration sets. One GetEmailIdentity call per identity.
func (c *AWSClient) ListSESIdentities(ctx context.Context, region string) ([]SESIdentity, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := sesv2.NewFromConfig(cfg)

	var identities []SESIdentity
	paginator := sesv2.NewListEmailIdentitiesPaginator(client, &sesv2.ListEmailIdentitiesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing SES identities in %s: %w", region, err)
		}
		for _, info := range page.EmailIdentities {
			identity := SESIdentity{
				Name:           aws.ToString(info.IdentityName),
				Type:           string(info.IdentityType),
				SendingEnabled: info.SendingEnabled,
			}
			detail, err := client.GetEmailIdentity(ctx, &sesv2.GetEmailIdentityInput{
				EmailIdentity: info.IdentityName,
			})
			if err != nil {
				identity.Unresolved = true
			} else {
				identity.DefaultConfigurationSet = aws.ToString(detail.ConfigurationSetName)
			}
			identities = append(identities, identity)
		}
	}
	return identities, nil
}
