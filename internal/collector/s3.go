package collector

import (
	"context"
	"fmt"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

// collectS3Metrics collects S3 security metrics.
func (c *Collector) collectS3Metrics(ctx context.Context, client *aws.AWSClient, accountID string) (*S3Metrics, error) {
	metrics := &S3Metrics{}

	// Get account-level public access block
	accountBlocked, _ := client.GetAccountPublicAccessBlock(ctx, accountID)
	metrics.AccountPublicAccessBlockEnabled = accountBlocked

	// List buckets and get their settings
	buckets, err := client.ListBuckets(ctx)
	if err != nil {
		return metrics, fmt.Errorf("listing buckets: %w", err)
	}

	var publicBlocked, encrypted, versioned, logging int

	for _, b := range buckets {
		if b.PublicAccessBlocked {
			publicBlocked++
		}
		if b.DefaultEncryptionEnabled {
			encrypted++
		}
		if b.VersioningEnabled {
			versioned++
		}
		if b.LoggingEnabled {
			logging++
		}
	}

	metrics.PublicAccessBlocked = percent(publicBlocked, len(buckets))
	metrics.DefaultEncryptionEnabled = percent(encrypted, len(buckets))
	metrics.VersioningEnabled = percent(versioned, len(buckets))
	metrics.LoggingEnabled = percent(logging, len(buckets))

	return metrics, nil
}
