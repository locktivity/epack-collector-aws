package collector

import (
	"context"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

const kmsKeySpecSymmetricDefault = "SYMMETRIC_DEFAULT"
const kmsKeyStatePendingDeletion = "PendingDeletion"

// collectKMSMetrics collects KMS posture for a single region, scoped to
// customer-managed keys. The AWS client filters out AWS-managed keys; this
// collector adds the trust aggregates + audit/internal row projection.
func (c *Collector) collectKMSMetrics(ctx context.Context, client *aws.AWSClient, region, accountID string, level componentsdk.Level) (*KMSMetrics, error) {
	keys, err := client.ListKMSCustomerKeys(ctx, region)
	if err != nil {
		return nil, err
	}

	out := &KMSMetrics{
		CustomerManagedKeyCount: len(keys),
	}
	for _, k := range keys {
		if k.KeySpec == kmsKeySpecSymmetricDefault && !k.RotationEnabled {
			out.CMKsWithRotationDisabledCount++
		}
		if k.KeyState == kmsKeyStatePendingDeletion {
			out.CMKsPendingDeletionCount++
		}
	}

	if !level.AtLeast(componentsdk.LevelAudit) {
		return out, nil
	}

	out.Keys = make([]KMSKeyRow, 0, len(keys))
	for _, k := range keys {
		out.Keys = append(out.Keys, kmsKeyToRow(k, region, level))
	}
	return out, nil
}

// kmsKeyToRow projects an aws.KMSKey onto its audit-level row. Internal-level
// fields (Description) are populated when level >= internal — no extra API
// calls; the data is already in the DescribeKey response.
func kmsKeyToRow(k aws.KMSKey, region string, level componentsdk.Level) KMSKeyRow {
	row := KMSKeyRow{
		KeyID:           k.KeyID,
		Region:          region,
		ARN:             k.ARN,
		KeyState:        k.KeyState,
		KeyUsage:        k.KeyUsage,
		KeySpec:         k.KeySpec,
		Origin:          k.Origin,
		MultiRegion:     k.MultiRegion,
		RotationEnabled: k.RotationEnabled,
	}
	if k.CreationDate != nil {
		row.CreationDate = k.CreationDate.UTC().Format(time.RFC3339)
	}
	if k.DeletionDate != nil {
		row.DeletionDate = k.DeletionDate.UTC().Format(time.RFC3339)
	}
	if len(k.Aliases) > 0 {
		row.Aliases = append([]string(nil), k.Aliases...)
	}
	if level.AtLeast(componentsdk.LevelInternal) {
		row.Description = k.Description
	}
	return row
}

// mergeKMSMetrics combines per-region results. Trust aggregates sum; audit
// rows concatenate. The orchestrator's normalizeForLevel pass is the single
// source of truth for the nil→[] flip at audit+.
func mergeKMSMetrics(a, b KMSMetrics) KMSMetrics {
	return KMSMetrics{
		CustomerManagedKeyCount:       a.CustomerManagedKeyCount + b.CustomerManagedKeyCount,
		CMKsWithRotationDisabledCount: a.CMKsWithRotationDisabledCount + b.CMKsWithRotationDisabledCount,
		CMKsPendingDeletionCount:      a.CMKsPendingDeletionCount + b.CMKsPendingDeletionCount,
		Keys:                          append(append([]KMSKeyRow(nil), a.Keys...), b.Keys...),
	}
}
