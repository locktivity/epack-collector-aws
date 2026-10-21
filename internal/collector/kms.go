package collector

import (
	"context"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

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
		if k.RotationErr != nil {
			c.warn("account %s region %s: failed to read rotation status for KMS key %s: %v", accountID, region, k.KeyID, k.RotationErr)
			out.missing.addPartial(k.RotationErr, 1, "cmks_with_rotation_disabled_count")
		} else if k.Rotatable() && !k.RotationEnabled {
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
		row := kmsKeyToRow(k, region, level)
		row.missing.add(k.RotationErr, "rotation_enabled")
		out.Keys = append(out.Keys, row)
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
	merged := KMSMetrics{
		CustomerManagedKeyCount:       a.CustomerManagedKeyCount + b.CustomerManagedKeyCount,
		CMKsWithRotationDisabledCount: a.CMKsWithRotationDisabledCount + b.CMKsWithRotationDisabledCount,
		CMKsPendingDeletionCount:      a.CMKsPendingDeletionCount + b.CMKsPendingDeletionCount,
		Keys:                          appendRows(a.Keys, b.Keys),
		missing:                       a.missing,
	}
	merged.missing.merge(b.missing)
	return merged
}
