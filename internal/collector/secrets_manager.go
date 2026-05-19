package collector

import (
	"context"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// collectSecretsManagerMetrics collects Secrets Manager posture for a single
// region. Secret VALUES are not fetched — only metadata. One paginated
// ListSecrets call supplies everything we need across all three levels.
func (c *Collector) collectSecretsManagerMetrics(ctx context.Context, client *aws.AWSClient, region, accountID string, level componentsdk.Level) (*SecretsManagerMetrics, error) {
	secrets, err := client.ListSecretsManagerSecrets(ctx, region)
	if err != nil {
		return nil, err
	}

	out := &SecretsManagerMetrics{
		SecretCount: len(secrets),
	}
	for _, s := range secrets {
		if !s.RotationEnabled {
			out.SecretsWithoutRotationCount++
		}
		if s.KMSKeyARN == "" {
			out.SecretsWithoutCustomerKMSCount++
		}
		if s.DeletionDate != nil {
			out.SecretsPendingDeletionCount++
		}
	}

	if !level.AtLeast(componentsdk.LevelAudit) {
		return out, nil
	}

	out.Secrets = make([]SecretsManagerSecretRow, 0, len(secrets))
	for _, s := range secrets {
		out.Secrets = append(out.Secrets, secretsManagerSecretToRow(s, region, level))
	}
	return out, nil
}

// secretsManagerSecretToRow projects an aws.SecretsManagerSecret onto its
// audit-level row. Internal-level fields (description, KMS ARN, rotation
// Lambda ARN, tags) are populated when level >= internal — no extra API
// calls; the data is already in the ListSecrets response.
func secretsManagerSecretToRow(s aws.SecretsManagerSecret, region string, level componentsdk.Level) SecretsManagerSecretRow {
	row := SecretsManagerSecretRow{
		Name:            s.Name,
		Region:          region,
		ARN:             s.ARN,
		RotationEnabled: s.RotationEnabled,
		RotationDays:    s.RotationDays,
		HasCustomerKMS:  s.KMSKeyARN != "",
		PrimaryRegion:   s.PrimaryRegion,
		OwningService:   s.OwningService,
	}
	if s.CreatedDate != nil {
		row.CreatedDate = s.CreatedDate.UTC().Format(time.RFC3339)
	}
	if s.LastChangedDate != nil {
		row.LastChangedDate = s.LastChangedDate.UTC().Format(time.RFC3339)
	}
	if s.LastAccessedDate != nil {
		row.LastAccessedDate = s.LastAccessedDate.UTC().Format(time.RFC3339)
	}
	if s.NextRotationDate != nil {
		row.NextRotationDate = s.NextRotationDate.UTC().Format(time.RFC3339)
	}
	if s.DeletionDate != nil {
		row.DeletionDate = s.DeletionDate.UTC().Format(time.RFC3339)
	}
	if level.AtLeast(componentsdk.LevelInternal) {
		row.Description = s.Description
		row.KMSKeyARN = s.KMSKeyARN
		row.RotationLambdaARN = s.RotationLambdaARN
		if len(s.Tags) > 0 {
			row.Tags = truncateTags(s.Tags, SecretsManagerTagsCap)
		}
	}
	return row
}

// mergeSecretsManagerMetrics combines per-region results. The orchestrator's
// normalizeForLevel pass is the single source of truth for the nil→[] flip
// at audit+.
func mergeSecretsManagerMetrics(a, b SecretsManagerMetrics) SecretsManagerMetrics {
	return SecretsManagerMetrics{
		SecretCount:                    a.SecretCount + b.SecretCount,
		SecretsWithoutRotationCount:    a.SecretsWithoutRotationCount + b.SecretsWithoutRotationCount,
		SecretsWithoutCustomerKMSCount: a.SecretsWithoutCustomerKMSCount + b.SecretsWithoutCustomerKMSCount,
		SecretsPendingDeletionCount:    a.SecretsPendingDeletionCount + b.SecretsPendingDeletionCount,
		Secrets:                        append(append([]SecretsManagerSecretRow(nil), a.Secrets...), b.Secrets...),
	}
}
