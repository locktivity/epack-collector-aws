package aws

// IMPORTANT for this file: the Secrets Manager collector calls ListSecrets
// only. Value-reading APIs are forbidden in collector source — secret material
// (SecretString, SecretBinary) must never enter the artifact. The forbidden-API
// lint enforces this at build time; see scripts/check-forbidden-apis.sh.

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// ListSecretsManagerSecrets returns every Secrets Manager secret in the region
// with the posture-relevant metadata. Secret VALUES are not fetched. The
// single paginated ListSecrets call returns name, ARN, description, KMS key,
// rotation config, timestamps, and tags — everything we need.
func (c *AWSClient) ListSecretsManagerSecrets(ctx context.Context, region string) ([]SecretsManagerSecret, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := secretsmanager.NewFromConfig(cfg)

	var secrets []SecretsManagerSecret
	paginator := secretsmanager.NewListSecretsPaginator(client, &secretsmanager.ListSecretsInput{})
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing Secrets Manager secrets in %s: %w", region, err)
		}
		for _, s := range out.SecretList {
			row := SecretsManagerSecret{
				Name:              aws.ToString(s.Name),
				ARN:               aws.ToString(s.ARN),
				Description:       aws.ToString(s.Description),
				KMSKeyARN:         aws.ToString(s.KmsKeyId),
				RotationEnabled:   aws.ToBool(s.RotationEnabled),
				RotationLambdaARN: aws.ToString(s.RotationLambdaARN),
				NextRotationDate:  s.NextRotationDate,
				CreatedDate:       s.CreatedDate,
				LastChangedDate:   s.LastChangedDate,
				LastAccessedDate:  s.LastAccessedDate,
				DeletionDate:      s.DeletedDate,
				PrimaryRegion:     aws.ToString(s.PrimaryRegion),
				OwningService:     aws.ToString(s.OwningService),
			}
			if s.RotationRules != nil {
				row.RotationDays = aws.ToInt64(s.RotationRules.AutomaticallyAfterDays)
			}
			if len(s.Tags) > 0 {
				row.Tags = make(map[string]string, len(s.Tags))
				for _, t := range s.Tags {
					row.Tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
				}
			}
			secrets = append(secrets, row)
		}
	}
	return secrets, nil
}
