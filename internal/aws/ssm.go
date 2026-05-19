package aws

// IMPORTANT for this file: the SSM Parameter Store collector calls
// DescribeParameters only. Value-reading APIs (the per-parameter and
// path-based value-fetch operations) are forbidden in collector source —
// SecureString contents must never enter the artifact. The forbidden-API
// lint enforces this at build time; see scripts/check-forbidden-apis.sh.

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// ListSSMParameters returns every SSM parameter in the region with the
// posture-relevant metadata. Parameter VALUES are not fetched. The single
// paginated DescribeParameters call supplies name, type, KMS key, version,
// tier, description, and last-modified info — everything we need.
func (c *AWSClient) ListSSMParameters(ctx context.Context, region string) ([]SSMParameter, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := ssm.NewFromConfig(cfg)

	var params []SSMParameter
	paginator := ssm.NewDescribeParametersPaginator(client, &ssm.DescribeParametersInput{})
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing SSM parameters in %s: %w", region, err)
		}
		for _, p := range out.Parameters {
			row := SSMParameter{
				Name:             aws.ToString(p.Name),
				Type:             string(p.Type),
				DataType:         aws.ToString(p.DataType),
				Version:          p.Version,
				Tier:             string(p.Tier),
				Description:      aws.ToString(p.Description),
				KMSKeyARN:        aws.ToString(p.KeyId),
				LastModifiedDate: p.LastModifiedDate,
				LastModifiedUser: aws.ToString(p.LastModifiedUser),
			}
			params = append(params, row)
		}
	}
	return params, nil
}
