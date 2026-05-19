package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

// ListCloudWatchLogGroups returns every log group in the region with the
// posture-relevant metadata returned by DescribeLogGroups. No per-group
// follow-up calls — retention, KMS, stored bytes, creation time, ARN all
// arrive in the single paginated response.
func (c *AWSClient) ListCloudWatchLogGroups(ctx context.Context, region string) ([]CloudWatchLogGroup, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := cloudwatchlogs.NewFromConfig(cfg)

	var groups []CloudWatchLogGroup
	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(client, &cloudwatchlogs.DescribeLogGroupsInput{})
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing CloudWatch log groups in %s: %w", region, err)
		}
		for _, g := range out.LogGroups {
			row := CloudWatchLogGroup{
				Name:            aws.ToString(g.LogGroupName),
				ARN:             aws.ToString(g.Arn),
				RetentionInDays: aws.ToInt32(g.RetentionInDays),
				StoredBytes:     aws.ToInt64(g.StoredBytes),
				KMSKeyARN:       aws.ToString(g.KmsKeyId),
			}
			if g.CreationTime != nil {
				t := time.UnixMilli(*g.CreationTime).UTC()
				row.CreationTime = &t
			}
			groups = append(groups, row)
		}
	}
	return groups, nil
}
