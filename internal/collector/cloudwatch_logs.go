package collector

import (
	"context"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// collectCloudWatchLogsMetrics collects log-group posture for a single region.
// One paginated DescribeLogGroups call supplies everything we need across all
// three levels — no per-group follow-ups.
func (c *Collector) collectCloudWatchLogsMetrics(ctx context.Context, client *aws.AWSClient, region, accountID string, level componentsdk.Level) (*CloudWatchLogsMetrics, error) {
	groups, err := client.ListCloudWatchLogGroups(ctx, region)
	if err != nil {
		return nil, err
	}

	out := &CloudWatchLogsMetrics{
		LogGroupCount: len(groups),
	}
	for _, g := range groups {
		if g.RetentionInDays == 0 {
			out.LogGroupsWithoutRetentionCount++
		}
		if g.KMSKeyARN == "" {
			out.LogGroupsWithoutCustomerKMSCount++
		}
	}

	if !level.AtLeast(componentsdk.LevelAudit) {
		return out, nil
	}

	out.LogGroups = make([]CloudWatchLogGroupRow, 0, len(groups))
	for _, g := range groups {
		out.LogGroups = append(out.LogGroups, cloudwatchLogGroupToRow(g, region, level))
	}
	return out, nil
}

// cloudwatchLogGroupToRow projects an aws.CloudWatchLogGroup onto its
// audit-level row. Internal-level fields (ARN, KMSKeyARN) are populated when
// level >= internal — no extra API calls; the data is already in the
// DescribeLogGroups response.
func cloudwatchLogGroupToRow(g aws.CloudWatchLogGroup, region string, level componentsdk.Level) CloudWatchLogGroupRow {
	row := CloudWatchLogGroupRow{
		Name:            g.Name,
		Region:          region,
		RetentionInDays: g.RetentionInDays,
		StoredBytes:     g.StoredBytes,
		HasCustomerKMS:  g.KMSKeyARN != "",
	}
	if g.CreationTime != nil {
		row.CreationTime = g.CreationTime.UTC().Format(time.RFC3339)
	}
	if level.AtLeast(componentsdk.LevelInternal) {
		row.ARN = g.ARN
		row.KMSKeyARN = g.KMSKeyARN
	}
	return row
}

// mergeCloudWatchLogsMetrics combines per-region results. Trust aggregates sum;
// audit rows concatenate. nil-preserving in the trivial-empty case; the
// orchestrator's normalizeForLevel pass is the single source of truth for
// the strict-superset contract.
func mergeCloudWatchLogsMetrics(a, b CloudWatchLogsMetrics) CloudWatchLogsMetrics {
	return CloudWatchLogsMetrics{
		LogGroupCount:                    a.LogGroupCount + b.LogGroupCount,
		LogGroupsWithoutRetentionCount:   a.LogGroupsWithoutRetentionCount + b.LogGroupsWithoutRetentionCount,
		LogGroupsWithoutCustomerKMSCount: a.LogGroupsWithoutCustomerKMSCount + b.LogGroupsWithoutCustomerKMSCount,
		LogGroups:                        append(append([]CloudWatchLogGroupRow(nil), a.LogGroups...), b.LogGroups...),
	}
}
