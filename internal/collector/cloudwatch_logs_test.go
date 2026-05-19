package collector

import (
	"testing"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

func TestCloudwatchLogGroupToRow_AuditOmitsInternalFields(t *testing.T) {
	created := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	in := aws.CloudWatchLogGroup{
		Name:            "/aws/lambda/foo",
		ARN:             "arn:aws:logs:us-east-1:123:log-group:/aws/lambda/foo:*",
		CreationTime:    &created,
		RetentionInDays: 30,
		StoredBytes:     1024,
		KMSKeyARN:       "arn:aws:kms:us-east-1:123:key/abc",
	}
	row := cloudwatchLogGroupToRow(in, "us-east-1", componentsdk.LevelAudit)
	if row.Region != "us-east-1" || row.Name != "/aws/lambda/foo" {
		t.Errorf("audit base fields mis-projected: %+v", row)
	}
	if row.RetentionInDays != 30 || row.StoredBytes != 1024 {
		t.Errorf("audit metadata mis-projected: %+v", row)
	}
	if row.CreationTime != "2026-05-14T10:00:00Z" {
		t.Errorf("expected RFC3339 creation_time, got %q", row.CreationTime)
	}
	if !row.HasCustomerKMS {
		t.Errorf("HasCustomerKMS should be true when KMS ARN is set")
	}
	if row.ARN != "" || row.KMSKeyARN != "" {
		t.Errorf("audit-level row must omit internal-only ARN fields: %+v", row)
	}
}

func TestCloudwatchLogGroupToRow_InternalPopulatesARNs(t *testing.T) {
	in := aws.CloudWatchLogGroup{
		Name:      "/aws/lambda/bar",
		ARN:       "arn:aws:logs:us-east-1:123:log-group:/aws/lambda/bar:*",
		KMSKeyARN: "arn:aws:kms:us-east-1:123:key/def",
	}
	row := cloudwatchLogGroupToRow(in, "us-east-1", componentsdk.LevelInternal)
	if row.ARN == "" || row.KMSKeyARN == "" {
		t.Errorf("internal-level row must populate ARN and KMSKeyARN: %+v", row)
	}
}

func TestCloudwatchLogGroupToRow_NoRetentionAndNoKMS(t *testing.T) {
	// The two trust-level signal cases: log group with no retention (logs accumulate
	// forever) and log group using AWS-managed encryption (no customer KMS).
	in := aws.CloudWatchLogGroup{Name: "/aws/lambda/legacy"}
	row := cloudwatchLogGroupToRow(in, "us-east-1", componentsdk.LevelAudit)
	if row.RetentionInDays != 0 {
		t.Errorf("expected retention=0 (never expires), got %d", row.RetentionInDays)
	}
	if row.HasCustomerKMS {
		t.Errorf("expected HasCustomerKMS=false for AWS-managed encryption")
	}
}

func TestMergeCloudWatchLogsMetrics_SumsAggregatesAndConcatsGroups(t *testing.T) {
	a := CloudWatchLogsMetrics{
		LogGroupCount:                    3,
		LogGroupsWithoutRetentionCount:   2,
		LogGroupsWithoutCustomerKMSCount: 3,
		LogGroups:                        []CloudWatchLogGroupRow{{Name: "east-1"}},
	}
	b := CloudWatchLogsMetrics{
		LogGroupCount:                    5,
		LogGroupsWithoutRetentionCount:   1,
		LogGroupsWithoutCustomerKMSCount: 5,
		LogGroups:                        []CloudWatchLogGroupRow{{Name: "west-1"}, {Name: "west-2"}},
	}
	got := mergeCloudWatchLogsMetrics(a, b)
	if got.LogGroupCount != 8 {
		t.Errorf("LogGroupCount: expected 8, got %d", got.LogGroupCount)
	}
	if got.LogGroupsWithoutRetentionCount != 3 {
		t.Errorf("LogGroupsWithoutRetentionCount: expected 3, got %d", got.LogGroupsWithoutRetentionCount)
	}
	if got.LogGroupsWithoutCustomerKMSCount != 8 {
		t.Errorf("LogGroupsWithoutCustomerKMSCount: expected 8, got %d", got.LogGroupsWithoutCustomerKMSCount)
	}
	if len(got.LogGroups) != 3 {
		t.Errorf("expected 3 log groups after merge, got %d", len(got.LogGroups))
	}
	if got.LogGroups[0].Name != "east-1" || got.LogGroups[2].Name != "west-2" {
		t.Errorf("merge did not preserve insertion order: %+v", got.LogGroups)
	}
}
