package collector

import (
	"testing"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

func TestMergeCISLevelCompliance(t *testing.T) {
	target := &CISComplianceByLevel{
		PassedControls:       1,
		FailedControls:       2,
		WarningControls:      3,
		NotAvailableControls: 4,
	}

	source := aws.SecurityHubCISCompliance{
		PassedControls:       10,
		FailedControls:       20,
		WarningControls:      30,
		NotAvailableControls: 40,
	}

	mergeCISLevelCompliance(target, source)

	if target.PassedControls != 11 {
		t.Fatalf("expected passed_controls=11, got %d", target.PassedControls)
	}
	if target.FailedControls != 22 {
		t.Fatalf("expected failed_controls=22, got %d", target.FailedControls)
	}
	if target.WarningControls != 33 {
		t.Fatalf("expected warning_controls=33, got %d", target.WarningControls)
	}
	if target.NotAvailableControls != 44 {
		t.Fatalf("expected not_available_controls=44, got %d", target.NotAvailableControls)
	}
}

func TestFinalizeCISLevelCompliance(t *testing.T) {
	t.Run("failed controls", func(t *testing.T) {
		level := &CISComplianceByLevel{
			PassedControls: 2,
			FailedControls: 1,
		}

		finalizeCISLevelCompliance(level)

		if !level.Enabled {
			t.Fatalf("expected enabled=true")
		}
		if level.CompliancePercent != 66 {
			t.Fatalf("expected compliance_percent=66, got %d", level.CompliancePercent)
		}
		if level.ComplianceState != "FAILED" {
			t.Fatalf("expected compliance_state=FAILED, got %s", level.ComplianceState)
		}
	})

	t.Run("not available only", func(t *testing.T) {
		level := &CISComplianceByLevel{
			NotAvailableControls: 3,
		}

		finalizeCISLevelCompliance(level)

		if !level.Enabled {
			t.Fatalf("expected enabled=true")
		}
		if level.CompliancePercent != 0 {
			t.Fatalf("expected compliance_percent=0, got %d", level.CompliancePercent)
		}
		if level.ComplianceState != "NOT_AVAILABLE" {
			t.Fatalf("expected compliance_state=NOT_AVAILABLE, got %s", level.ComplianceState)
		}
	})

	t.Run("empty", func(t *testing.T) {
		level := &CISComplianceByLevel{}

		finalizeCISLevelCompliance(level)

		if level.Enabled {
			t.Fatalf("expected enabled=false")
		}
		if level.ComplianceState != "UNKNOWN" {
			t.Fatalf("expected compliance_state=UNKNOWN, got %s", level.ComplianceState)
		}
	})
}

func TestCISComplianceStatePrecedence(t *testing.T) {
	tests := []struct {
		name         string
		passed       int
		failed       int
		warning      int
		notAvailable int
		want         string
	}{
		{name: "failed wins", passed: 10, failed: 1, warning: 2, notAvailable: 3, want: "FAILED"},
		{name: "warning wins when no failed", passed: 10, failed: 0, warning: 2, notAvailable: 3, want: "WARNING"},
		{name: "passed wins when no failed or warning", passed: 10, failed: 0, warning: 0, notAvailable: 3, want: "PASSED"},
		{name: "not available only", passed: 0, failed: 0, warning: 0, notAvailable: 3, want: "NOT_AVAILABLE"},
		{name: "empty", passed: 0, failed: 0, warning: 0, notAvailable: 0, want: "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cisComplianceState(tt.passed, tt.failed, tt.warning, tt.notAvailable)
			if got != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, got)
			}
		})
	}
}

func TestCISStandardHelpers(t *testing.T) {
	if !isCISStandard("arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0") {
		t.Fatalf("expected CIS standard ARN to be detected")
	}
	if isCISStandard("arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0") {
		t.Fatalf("did not expect non-CIS standard ARN to be detected as CIS")
	}

	gotID := standardIDFromARN("arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0")
	wantID := "standards/cis-aws-foundations-benchmark/v/1.4.0"
	if gotID != wantID {
		t.Fatalf("expected standard id %q, got %q", wantID, gotID)
	}

	if standardIDFromARN("invalid-arn") != "" {
		t.Fatalf("expected empty standard id for invalid ARN")
	}
}

func TestTrailsToInventory_ProjectsFields(t *testing.T) {
	kmsKey := "arn:aws:kms:us-east-1:123:key/abc"
	cwLogs := "arn:aws:logs:us-east-1:123:log-group:/aws/cloudtrail/main:*"
	in := []aws.Trail{
		{
			Name:                      "main-trail",
			S3BucketName:              "audit-logs",
			IsMultiRegionTrail:        true,
			LogFileValidationEnabled:  true,
			KMSKeyId:                  &kmsKey,
			CloudWatchLogsLogGroupArn: &cwLogs,
			IsLogging:                 true,
		},
		{
			Name:               "second-trail",
			S3BucketName:       "secondary-logs",
			IsMultiRegionTrail: false,
			IsLogging:          false,
		},
	}
	out := trailsToInventory(in, componentsdk.LevelAudit)
	if len(out) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(out))
	}
	if out[0].Name != "main-trail" || !out[0].KMSEncrypted || !out[0].CloudWatchLogsEnabled {
		t.Errorf("trail 0 mis-projected: %+v", out[0])
	}
	if out[1].KMSEncrypted || out[1].CloudWatchLogsEnabled {
		t.Errorf("trail 1 (no KMS / no CW) should have both false: %+v", out[1])
	}
	if out[0].KMSKeyARN != "" || out[0].CloudWatchLogsARN != "" {
		t.Errorf("audit level must not populate ARNs: %+v", out[0])
	}
}

func TestTrailsToInventory_InternalPopulatesARNs(t *testing.T) {
	kmsKey := "arn:aws:kms:us-east-1:123:key/abc"
	cwLogs := "arn:aws:logs:us-east-1:123:log-group:/aws/cloudtrail/main:*"
	in := []aws.Trail{
		{
			Name:                      "main-trail",
			KMSKeyId:                  &kmsKey,
			CloudWatchLogsLogGroupArn: &cwLogs,
		},
		{Name: "no-extras"},
	}
	out := trailsToInventory(in, componentsdk.LevelInternal)
	if out[0].KMSKeyARN != kmsKey {
		t.Errorf("internal should populate KMSKeyARN, got %q", out[0].KMSKeyARN)
	}
	if out[0].CloudWatchLogsARN != cwLogs {
		t.Errorf("internal should populate CloudWatchLogsARN, got %q", out[0].CloudWatchLogsARN)
	}
	if out[1].KMSKeyARN != "" || out[1].CloudWatchLogsARN != "" {
		t.Errorf("trail with nil pointers should have empty ARNs: %+v", out[1])
	}
}

func TestTrailsToInventory_EmptyKMSKeyStringIsNoEncryption(t *testing.T) {
	// AWS sometimes returns a non-nil pointer to an empty string for KMSKeyId.
	// Treat empty-string the same as nil.
	emptyKey := ""
	in := []aws.Trail{{Name: "t", KMSKeyId: &emptyKey}}
	out := trailsToInventory(in, componentsdk.LevelAudit)
	if out[0].KMSEncrypted {
		t.Errorf("empty KMS key string should be treated as no encryption, got KMSEncrypted=true")
	}
}

func TestConfigRecordersToInventory_StampsRegion(t *testing.T) {
	in := []aws.ConfigRecorder{
		{Name: "default", AllSupported: true, IncludeGlobal: true, Recording: true},
		{Name: "custom", RoleARN: "arn:aws:iam::123:role/config", AllSupported: false, Recording: false},
	}
	out := configRecordersToInventory(in, "us-east-1")
	if len(out) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(out))
	}
	if out[0].Region != "us-east-1" || !out[0].AllSupported || !out[0].IncludeGlobal || !out[0].Recording {
		t.Errorf("recorder 0 mis-projected: %+v", out[0])
	}
	if out[1].Name != "custom" || out[1].RoleARN != "arn:aws:iam::123:role/config" || out[1].AllSupported || out[1].Recording {
		t.Errorf("recorder 1 mis-projected: %+v", out[1])
	}
}

func TestConfigRulesToInventory_StampsRegionAndFormatsTimestamp(t *testing.T) {
	evaluated := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	in := []aws.ConfigRule{
		{
			Name:             "iam-password-policy",
			ARN:              "arn:aws:config:us-east-1:123:config-rule/config-rule-abc",
			SourceOwner:      "AWS",
			SourceIdentifier: "IAM_PASSWORD_POLICY",
			ComplianceState:  "COMPLIANT",
			LastEvaluated:    &evaluated,
		},
		{Name: "never-evaluated", SourceOwner: "CUSTOM_LAMBDA"},
	}
	out := configRulesToInventory(in, "us-east-1")
	if len(out) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(out))
	}
	if out[0].Region != "us-east-1" || out[0].SourceIdentifier != "IAM_PASSWORD_POLICY" || out[0].ComplianceState != "COMPLIANT" {
		t.Errorf("rule 0 mis-projected: %+v", out[0])
	}
	if out[0].LastEvaluated != "2026-05-14T10:00:00Z" {
		t.Errorf("expected RFC3339 timestamp, got %q", out[0].LastEvaluated)
	}
	if out[1].LastEvaluated != "" {
		t.Errorf("rule with nil timestamp should have empty LastEvaluated, got %q", out[1].LastEvaluated)
	}
	if out[1].SourceOwner != "CUSTOM_LAMBDA" {
		t.Errorf("custom source owner mis-projected: %+v", out[1])
	}
}

func TestGuardDutyFindingToRow_FormatsTimestampsAndStampsRegion(t *testing.T) {
	created := time.Date(2026, 5, 10, 8, 0, 0, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 9, 30, 0, 0, time.UTC)
	in := aws.GuardDutyFinding{
		ID:           "f-1",
		DetectorID:   "det-1",
		Severity:     8.5,
		Type:         "UnauthorizedAccess:IAMUser/ConsoleLogin",
		Title:        "Suspicious console login",
		ResourceType: "AccessKey",
		ResourceID:   "alice",
		CreatedAt:    &created,
		UpdatedAt:    &updated,
	}
	row := guardDutyFindingToRow(in, "us-west-2")
	if row.Region != "us-west-2" {
		t.Errorf("region not stamped: %+v", row)
	}
	if row.Severity != 8.5 || row.Type != in.Type || row.ResourceID != "alice" {
		t.Errorf("finding mis-projected: %+v", row)
	}
	if row.CreatedAt != "2026-05-10T08:00:00Z" {
		t.Errorf("expected RFC3339 created_at, got %q", row.CreatedAt)
	}
	if row.UpdatedAt != "2026-05-14T09:30:00Z" {
		t.Errorf("expected RFC3339 updated_at, got %q", row.UpdatedAt)
	}
}

func TestGuardDutyFindingToRow_NilTimestampsOmitFields(t *testing.T) {
	row := guardDutyFindingToRow(aws.GuardDutyFinding{ID: "f-2", DetectorID: "det-1", Severity: 7}, "us-east-1")
	if row.CreatedAt != "" || row.UpdatedAt != "" {
		t.Errorf("nil timestamps must yield empty strings (for omitempty), got created=%q updated=%q", row.CreatedAt, row.UpdatedAt)
	}
}

func TestGuardDutyDetectorToRow_PreservesAllFields(t *testing.T) {
	d := aws.GuardDutyDetector{
		DetectorID:                             "det-abc",
		Status:                                 "ENABLED",
		FindingPublishingFreq:                  "FIFTEEN_MINUTES",
		S3LogsEnabled:                          true,
		EKSAuditLogsEnabled:                    true,
		MalwareScanEnabled:                     false,
		HighOrCriticalFindings:                 5,
		HighOrCriticalFindingsOlderThan48Hours: 2,
	}
	row := guardDutyDetectorToRow(d, "us-west-2")
	if row.Region != "us-west-2" {
		t.Errorf("region not stamped: %+v", row)
	}
	if row.DetectorID != "det-abc" || row.Status != "ENABLED" || !row.S3LogsEnabled || row.MalwareScanEnabled {
		t.Errorf("detector fields mis-projected: %+v", row)
	}
	if row.HighOrCriticalFindings != 5 || row.HighOrCriticalFindingsOlderThan48Hours != 2 {
		t.Errorf("finding counts mis-projected: %+v", row)
	}
}
