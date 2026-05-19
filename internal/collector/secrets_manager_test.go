package collector

import (
	"testing"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

func TestSecretsManagerSecretToRow_AuditOmitsInternalFields(t *testing.T) {
	changed := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	in := aws.SecretsManagerSecret{
		Name:              "prod/db/password",
		ARN:               "arn:aws:secretsmanager:us-east-1:123:secret:prod/db/password-abc123",
		Description:       "Postgres prod password",
		KMSKeyARN:         "arn:aws:kms:us-east-1:123:key/abc",
		RotationEnabled:   true,
		RotationLambdaARN: "arn:aws:lambda:us-east-1:123:function:rotator",
		RotationDays:      30,
		LastChangedDate:   &changed,
		Tags:              map[string]string{"Env": "prod"},
	}
	row := secretsManagerSecretToRow(in, "us-east-1", componentsdk.LevelAudit)

	if row.Name != "prod/db/password" || row.Region != "us-east-1" {
		t.Errorf("audit base fields mis-projected: %+v", row)
	}
	if row.LastChangedDate != "2026-05-14T10:00:00Z" {
		t.Errorf("expected RFC3339 last_changed_date, got %q", row.LastChangedDate)
	}
	if !row.RotationEnabled || row.RotationDays != 30 {
		t.Errorf("rotation fields must propagate at audit: %+v", row)
	}
	if !row.HasCustomerKMS {
		t.Errorf("HasCustomerKMS should be true when KMSKeyARN is set")
	}

	// Internal-only fields must be empty at audit level.
	if row.Description != "" {
		t.Errorf("audit-level row must omit Description (borderline sensitive), got %q", row.Description)
	}
	if row.KMSKeyARN != "" {
		t.Errorf("audit-level row must omit KMSKeyARN")
	}
	if row.RotationLambdaARN != "" {
		t.Errorf("audit-level row must omit RotationLambdaARN")
	}
	if len(row.Tags) != 0 {
		t.Errorf("audit-level row must omit Tags")
	}
}

func TestSecretsManagerSecretToRow_InternalPopulatesAllFields(t *testing.T) {
	in := aws.SecretsManagerSecret{
		Name:              "prod/api/stripe",
		Description:       "Stripe production API key",
		KMSKeyARN:         "arn:aws:kms:us-east-1:123:key/abc",
		RotationLambdaARN: "arn:aws:lambda:us-east-1:123:function:rotator",
		Tags:              map[string]string{"Env": "prod", "Service": "payments"},
	}
	row := secretsManagerSecretToRow(in, "us-east-1", componentsdk.LevelInternal)

	if row.Description != "Stripe production API key" {
		t.Errorf("internal must populate Description, got %q", row.Description)
	}
	if row.KMSKeyARN == "" || row.RotationLambdaARN == "" {
		t.Errorf("internal must populate KMS + rotation Lambda ARNs: %+v", row)
	}
	if len(row.Tags) != 2 {
		t.Errorf("internal must populate Tags, got %d entries", len(row.Tags))
	}
}

func TestSecretsManagerSecretToRow_PendingDeletionPopulatesDate(t *testing.T) {
	deletion := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	in := aws.SecretsManagerSecret{
		Name:         "prod/db/legacy",
		DeletionDate: &deletion,
	}
	row := secretsManagerSecretToRow(in, "us-east-1", componentsdk.LevelAudit)
	if row.DeletionDate != "2026-08-14T10:00:00Z" {
		t.Errorf("expected RFC3339 deletion_date, got %q", row.DeletionDate)
	}
}

func TestSecretsManagerSecretToRow_NoCustomerKMS(t *testing.T) {
	// Secret using AWS-managed key (aws/secretsmanager) — KMSKeyARN is empty.
	in := aws.SecretsManagerSecret{Name: "prod/db/legacy"}
	row := secretsManagerSecretToRow(in, "us-east-1", componentsdk.LevelAudit)
	if row.HasCustomerKMS {
		t.Errorf("HasCustomerKMS should be false for AWS-managed encryption")
	}
}

func TestMergeSecretsManagerMetrics_SumsAggregatesAndConcatsSecrets(t *testing.T) {
	a := SecretsManagerMetrics{
		SecretCount:                    3,
		SecretsWithoutRotationCount:    2,
		SecretsWithoutCustomerKMSCount: 1,
		SecretsPendingDeletionCount:    0,
		Secrets:                        []SecretsManagerSecretRow{{Name: "east-1"}, {Name: "east-2"}},
	}
	b := SecretsManagerMetrics{
		SecretCount:                    5,
		SecretsWithoutRotationCount:    1,
		SecretsWithoutCustomerKMSCount: 4,
		SecretsPendingDeletionCount:    1,
		Secrets:                        []SecretsManagerSecretRow{{Name: "west-1"}},
	}
	got := mergeSecretsManagerMetrics(a, b)
	if got.SecretCount != 8 {
		t.Errorf("SecretCount: expected 8, got %d", got.SecretCount)
	}
	if got.SecretsWithoutRotationCount != 3 {
		t.Errorf("SecretsWithoutRotationCount: expected 3, got %d", got.SecretsWithoutRotationCount)
	}
	if got.SecretsWithoutCustomerKMSCount != 5 {
		t.Errorf("SecretsWithoutCustomerKMSCount: expected 5, got %d", got.SecretsWithoutCustomerKMSCount)
	}
	if got.SecretsPendingDeletionCount != 1 {
		t.Errorf("SecretsPendingDeletionCount: expected 1, got %d", got.SecretsPendingDeletionCount)
	}
	if len(got.Secrets) != 3 {
		t.Errorf("expected 3 secrets after merge, got %d", len(got.Secrets))
	}
	if got.Secrets[0].Name != "east-1" || got.Secrets[2].Name != "west-1" {
		t.Errorf("merge did not preserve insertion order: %+v", got.Secrets)
	}
}
