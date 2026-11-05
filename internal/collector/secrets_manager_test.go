package collector

import (
	"fmt"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
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

// runOutput runs the kit's account with responses and decodes the detailed
// artifact.
func runOutput(t *testing.T, responses []collectortest.Response) Output {
	t.Helper()
	isolateAWSEnvironment(t)
	res := runKit(t, kitConfig(), kitSecrets(), responses)
	if res.ExitCode != 0 {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	var out Output
	decodeArtifact(t, res, awsPath, &out)
	if len(out.Accounts) != 1 {
		t.Fatalf("accounts = %d, want 1", len(out.Accounts))
	}
	return out
}

const deletedSecretARN = "arn:aws:secretsmanager:us-east-1:111122223333:secret:northwind/old-ZyXwVu"

func rotatedSecret() map[string]any {
	return map[string]any{
		"ARN": "arn:aws:secretsmanager:us-east-1:111122223333:secret:northwind/db-AbCdEf", "Name": "northwind/db", "Description": "Database credentials",
		"KmsKeyId": "arn:aws:kms:us-east-1:111122223333:key/" + kitKMSKeyID, "RotationEnabled": true,
		"RotationLambdaARN": "arn:aws:lambda:us-east-1:111122223333:function:rotate-db", "RotationRules": map[string]any{"AutomaticallyAfterDays": 30},
		"CreatedDate": 1704067200, "LastChangedDate": 1764547200,
	}
}

// ListSecrets returns a secret scheduled for deletion only when the request
// sets IncludePlannedDeletion, and the collector asks for it.
func TestSecretsManager_SecretsPendingDeletionAreListed(t *testing.T) {
	deleted := map[string]any{"ARN": deletedSecretARN, "Name": "northwind/old", "CreatedDate": 1704067200, "LastChangedDate": 1764547200, "DeletedDate": 1769904000}
	withDeleted := jsonItemResponse("aws.secretsmanager.ListSecrets", regional("secretsmanager"),
		map[string]any{"IncludePlannedDeletion": true},
		map[string]any{"SecretList": []any{rotatedSecret(), deleted}})

	sm := runOutput(t, append([]collectortest.Response{withDeleted}, kitResponses()...)).Accounts[0].SecretsManager

	if sm.SecretCount != 2 || sm.SecretsPendingDeletionCount != 1 {
		t.Errorf("secret_count = %d, secrets_pending_deletion_count = %d; want 2 and 1", sm.SecretCount, sm.SecretsPendingDeletionCount)
	}
	found := false
	for _, row := range sm.Secrets {
		if row.ARN == deletedSecretARN {
			found = true
			if row.DeletionDate != "2026-02-01T00:00:00Z" {
				t.Errorf("deletion_date = %q, want 2026-02-01T00:00:00Z", row.DeletionDate)
			}
		}
	}
	if !found {
		t.Errorf("secrets = %d rows, none for the secret scheduled for deletion", len(sm.Secrets))
	}
}

// The rotation rules keep their schedule after rotation is turned off, so a
// row with rotation off has no rotation days or function.
func TestSecretsManager_RotationOffCarriesNoSchedule(t *testing.T) {
	off := rotatedSecret()
	off["RotationEnabled"] = false
	for _, tc := range []struct {
		name   string
		secret map[string]any
		days   int64
		lambda bool
	}{
		{"rotation on", rotatedSecret(), 30, true},
		{"rotation off", off, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			responses := replaceResponses(kitResponses(),
				jsonResponse("aws.secretsmanager.ListSecrets", regional("secretsmanager"), map[string]any{"SecretList": []any{tc.secret}}))
			rows := runOutput(t, responses).Accounts[0].SecretsManager.Secrets
			if len(rows) != 1 {
				t.Fatalf("rows = %d, want 1", len(rows))
			}
			if rows[0].RotationDays != tc.days || (rows[0].RotationLambdaARN != "") != tc.lambda {
				t.Errorf("rotation_days = %d, rotation_lambda_arn = %q; want %d and a function: %v", rows[0].RotationDays, rows[0].RotationLambdaARN, tc.days, tc.lambda)
			}
		})
	}
}

// A secret can carry 50 tags of its own beside aws: tags, which do not count
// against AWS's limit. Every one of its own tags reaches the row.
func TestSecretsManager_RowKeepsEveryOwnTagBesideSystemTags(t *testing.T) {
	tags := []any{map[string]any{"Key": "team", "Value": "platform"}}
	for i := 1; i < 50; i++ {
		tags = append(tags, map[string]any{"Key": fmt.Sprintf("tag-%02d", i), "Value": "v"})
	}
	for _, key := range []string{"aws:cloudformation:stack-name", "aws:cloudformation:logical-id", "aws:cloudformation:stack-id"} {
		tags = append(tags, map[string]any{"Key": key, "Value": "northwind"})
	}
	secret := rotatedSecret()
	secret["Tags"] = tags
	rows := runOutput(t, replaceResponses(kitResponses(),
		jsonResponse("aws.secretsmanager.ListSecrets", regional("secretsmanager"), map[string]any{"SecretList": []any{secret}}))).Accounts[0].SecretsManager.Secrets
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	for _, tag := range tags[:50] {
		if key := tag.(map[string]any)["Key"].(string); rows[0].Tags[key] == "" {
			t.Errorf("tags/%s is missing from the row", key)
		}
	}
}
