//go:build e2e
// +build e2e

package collector

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// E2E tests run against real AWS APIs.
//
// To run:
//
//	AWS_E2E_RUN=true go test -tags=e2e -v ./internal/collector/...
//
// Required environment variables:
//
//	AWS_E2E_RUN=true
//
// Optional environment variables:
//
//	AWS_E2E_REGIONS=us-east-1,us-west-2
//	AWS_E2E_ROLE_ARN=arn:aws:iam::123456789012:role/EpackCollectorRole
//	AWS_E2E_EXTERNAL_ID=external-id-if-needed

func getE2EConfig(t *testing.T) Config {
	t.Helper()

	if strings.ToLower(os.Getenv("AWS_E2E_RUN")) != "true" {
		t.Skip("AWS_E2E_RUN=true not set, skipping e2e test")
	}

	cfg := Config{}

	if regions := os.Getenv("AWS_E2E_REGIONS"); regions != "" {
		for _, region := range strings.Split(regions, ",") {
			trimmed := strings.TrimSpace(region)
			if trimmed != "" {
				cfg.Regions = append(cfg.Regions, trimmed)
			}
		}
	}

	roleARN := strings.TrimSpace(os.Getenv("AWS_E2E_ROLE_ARN"))
	if roleARN != "" {
		cfg.Accounts = []AccountConfig{
			{
				RoleARN:    roleARN,
				ExternalID: strings.TrimSpace(os.Getenv("AWS_E2E_EXTERNAL_ID")),
			},
		}
	}

	return cfg
}

func TestE2E_RealAWSCollection(t *testing.T) {
	config := getE2EConfig(t)

	collector, err := New(config)
	if err != nil {
		t.Fatalf("failed to create collector: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	output, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("failed to collect: %v", err)
	}

	if output.SchemaVersion != SchemaVersion {
		t.Fatalf("schema_version = %q, want %q", output.SchemaVersion, SchemaVersion)
	}
	if output.CollectedAt == "" {
		t.Fatal("collected_at should not be empty")
	}
	if _, err := time.Parse(time.RFC3339, output.CollectedAt); err != nil {
		t.Fatalf("collected_at is not RFC3339: %v", err)
	}
	if len(output.Accounts) == 0 {
		t.Fatal("expected at least one account in output")
	}

	for i, acct := range output.Accounts {
		if len(acct.AccountID) != 12 {
			t.Errorf("accounts[%d].account_id should be 12 digits, got %q", i, acct.AccountID)
		}
		if len(acct.Regions) == 0 {
			t.Errorf("accounts[%d].regions should not be empty", i)
		}

		assertPercent(t, "iam.mfa_enabled", acct.IAM.MFAEnabled)
		assertPercent(t, "iam.hardware_mfa_enabled", acct.IAM.HardwareMFAEnabled)
		assertPercent(t, "iam.access_keys_rotated", acct.IAM.AccessKeysRotated)
		if !acct.IAM.IAMUsersPresent && acct.IAM.MFAEnabled != 0 {
			t.Errorf("iam.mfa_enabled should be 0 when iam_users_present=false, got %d", acct.IAM.MFAEnabled)
		}

		assertPercent(t, "s3.public_access_blocked", acct.S3.PublicAccessBlocked)
		assertPercent(t, "s3.default_encryption_enabled", acct.S3.DefaultEncryptionEnabled)
		assertPercent(t, "s3.versioning_enabled", acct.S3.VersioningEnabled)
		assertPercent(t, "s3.logging_enabled", acct.S3.LoggingEnabled)

		assertPercent(t, "rds.encrypted_at_rest", acct.RDS.EncryptedAtRest)
		assertPercent(t, "rds.publicly_accessible", acct.RDS.PubliclyAccessible)
		assertPercent(t, "rds.deletion_protection", acct.RDS.DeletionProtection)
		assertPercent(t, "rds.backup_retention_adequate", acct.RDS.BackupRetentionAdequate)
		assertPercent(t, "rds.multi_az_enabled", acct.RDS.MultiAZEnabled)

		assertPercent(t, "network.open_to_world_ssh", acct.Network.OpenToWorldSSH)
		assertPercent(t, "network.open_to_world_rdp", acct.Network.OpenToWorldRDP)
		assertPercent(t, "network.flow_logs_enabled", acct.Network.FlowLogsEnabled)

		assertPercent(t, "security_hub.level_1.compliance_percent", acct.AccountSecurity.SecurityHub.CISAWSFoundationsBenchmarkLevel1.CompliancePercent)
		assertPercent(t, "security_hub.level_2.compliance_percent", acct.AccountSecurity.SecurityHub.CISAWSFoundationsBenchmarkLevel2.CompliancePercent)
		assertPercent(t, "security_hub.unknown_level.compliance_percent", acct.AccountSecurity.SecurityHub.CISAWSFoundationsBenchmarkUnknownLevel.CompliancePercent)
		assertPercent(t, "inspector.unpatched_server_percent", acct.AccountSecurity.Inspector.UnpatchedServerPercent)
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	t.Logf("collection complete; accounts=%d\n%s", len(output.Accounts), string(data))
}

func TestE2E_OutputValidJSON(t *testing.T) {
	config := getE2EConfig(t)

	collector, err := New(config)
	if err != nil {
		t.Fatalf("failed to create collector: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	output, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("failed to collect: %v", err)
	}

	data, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("failed to marshal output: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	required := []string{"schema_version", "collected_at", "accounts"}
	for _, field := range required {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing required top-level field: %s", field)
		}
	}
}

func TestE2E_RespectsConfiguredRegions(t *testing.T) {
	regionsEnv := strings.TrimSpace(os.Getenv("AWS_E2E_REGIONS"))
	if regionsEnv == "" {
		t.Skip("AWS_E2E_REGIONS not set, skipping configured-regions e2e test")
	}

	config := getE2EConfig(t)
	if len(config.Regions) == 0 {
		t.Skip("no parsed regions from AWS_E2E_REGIONS")
	}

	collector, err := New(config)
	if err != nil {
		t.Fatalf("failed to create collector: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	output, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("failed to collect: %v", err)
	}

	for i, acct := range output.Accounts {
		if len(acct.Regions) != len(config.Regions) {
			t.Errorf("accounts[%d].regions length = %d, want %d", i, len(acct.Regions), len(config.Regions))
			continue
		}
		for j := range config.Regions {
			if acct.Regions[j] != config.Regions[j] {
				t.Errorf("accounts[%d].regions[%d] = %q, want %q", i, j, acct.Regions[j], config.Regions[j])
			}
		}
	}
}

func assertPercent(t *testing.T, name string, v int) {
	t.Helper()
	if v < 0 || v > 100 {
		t.Errorf("%s should be in [0,100], got %d", name, v)
	}
}
