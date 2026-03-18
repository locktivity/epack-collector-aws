package collector

import (
	"encoding/json"
	"testing"
)

func TestToCloudPosture(t *testing.T) {
	// Test transformation from Output to normalized CloudPosture
	output := &Output{
		SchemaVersion: "1.0.0",
		CollectedAt:   "2024-01-15T10:00:00Z",
		Accounts: []AccountPosture{
			{
				AccountID: "123456789012",
				Regions:   []string{"us-east-1", "us-west-2"},
				IAM: IAMMetrics{
					MFAEnabled:         80,
					RootMFAEnabled:     true,
					AccessKeysRotated:  90,
					HardwareMFAEnabled: 30,
				},
				S3: S3Metrics{
					DefaultEncryptionEnabled: 95,
					PublicAccessBlocked:      100,
					VersioningEnabled:        75,
				},
				RDS: RDSMetrics{
					EncryptedAtRest:         100,
					BackupRetentionAdequate: 100,
					BackupRetentionMin:      14,
				},
				Network: NetworkMetrics{
					OpenToWorldSSH:  5,
					OpenToWorldRDP:  0,
					FlowLogsEnabled: 85,
				},
				AccountSecurity: AccountSecurity{
					CloudTrail: CloudTrailStatus{
						Enabled:            true,
						MultiRegionEnabled: true,
					},
					Inspector: InspectorStatus{
						Enabled:                true,
						UnpatchedServerPercent: 10,
					},
				},
			},
		},
	}

	cloudPosture := output.ToCloudPosture()

	// Verify basic fields
	if cloudPosture.SchemaVersion != "1.0.0" {
		t.Errorf("SchemaVersion = %q, want %q", cloudPosture.SchemaVersion, "1.0.0")
	}
	if cloudPosture.Provider != "aws" {
		t.Errorf("Provider = %q, want %q", cloudPosture.Provider, "aws")
	}
	if len(cloudPosture.Accounts) != 1 {
		t.Fatalf("len(Accounts) = %d, want 1", len(cloudPosture.Accounts))
	}

	acct := cloudPosture.Accounts[0]

	// Verify account ID
	if acct.AccountID != "123456789012" {
		t.Errorf("AccountID = %q, want %q", acct.AccountID, "123456789012")
	}

	// Verify IAM mappings
	if acct.IAM.MFACoveragePct != 80 {
		t.Errorf("IAM.MFACoveragePct = %v, want 80", acct.IAM.MFACoveragePct)
	}
	if !acct.IAM.RootMFAEnabled {
		t.Error("IAM.RootMFAEnabled = false, want true")
	}
	if acct.IAM.AccessKeyRotationCompliantPct != 90 {
		t.Errorf("IAM.AccessKeyRotationCompliantPct = %v, want 90", acct.IAM.AccessKeyRotationCompliantPct)
	}

	// Verify Storage mappings
	if acct.Storage.EncryptionPct != 95 {
		t.Errorf("Storage.EncryptionPct = %v, want 95", acct.Storage.EncryptionPct)
	}
	if acct.Storage.PublicAccessBlockedPct != 100 {
		t.Errorf("Storage.PublicAccessBlockedPct = %v, want 100", acct.Storage.PublicAccessBlockedPct)
	}

	// Verify Logging mappings
	if !acct.Logging.CloudTrailEnabled {
		t.Error("Logging.CloudTrailEnabled = false, want true")
	}
	if !acct.Logging.CloudTrailMultiregion {
		t.Error("Logging.CloudTrailMultiregion = false, want true")
	}
	if acct.Logging.FlowLogsPct != 85 {
		t.Errorf("Logging.FlowLogsPct = %v, want 85", acct.Logging.FlowLogsPct)
	}

	// Verify Network mappings
	if acct.Network.SSHOpenToWorldPct != 5 {
		t.Errorf("Network.SSHOpenToWorldPct = %v, want 5", acct.Network.SSHOpenToWorldPct)
	}
	if acct.Network.RDPOpenToWorldPct != 0 {
		t.Errorf("Network.RDPOpenToWorldPct = %v, want 0", acct.Network.RDPOpenToWorldPct)
	}

	// Verify Backup mappings (using actual min retention from RDS)
	if acct.Backup.RetentionDaysMin != 14 {
		t.Errorf("Backup.RetentionDaysMin = %d, want 14", acct.Backup.RetentionDaysMin)
	}

	// Verify VulnScanning mappings
	if !acct.VulnScanning.Enabled {
		t.Error("VulnScanning.Enabled = false, want true")
	}
	if acct.VulnScanning.UnpatchedPct != 10 {
		t.Errorf("VulnScanning.UnpatchedPct = %v, want 10", acct.VulnScanning.UnpatchedPct)
	}
}

func TestToCloudPosture_MultipleAccounts(t *testing.T) {
	// Test transformation with multiple accounts
	output := &Output{
		SchemaVersion: "1.0.0",
		Accounts: []AccountPosture{
			{
				AccountID: "111111111111",
				IAM:       IAMMetrics{MFAEnabled: 100, RootMFAEnabled: true},
			},
			{
				AccountID: "222222222222",
				IAM:       IAMMetrics{MFAEnabled: 50, RootMFAEnabled: false},
			},
		},
	}

	cloudPosture := output.ToCloudPosture()

	if len(cloudPosture.Accounts) != 2 {
		t.Fatalf("len(Accounts) = %d, want 2", len(cloudPosture.Accounts))
	}

	// Verify first account
	if cloudPosture.Accounts[0].AccountID != "111111111111" {
		t.Errorf("Accounts[0].AccountID = %q, want %q", cloudPosture.Accounts[0].AccountID, "111111111111")
	}
	if cloudPosture.Accounts[0].IAM.MFACoveragePct != 100 {
		t.Errorf("Accounts[0].IAM.MFACoveragePct = %v, want 100", cloudPosture.Accounts[0].IAM.MFACoveragePct)
	}

	// Verify second account
	if cloudPosture.Accounts[1].AccountID != "222222222222" {
		t.Errorf("Accounts[1].AccountID = %q, want %q", cloudPosture.Accounts[1].AccountID, "222222222222")
	}
	if cloudPosture.Accounts[1].IAM.MFACoveragePct != 50 {
		t.Errorf("Accounts[1].IAM.MFACoveragePct = %v, want 50", cloudPosture.Accounts[1].IAM.MFACoveragePct)
	}
}

func TestToCloudPosture_EmptyAccounts(t *testing.T) {
	// Test transformation with no accounts
	output := &Output{
		SchemaVersion: "1.0.0",
		Accounts:      []AccountPosture{},
	}

	cloudPosture := output.ToCloudPosture()

	if cloudPosture.Provider != "aws" {
		t.Errorf("Provider = %q, want %q", cloudPosture.Provider, "aws")
	}
	if len(cloudPosture.Accounts) != 0 {
		t.Errorf("len(Accounts) = %d, want 0", len(cloudPosture.Accounts))
	}
}

func TestToCloudPosture_ZeroRetention(t *testing.T) {
	// Test that zero retention (backups disabled) is correctly passed through
	output := &Output{
		SchemaVersion: "1.0.0",
		Accounts: []AccountPosture{
			{
				AccountID: "123456789012",
				RDS: RDSMetrics{
					BackupRetentionMin: 0, // Backups disabled
				},
			},
		},
	}

	cloudPosture := output.ToCloudPosture()

	if cloudPosture.Accounts[0].Backup.RetentionDaysMin != 0 {
		t.Errorf("Backup.RetentionDaysMin = %d, want 0", cloudPosture.Accounts[0].Backup.RetentionDaysMin)
	}
}

func TestCloudPostureJSONStructure(t *testing.T) {
	// Test that CloudPosture JSON output matches cloud-posture@v1 schema
	output := &Output{
		SchemaVersion: "1.0.0",
		Accounts: []AccountPosture{
			{
				AccountID: "123456789012",
				IAM: IAMMetrics{
					MFAEnabled:        100,
					RootMFAEnabled:    true,
					AccessKeysRotated: 95,
				},
				S3: S3Metrics{
					DefaultEncryptionEnabled: 100,
					PublicAccessBlocked:      100,
				},
				Network: NetworkMetrics{
					OpenToWorldSSH:  0,
					OpenToWorldRDP:  0,
					FlowLogsEnabled: 100,
				},
				RDS: RDSMetrics{
					BackupRetentionAdequate: 100,
					BackupRetentionMin:      7,
				},
				AccountSecurity: AccountSecurity{
					CloudTrail: CloudTrailStatus{
						Enabled:            true,
						MultiRegionEnabled: true,
					},
					Inspector: InspectorStatus{
						Enabled:                true,
						UnpatchedServerPercent: 5,
					},
				},
			},
		},
	}

	cloudPosture := output.ToCloudPosture()

	// Marshal to JSON and unmarshal to map to verify structure
	jsonBytes, err := json.Marshal(cloudPosture)
	if err != nil {
		t.Fatalf("failed to marshal CloudPosture: %v", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	// Check top-level required fields per cloud-posture@v1 schema
	topLevelRequired := []string{
		"schema_version", "collected_at", "provider", "accounts",
	}
	for _, field := range topLevelRequired {
		if _, ok := data[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}

	// Check accounts array
	accounts, ok := data["accounts"].([]interface{})
	if !ok {
		t.Fatal("accounts is not an array")
	}
	if len(accounts) != 1 {
		t.Fatalf("len(accounts) = %d, want 1", len(accounts))
	}

	acct, ok := accounts[0].(map[string]interface{})
	if !ok {
		t.Fatal("accounts[0] is not an object")
	}

	// Check account required fields
	acctRequired := []string{
		"account_id", "iam", "storage", "logging", "network", "backup", "vuln_scanning",
	}
	for _, field := range acctRequired {
		if _, ok := acct[field]; !ok {
			t.Errorf("account missing required field: %s", field)
		}
	}

	// Check iam fields
	iam, ok := acct["iam"].(map[string]interface{})
	if !ok {
		t.Fatal("iam is not an object")
	}
	iamFields := []string{"mfa_coverage_pct", "root_mfa_enabled", "access_key_rotation_compliant_pct"}
	for _, field := range iamFields {
		if _, ok := iam[field]; !ok {
			t.Errorf("iam missing required field: %s", field)
		}
	}

	// Check storage fields
	storage, ok := acct["storage"].(map[string]interface{})
	if !ok {
		t.Fatal("storage is not an object")
	}
	storageFields := []string{"encryption_pct", "public_access_blocked_pct"}
	for _, field := range storageFields {
		if _, ok := storage[field]; !ok {
			t.Errorf("storage missing required field: %s", field)
		}
	}

	// Check logging fields
	logging, ok := acct["logging"].(map[string]interface{})
	if !ok {
		t.Fatal("logging is not an object")
	}
	loggingFields := []string{"cloudtrail_enabled", "cloudtrail_multiregion", "flow_logs_pct"}
	for _, field := range loggingFields {
		if _, ok := logging[field]; !ok {
			t.Errorf("logging missing required field: %s", field)
		}
	}

	// Check network fields
	network, ok := acct["network"].(map[string]interface{})
	if !ok {
		t.Fatal("network is not an object")
	}
	networkFields := []string{"ssh_open_to_world_pct", "rdp_open_to_world_pct"}
	for _, field := range networkFields {
		if _, ok := network[field]; !ok {
			t.Errorf("network missing required field: %s", field)
		}
	}

	// Check backup fields
	backup, ok := acct["backup"].(map[string]interface{})
	if !ok {
		t.Fatal("backup is not an object")
	}
	if _, ok := backup["retention_days_min"]; !ok {
		t.Error("backup missing required field: retention_days_min")
	}

	// Check vuln_scanning fields
	vulnScanning, ok := acct["vuln_scanning"].(map[string]interface{})
	if !ok {
		t.Fatal("vuln_scanning is not an object")
	}
	vulnFields := []string{"enabled", "unpatched_pct"}
	for _, field := range vulnFields {
		if _, ok := vulnScanning[field]; !ok {
			t.Errorf("vuln_scanning missing required field: %s", field)
		}
	}
}
