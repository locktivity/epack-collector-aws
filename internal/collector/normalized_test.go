package collector

import (
	"encoding/json"
	"testing"
)

// evaluatedAccountFixture returns an AccountPosture with every family's
// evaluated sentinels set, so all normalized metrics should be present.
func evaluatedAccountFixture() AccountPosture {
	return AccountPosture{
		AccountID: "123456789012",
		Regions:   []string{"us-east-1", "us-west-2"},
		IAM: IAMMetrics{
			CredentialReportEvaluated:    true,
			RootCredentialStateEvaluated: true,
			MFAEnabled:                   80,
			RootMFAEnabled:               true,
			RootAccessProtected:          true,
			AccessKeysRotated:            90,
			HardwareMFAEnabled:           30,
		},
		S3: S3Metrics{
			BucketListingEvaluated:          true,
			BucketCount:                     20,
			DefaultEncryptionEnabled:        95,
			DefaultEncryptionEvaluatedCount: 20,
			PublicAccessBlocked:             100,
			VersioningEnabled:               75,
		},
		RDS: RDSMetrics{
			RegionsEvaluatedCount:   2,
			DatabaseCount:           3,
			EncryptedAtRest:         100,
			BackupRetentionAdequate: 100,
			BackupRetentionMin:      14,
		},
		Network: NetworkMetrics{
			RegionsEvaluatedCount: 2,
			OpenToWorldSSH:        5,
			OpenToWorldRDP:        0,
		},
		AccountSecurity: AccountSecurity{
			CloudTrail: CloudTrailStatus{
				TrailListingEvaluated: true,
				Enabled:               true,
				MultiRegionEnabled:    true,
			},
			Inspector: InspectorStatus{
				StatusEvaluated:        true,
				Enabled:                true,
				UnpatchedServerPercent: 10,
			},
		},
	}
}

func TestToCloudPosture(t *testing.T) {
	output := &Output{
		SchemaVersion: "1.0.0",
		CollectedAt:   "2024-01-15T10:00:00Z",
		Accounts:      []AccountPosture{evaluatedAccountFixture()},
	}

	cloudPosture := output.ToCloudPosture()

	if cloudPosture.SchemaVersion != "1.0.0" {
		t.Errorf("SchemaVersion = %q, want %q", cloudPosture.SchemaVersion, "1.0.0")
	}
	if cloudPosture.Provider != "aws" {
		t.Errorf("Provider = %q, want %q", cloudPosture.Provider, "aws")
	}
	if cloudPosture.AccountsExpected != 1 {
		t.Errorf("AccountsExpected = %d, want 1", cloudPosture.AccountsExpected)
	}
	if len(cloudPosture.Accounts) != 1 {
		t.Fatalf("len(Accounts) = %d, want 1", len(cloudPosture.Accounts))
	}

	acct := cloudPosture.Accounts[0]

	if acct.AccountID != "123456789012" {
		t.Errorf("AccountID = %q, want %q", acct.AccountID, "123456789012")
	}
	if acct.CollectionErrorCode != "" {
		t.Errorf("CollectionErrorCode = %q, want empty", acct.CollectionErrorCode)
	}

	if acct.IAM.MFACoveragePct == nil || *acct.IAM.MFACoveragePct != 80 {
		t.Errorf("IAM.MFACoveragePct = %v, want 80", acct.IAM.MFACoveragePct)
	}
	if acct.IAM.RootMFAEnabled == nil || !*acct.IAM.RootMFAEnabled {
		t.Error("IAM.RootMFAEnabled != true, want true")
	}
	if acct.IAM.RootAccessProtected == nil || !*acct.IAM.RootAccessProtected {
		t.Error("IAM.RootAccessProtected != true, want true")
	}
	if acct.IAM.AccessKeyRotationCompliantPct == nil || *acct.IAM.AccessKeyRotationCompliantPct != 90 {
		t.Errorf("IAM.AccessKeyRotationCompliantPct = %v, want 90", acct.IAM.AccessKeyRotationCompliantPct)
	}

	if acct.Storage.EncryptionPct == nil || *acct.Storage.EncryptionPct != 95 {
		t.Errorf("Storage.EncryptionPct = %v, want 95", acct.Storage.EncryptionPct)
	}
	if acct.Storage.PublicAccessBlockedPct == nil || *acct.Storage.PublicAccessBlockedPct != 100 {
		t.Errorf("Storage.PublicAccessBlockedPct = %v, want 100", acct.Storage.PublicAccessBlockedPct)
	}

	if acct.Logging.CloudTrailEnabled == nil || !*acct.Logging.CloudTrailEnabled {
		t.Error("Logging.CloudTrailEnabled != true, want true")
	}
	if acct.Logging.CloudTrailMultiregion == nil || !*acct.Logging.CloudTrailMultiregion {
		t.Error("Logging.CloudTrailMultiregion != true, want true")
	}

	if acct.Network.SSHOpenToWorldPct == nil || *acct.Network.SSHOpenToWorldPct != 5 {
		t.Errorf("Network.SSHOpenToWorldPct = %v, want 5", acct.Network.SSHOpenToWorldPct)
	}
	if acct.Network.RDPOpenToWorldPct == nil || *acct.Network.RDPOpenToWorldPct != 0 {
		t.Errorf("Network.RDPOpenToWorldPct = %v, want 0", acct.Network.RDPOpenToWorldPct)
	}

	if acct.Backup.RetentionDaysMin == nil || *acct.Backup.RetentionDaysMin != 14 {
		t.Errorf("Backup.RetentionDaysMin = %v, want 14", acct.Backup.RetentionDaysMin)
	}

	if acct.VulnScanning.Enabled == nil || !*acct.VulnScanning.Enabled {
		t.Error("VulnScanning.Enabled != true, want true")
	}
	if acct.VulnScanning.UnpatchedPct == nil || *acct.VulnScanning.UnpatchedPct != 10 {
		t.Errorf("VulnScanning.UnpatchedPct = %v, want 10", acct.VulnScanning.UnpatchedPct)
	}
}

func TestToCloudPosture_MultipleAccounts(t *testing.T) {
	output := &Output{
		SchemaVersion: "1.0.0",
		Accounts: []AccountPosture{
			{
				AccountID: "111111111111",
				IAM:       IAMMetrics{CredentialReportEvaluated: true, RootCredentialStateEvaluated: true, MFAEnabled: 100, RootMFAEnabled: true, RootAccessProtected: true},
			},
			{
				AccountID: "222222222222",
				IAM:       IAMMetrics{CredentialReportEvaluated: true, RootCredentialStateEvaluated: true, MFAEnabled: 50, RootMFAEnabled: false, RootAccessProtected: false},
			},
		},
	}

	cloudPosture := output.ToCloudPosture()

	if len(cloudPosture.Accounts) != 2 {
		t.Fatalf("len(Accounts) = %d, want 2", len(cloudPosture.Accounts))
	}
	if cloudPosture.AccountsExpected != 2 {
		t.Errorf("AccountsExpected = %d, want 2", cloudPosture.AccountsExpected)
	}

	if cloudPosture.Accounts[0].AccountID != "111111111111" {
		t.Errorf("Accounts[0].AccountID = %q, want %q", cloudPosture.Accounts[0].AccountID, "111111111111")
	}
	if got := cloudPosture.Accounts[0].IAM.MFACoveragePct; got == nil || *got != 100 {
		t.Errorf("Accounts[0].IAM.MFACoveragePct = %v, want 100", got)
	}

	if cloudPosture.Accounts[1].AccountID != "222222222222" {
		t.Errorf("Accounts[1].AccountID = %q, want %q", cloudPosture.Accounts[1].AccountID, "222222222222")
	}
	if got := cloudPosture.Accounts[1].IAM.MFACoveragePct; got == nil || *got != 50 {
		t.Errorf("Accounts[1].IAM.MFACoveragePct = %v, want 50", got)
	}
}

func TestToCloudPosture_UncollectedIAMOmitted(t *testing.T) {
	// A credential-report failure (e.g. generation timeout) must not surface as
	// worst-case metrics in the normalized artifact: the IAM fields are omitted
	// entirely rather than emitted as 0% / false.
	output := &Output{
		SchemaVersion: "1.0.0",
		Accounts: []AccountPosture{
			{
				AccountID: "123456789012",
				IAM: IAMMetrics{
					CredentialReportErrorCode: "CredentialReportTimeout",
				},
			},
		},
	}

	cloudPosture := output.ToCloudPosture()

	iam := cloudPosture.Accounts[0].IAM
	if iam.MFACoveragePct != nil {
		t.Errorf("MFACoveragePct = %v, want nil", *iam.MFACoveragePct)
	}
	if iam.AccessKeyRotationCompliantPct != nil {
		t.Errorf("AccessKeyRotationCompliantPct = %v, want nil", *iam.AccessKeyRotationCompliantPct)
	}
	if iam.RootMFAEnabled != nil {
		t.Errorf("RootMFAEnabled = %v, want nil", *iam.RootMFAEnabled)
	}
	if iam.RootAccessProtected != nil {
		t.Errorf("RootAccessProtected = %v, want nil", *iam.RootAccessProtected)
	}

	jsonBytes, err := json.Marshal(cloudPosture)
	if err != nil {
		t.Fatalf("failed to marshal CloudPosture: %v", err)
	}
	var data map[string]any
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	iamJSON := data["accounts"].([]any)[0].(map[string]any)["iam"].(map[string]any)
	for _, field := range []string{"mfa_coverage_pct", "root_mfa_enabled", "root_access_protected", "access_key_rotation_compliant_pct"} {
		if _, present := iamJSON[field]; present {
			t.Errorf("uncollected iam field %s serialized; want omitted", field)
		}
	}
}

func TestToCloudPosture_RootStateFromSummarySurvivesReportFailure(t *testing.T) {
	// Root state can be evaluated from the account summary even when the
	// credential report failed; only the report-derived aggregates are omitted.
	output := &Output{
		SchemaVersion: "1.0.0",
		Accounts: []AccountPosture{
			{
				AccountID: "123456789012",
				IAM: IAMMetrics{
					CredentialReportErrorCode:    "CredentialReportTimeout",
					RootCredentialStateEvaluated: true,
					RootMFAEnabled:               true,
					RootAccessProtected:          true,
				},
			},
		},
	}

	iam := output.ToCloudPosture().Accounts[0].IAM
	if iam.MFACoveragePct != nil {
		t.Errorf("MFACoveragePct = %v, want nil", *iam.MFACoveragePct)
	}
	if iam.RootMFAEnabled == nil || !*iam.RootMFAEnabled {
		t.Error("RootMFAEnabled != true, want true")
	}
	if iam.RootAccessProtected == nil || !*iam.RootAccessProtected {
		t.Error("RootAccessProtected != true, want true")
	}
}

func TestToCloudPosture_UncollectedStorageOmitted(t *testing.T) {
	// A bucket-listing failure must omit both storage percentages instead of
	// publishing fabricated zeros (public_access_blocked_pct: 0 reads as a
	// critical finding).
	output := &Output{
		Accounts: []AccountPosture{{
			AccountID: "123456789012",
			S3:        S3Metrics{BucketListingErrorCode: "Throttling"},
		}},
	}

	storage := output.ToCloudPosture().Accounts[0].Storage
	if storage.EncryptionPct != nil {
		t.Errorf("EncryptionPct = %v, want nil", *storage.EncryptionPct)
	}
	if storage.PublicAccessBlockedPct != nil {
		t.Errorf("PublicAccessBlockedPct = %v, want nil", *storage.PublicAccessBlockedPct)
	}
}

func TestToCloudPosture_StoragePABOmittedWhenAnyBucketUnknown(t *testing.T) {
	// Unknown per-bucket public-access states drag the percentage toward
	// failure, so the normalized metric is omitted while encryption (with its
	// evaluated-only denominator) stays present.
	output := &Output{
		Accounts: []AccountPosture{{
			AccountID: "123456789012",
			S3: S3Metrics{
				BucketListingEvaluated:          true,
				BucketCount:                     10,
				PublicAccessBlocked:             90,
				PublicAccessBlockUnknownCount:   1,
				DefaultEncryptionEnabled:        100,
				DefaultEncryptionEvaluatedCount: 10,
			},
		}},
	}

	storage := output.ToCloudPosture().Accounts[0].Storage
	if storage.PublicAccessBlockedPct != nil {
		t.Errorf("PublicAccessBlockedPct = %v, want nil with unknown buckets", *storage.PublicAccessBlockedPct)
	}
	if storage.EncryptionPct == nil || *storage.EncryptionPct != 100 {
		t.Errorf("EncryptionPct = %v, want 100", storage.EncryptionPct)
	}
}

func TestToCloudPosture_StorageEncryptionOmittedWhenNoBucketEvaluated(t *testing.T) {
	// Buckets exist but none had a readable encryption config: the percentage
	// has an empty denominator and must be omitted, not published as 0.
	output := &Output{
		Accounts: []AccountPosture{{
			AccountID: "123456789012",
			S3: S3Metrics{
				BucketListingEvaluated:        true,
				BucketCount:                   5,
				DefaultEncryptionUnknownCount: 5,
			},
		}},
	}

	storage := output.ToCloudPosture().Accounts[0].Storage
	if storage.EncryptionPct != nil {
		t.Errorf("EncryptionPct = %v, want nil with no evaluated buckets", *storage.EncryptionPct)
	}
}

func TestToCloudPosture_UncollectedLoggingOmitted(t *testing.T) {
	// A trail-listing failure must omit cloudtrail_enabled rather than
	// publishing false (which scores as a critical finding).
	output := &Output{
		Accounts: []AccountPosture{{
			AccountID: "123456789012",
			AccountSecurity: AccountSecurity{
				CloudTrail: CloudTrailStatus{TrailListingErrorCode: "AccessDenied"},
			},
		}},
	}

	logging := output.ToCloudPosture().Accounts[0].Logging
	if logging.CloudTrailEnabled != nil {
		t.Errorf("CloudTrailEnabled = %v, want nil", *logging.CloudTrailEnabled)
	}
	if logging.CloudTrailMultiregion != nil {
		t.Errorf("CloudTrailMultiregion = %v, want nil", *logging.CloudTrailMultiregion)
	}
}

func TestToCloudPosture_LoggingFalseOmittedWhenTrailStatusUnknown(t *testing.T) {
	// "No trail is logging" and "a trail's status was unreadable" must not
	// look the same: a false summary is only published when every trail
	// status was readable.
	output := &Output{
		Accounts: []AccountPosture{{
			AccountID: "123456789012",
			AccountSecurity: AccountSecurity{
				CloudTrail: CloudTrailStatus{
					TrailListingEvaluated:   true,
					Enabled:                 false,
					MultiRegionEnabled:      false,
					TrailStatusUnknownCount: 1,
				},
			},
		}},
	}

	logging := output.ToCloudPosture().Accounts[0].Logging
	if logging.CloudTrailEnabled != nil {
		t.Errorf("CloudTrailEnabled = %v, want nil with unknown trail statuses", *logging.CloudTrailEnabled)
	}
	if logging.CloudTrailMultiregion != nil {
		t.Errorf("CloudTrailMultiregion = %v, want nil with unknown trail statuses", *logging.CloudTrailMultiregion)
	}
}

func TestToCloudPosture_LoggingTrueSurvivesUnknownStatuses(t *testing.T) {
	// A true summary is definite evidence (a logging trail was observed) even
	// when some other trail's status was unreadable.
	output := &Output{
		Accounts: []AccountPosture{{
			AccountID: "123456789012",
			AccountSecurity: AccountSecurity{
				CloudTrail: CloudTrailStatus{
					TrailListingEvaluated:   true,
					Enabled:                 true,
					MultiRegionEnabled:      false,
					TrailStatusUnknownCount: 1,
				},
			},
		}},
	}

	logging := output.ToCloudPosture().Accounts[0].Logging
	if logging.CloudTrailEnabled == nil || !*logging.CloudTrailEnabled {
		t.Error("CloudTrailEnabled != true, want true")
	}
	if logging.CloudTrailMultiregion != nil {
		t.Errorf("CloudTrailMultiregion = %v, want nil (false with unknown statuses)", *logging.CloudTrailMultiregion)
	}
}

func TestToCloudPosture_NetworkOmittedOnPartialRegions(t *testing.T) {
	// A failed region could contain the exposed security group; the exposure
	// percentages are omitted rather than silently understated.
	output := &Output{
		Accounts: []AccountPosture{{
			AccountID: "123456789012",
			Network: NetworkMetrics{
				RegionsEvaluatedCount: 1,
				RegionsFailed:         []string{"eu-west-1"},
				OpenToWorldSSH:        0,
				OpenToWorldRDP:        0,
			},
		}},
	}

	network := output.ToCloudPosture().Accounts[0].Network
	if network.SSHOpenToWorldPct != nil {
		t.Errorf("SSHOpenToWorldPct = %v, want nil on partial regions", *network.SSHOpenToWorldPct)
	}
	if network.RDPOpenToWorldPct != nil {
		t.Errorf("RDPOpenToWorldPct = %v, want nil on partial regions", *network.RDPOpenToWorldPct)
	}
}

func TestToCloudPosture_NetworkOmittedWhenNoRegionEvaluated(t *testing.T) {
	output := &Output{
		Accounts: []AccountPosture{{AccountID: "123456789012"}},
	}

	network := output.ToCloudPosture().Accounts[0].Network
	if network.SSHOpenToWorldPct != nil || network.RDPOpenToWorldPct != nil {
		t.Error("expected network percentages omitted with zero evaluated regions")
	}
}

func TestToCloudPosture_BackupOmittedWithZeroDatabases(t *testing.T) {
	// A retention minimum over zero databases would read as "no backups".
	output := &Output{
		Accounts: []AccountPosture{{
			AccountID: "123456789012",
			RDS: RDSMetrics{
				RegionsEvaluatedCount: 2,
				DatabaseCount:         0,
			},
		}},
	}

	backup := output.ToCloudPosture().Accounts[0].Backup
	if backup.RetentionDaysMin != nil {
		t.Errorf("RetentionDaysMin = %v, want nil with zero databases", *backup.RetentionDaysMin)
	}
}

func TestToCloudPosture_UncollectedVulnScanningOmitted(t *testing.T) {
	output := &Output{
		Accounts: []AccountPosture{{
			AccountID: "123456789012",
			AccountSecurity: AccountSecurity{
				Inspector: InspectorStatus{StatusErrorCode: "AccessDenied"},
			},
		}},
	}

	vuln := output.ToCloudPosture().Accounts[0].VulnScanning
	if vuln.Enabled != nil {
		t.Errorf("Enabled = %v, want nil", *vuln.Enabled)
	}
	if vuln.UnpatchedPct != nil {
		t.Errorf("UnpatchedPct = %v, want nil", *vuln.UnpatchedPct)
	}
}

func TestToCloudPosture_EmptyAccounts(t *testing.T) {
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
	// Zero retention on a real database (backups disabled) is genuine evidence
	// and passes through, distinct from the omitted zero-database case.
	output := &Output{
		SchemaVersion: "1.0.0",
		Accounts: []AccountPosture{
			{
				AccountID: "123456789012",
				RDS: RDSMetrics{
					RegionsEvaluatedCount: 1,
					DatabaseCount:         1,
					BackupRetentionMin:    0,
				},
			},
		},
	}

	cloudPosture := output.ToCloudPosture()

	got := cloudPosture.Accounts[0].Backup.RetentionDaysMin
	if got == nil || *got != 0 {
		t.Errorf("Backup.RetentionDaysMin = %v, want 0", got)
	}
}

func TestCloudPostureJSONStructure(t *testing.T) {
	// A fully-evaluated account serializes every cloud-posture@v1 field.
	output := &Output{
		SchemaVersion: "1.0.0",
		Accounts:      []AccountPosture{evaluatedAccountFixture()},
	}

	cloudPosture := output.ToCloudPosture()

	jsonBytes, err := json.Marshal(cloudPosture)
	if err != nil {
		t.Fatalf("failed to marshal CloudPosture: %v", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	topLevelRequired := []string{
		"schema_version", "collected_at", "provider", "accounts", "accounts_expected",
	}
	for _, field := range topLevelRequired {
		if _, ok := data[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}

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

	acctRequired := []string{
		"account_id", "iam", "storage", "logging", "network", "backup", "vuln_scanning",
	}
	for _, field := range acctRequired {
		if _, ok := acct[field]; !ok {
			t.Errorf("account missing required field: %s", field)
		}
	}

	groupFields := map[string][]string{
		"iam":           {"mfa_coverage_pct", "root_mfa_enabled", "root_access_protected", "access_key_rotation_compliant_pct"},
		"storage":       {"encryption_pct", "public_access_blocked_pct"},
		"logging":       {"cloudtrail_enabled", "cloudtrail_multiregion"},
		"network":       {"ssh_open_to_world_pct", "rdp_open_to_world_pct"},
		"backup":        {"retention_days_min"},
		"vuln_scanning": {"enabled", "unpatched_pct"},
	}
	for group, fields := range groupFields {
		obj, ok := acct[group].(map[string]interface{})
		if !ok {
			t.Fatalf("%s is not an object", group)
		}
		for _, field := range fields {
			if _, ok := obj[field]; !ok {
				t.Errorf("%s missing field: %s (evaluated account should emit all metrics)", group, field)
			}
		}
	}
}

func TestToCloudPosture_FailedAccountStub(t *testing.T) {
	// A configured account that never answered appears as a stub entry with
	// collection_error_code and empty metric groups, and counts toward
	// accounts_expected, so cardinality-all rules cannot silently pass over it.
	output := &Output{
		SchemaVersion: "1.0.0",
		Accounts:      []AccountPosture{evaluatedAccountFixture()},
		FailedAccounts: []FailedAccountRecord{
			{AccountID: "222222222222", RoleARN: "arn:aws:iam::222222222222:role/collector", ErrorCode: "AccessDenied"},
		},
	}

	cloudPosture := output.ToCloudPosture()

	if cloudPosture.AccountsExpected != 2 {
		t.Errorf("AccountsExpected = %d, want 2", cloudPosture.AccountsExpected)
	}
	if len(cloudPosture.Accounts) != 2 {
		t.Fatalf("len(Accounts) = %d, want 2 (one healthy, one stub)", len(cloudPosture.Accounts))
	}

	stub := cloudPosture.Accounts[1]
	if stub.AccountID != "222222222222" {
		t.Errorf("stub AccountID = %q, want 222222222222", stub.AccountID)
	}
	if stub.CollectionErrorCode != "AccessDenied" {
		t.Errorf("stub CollectionErrorCode = %q, want AccessDenied", stub.CollectionErrorCode)
	}
	if stub.IAM.MFACoveragePct != nil || stub.Storage.EncryptionPct != nil || stub.Logging.CloudTrailEnabled != nil {
		t.Error("stub entry must carry no metric values")
	}

	jsonBytes, err := json.Marshal(cloudPosture)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var data map[string]any
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	stubJSON := data["accounts"].([]any)[1].(map[string]any)
	iamJSON := stubJSON["iam"].(map[string]any)
	if len(iamJSON) != 0 {
		t.Errorf("stub iam group not empty: %v", iamJSON)
	}
	if _, ok := stubJSON["collection_error_code"]; !ok {
		t.Error("stub missing collection_error_code in JSON")
	}
}

func TestAccountIDFromRoleARN(t *testing.T) {
	cases := []struct {
		arn  string
		want string
	}{
		{"arn:aws:iam::123456789012:role/collector", "123456789012"},
		{"arn:aws-us-gov:iam::123456789012:role/x", "123456789012"},
		{"", ""},
		{"not-an-arn", ""},
		{"arn:aws:iam::12345:role/short", ""},
		{"arn:aws:iam::12345678901b:role/nondigit", ""},
	}
	for _, tc := range cases {
		if got := accountIDFromRoleARN(tc.arn); got != tc.want {
			t.Errorf("accountIDFromRoleARN(%q) = %q, want %q", tc.arn, got, tc.want)
		}
	}
}
