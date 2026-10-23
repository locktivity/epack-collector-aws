package collector

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

// evaluatedAccountFixture returns an AccountPosture with every family's
// evaluated sentinels set, so all normalized metrics should be present.
func evaluatedAccountFixture() AccountPosture {
	return AccountPosture{
		AccountID: "123456789012",
		Regions:   []string{"us-east-1", "us-west-2"},
		IAM: IAMMetrics{
			CredentialReportEvaluated:       true,
			RootCredentialStateEvaluated:    true,
			IAMUserCount:                    10,
			AccessKeyUserCount:              10,
			MFAEnabled:                      intPtr(80),
			RootMFAEnabled:                  true,
			RootAccessProtected:             true,
			AccessKeysRotated:               intPtr(90),
			HardwareMFAEnabled:              intPtr(30),
			SAMLProviderCount:               intPtr(0),
			IdentityCenterSAMLProviderCount: intPtr(0),
			IdentityCenterRoleCount:         intPtr(0),
		},
		IdentityCenter: IdentityCenterStatus{RegionsChecked: []string{"us-east-1", "us-west-2"}},
		S3: S3Metrics{
			BucketListingEvaluated:          true,
			BucketCount:                     20,
			DefaultEncryptionEnabled:        intPtr(95),
			DefaultEncryptionEvaluatedCount: 20,
			PublicAccessBlocked:             intPtr(100),
			VersioningEnabled:               intPtr(75),
		},
		RDS: RDSMetrics{
			RegionsEvaluatedCount:   2,
			DatabaseCount:           3,
			EncryptedAtRest:         intPtr(100),
			BackupRetentionAdequate: intPtr(100),
			BackupRetentionMin:      intPtr(14),
		},
		Network: NetworkMetrics{
			RegionsEvaluatedCount: 2,
			OpenToWorldSSH:        intPtr(5),
			OpenToWorldRDP:        intPtr(0),
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
				UnpatchedServerPercent: intPtr(10),
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

	if acct.Logging.AuditLogEnabled == nil || !*acct.Logging.AuditLogEnabled {
		t.Error("Logging.AuditLogEnabled != true, want true")
	}
	if acct.Logging.AuditLogAllRegions == nil || !*acct.Logging.AuditLogAllRegions {
		t.Error("Logging.AuditLogAllRegions != true, want true")
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
				IAM:       IAMMetrics{CredentialReportEvaluated: true, RootCredentialStateEvaluated: true, MFAEnabled: intPtr(100), RootMFAEnabled: true, RootAccessProtected: true},
			},
			{
				AccountID: "222222222222",
				IAM:       IAMMetrics{CredentialReportEvaluated: true, RootCredentialStateEvaluated: true, MFAEnabled: intPtr(50), RootMFAEnabled: false, RootAccessProtected: false},
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
	// A metric group with nothing collected in it is left out whole.
	if iamJSON, present := data["accounts"].([]any)[0].(map[string]any)["iam"]; present {
		t.Errorf("iam group serialized with nothing collected: %v", iamJSON)
	}
	var iamJSON map[string]any
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
				PublicAccessBlocked:             intPtr(90),
				PublicAccessBlockUnknownCount:   1,
				DefaultEncryptionEnabled:        intPtr(100),
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
	// A trail-listing failure must omit the audit log fields rather than
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
	if logging.AuditLogEnabled != nil {
		t.Errorf("AuditLogEnabled = %v, want nil", *logging.AuditLogEnabled)
	}
	if logging.AuditLogAllRegions != nil {
		t.Errorf("AuditLogAllRegions = %v, want nil", *logging.AuditLogAllRegions)
	}
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
	if logging.AuditLogEnabled != nil {
		t.Errorf("AuditLogEnabled = %v, want nil with unknown trail statuses", *logging.AuditLogEnabled)
	}
	if logging.AuditLogAllRegions != nil {
		t.Errorf("AuditLogAllRegions = %v, want nil with unknown trail statuses", *logging.AuditLogAllRegions)
	}
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
	if logging.AuditLogEnabled == nil || !*logging.AuditLogEnabled {
		t.Error("AuditLogEnabled != true, want true")
	}
	if logging.AuditLogAllRegions != nil {
		t.Errorf("AuditLogAllRegions = %v, want nil (false with unknown statuses)", *logging.AuditLogAllRegions)
	}
	if logging.CloudTrailEnabled == nil || !*logging.CloudTrailEnabled {
		t.Error("CloudTrailEnabled != true, want true")
	}
	if logging.CloudTrailMultiregion != nil {
		t.Errorf("CloudTrailMultiregion = %v, want nil (false with unknown statuses)", *logging.CloudTrailMultiregion)
	}
}

func TestNormalizedLogging_DeprecatedNamesMatchAuditLogFields(t *testing.T) {
	// cloud-posture v1 keeps cloudtrail_enabled and cloudtrail_multiregion as
	// aliases of the audit_log_* fields, so profiles that read either name
	// score the same.
	cases := []CloudTrailStatus{
		{},
		{TrailListingEvaluated: true},
		{TrailListingEvaluated: true, Enabled: true},
		{TrailListingEvaluated: true, Enabled: true, MultiRegionEnabled: true},
		{TrailListingEvaluated: true, Enabled: true, TrailStatusUnknownCount: 1},
		{TrailListingEvaluated: true, TrailStatusUnknownCount: 1},
	}
	for _, ct := range cases {
		logging := normalizedLogging(ct)
		if !samePtr(logging.CloudTrailEnabled, logging.AuditLogEnabled) {
			t.Errorf("%+v: cloudtrail_enabled = %v, audit_log_enabled = %v, want the same", ct, logging.CloudTrailEnabled, logging.AuditLogEnabled)
		}
		if !samePtr(logging.CloudTrailMultiregion, logging.AuditLogAllRegions) {
			t.Errorf("%+v: cloudtrail_multiregion = %v, audit_log_all_regions = %v, want the same", ct, logging.CloudTrailMultiregion, logging.AuditLogAllRegions)
		}
	}
}

func samePtr(a, b *bool) bool {
	return (a == nil) == (b == nil) && (a == nil || *a == *b)
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
				OpenToWorldSSH:        intPtr(0),
				OpenToWorldRDP:        intPtr(0),
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
					BackupRetentionMin:    intPtr(0),
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
		"schema_version", "collected_at", "provider", "accounts", "accounts_expected", "workforce_sign_in",
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
		"iam":           {"mfa_coverage_pct", "root_mfa_enabled", "root_access_protected", "access_key_rotation_compliant_pct", "user_count", "access_key_user_count", "saml_provider_count"},
		"storage":       {"encryption_pct", "public_access_blocked_pct"},
		"logging":       {"audit_log_enabled", "audit_log_all_regions", "cloudtrail_enabled", "cloudtrail_multiregion"},
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
	// collection_error_code and no metric groups, and counts toward
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
	if stub.IAM.MFACoveragePct != nil || stub.Storage.EncryptionPct != nil || stub.Logging.AuditLogEnabled != nil || stub.Logging.CloudTrailEnabled != nil {
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
	for _, group := range []string{"iam", "storage", "logging", "network", "backup", "vuln_scanning"} {
		if value, present := stubJSON[group]; present {
			t.Errorf("stub carries the %s group: %v", group, value)
		}
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

func TestToCloudPosture_AccountLabelPropagates(t *testing.T) {
	// The operator-supplied label rides both artifacts, including a failed
	// account's stub entry, so downstream consumers can tell which
	// environment an entry (or an outage) belongs to.
	healthy := evaluatedAccountFixture()
	healthy.AccountLabel = "production"
	output := &Output{
		SchemaVersion: "1.0.0",
		Accounts:      []AccountPosture{healthy},
		FailedAccounts: []FailedAccountRecord{
			{AccountID: "222222222222", Label: "staging", ErrorCode: "AccessDenied"},
		},
	}

	cloudPosture := output.ToCloudPosture()

	if cloudPosture.Accounts[0].AccountLabel != "production" {
		t.Errorf("Accounts[0].AccountLabel = %q, want production", cloudPosture.Accounts[0].AccountLabel)
	}
	if cloudPosture.Accounts[1].AccountLabel != "staging" {
		t.Errorf("stub AccountLabel = %q, want staging", cloudPosture.Accounts[1].AccountLabel)
	}

	jsonBytes, err := json.Marshal(cloudPosture)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var data map[string]any
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	first := data["accounts"].([]any)[0].(map[string]any)
	if first["account_label"] != "production" {
		t.Errorf("account_label = %v, want production", first["account_label"])
	}
}

func TestToCloudPosture_NoLabelOmitted(t *testing.T) {
	output := &Output{
		SchemaVersion: "1.0.0",
		Accounts:      []AccountPosture{evaluatedAccountFixture()},
	}

	jsonBytes, err := json.Marshal(output.ToCloudPosture())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var data map[string]any
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	first := data["accounts"].([]any)[0].(map[string]any)
	if _, present := first["account_label"]; present {
		t.Error("account_label serialized without a configured label; want omitted")
	}
}

func TestNormalizedIAM_RootWithoutCredentialsCountsAsMFAProtected(t *testing.T) {
	removed := normalizedIAM(IAMMetrics{RootCredentialStateEvaluated: true, RootMFAEnabled: false, RootCredentialsPresent: false, RootAccessProtected: true})
	if removed.RootMFAEnabled == nil || !*removed.RootMFAEnabled {
		t.Errorf("root without credentials: root_mfa_enabled = %v, want true", removed.RootMFAEnabled)
	}

	unprotected := normalizedIAM(IAMMetrics{RootCredentialStateEvaluated: true, RootMFAEnabled: false, RootCredentialsPresent: true, RootAccessProtected: false})
	if unprotected.RootMFAEnabled == nil || *unprotected.RootMFAEnabled {
		t.Errorf("root password without MFA: root_mfa_enabled = %v, want false", unprotected.RootMFAEnabled)
	}
}

// The counts behind the IAM percentages are 0 over an empty population,
// where the percentage is left out, and left out where the credential
// report was not read.
func TestToCloudPosture_IAMCounts(t *testing.T) {
	account := evaluatedAccountFixture()
	account.IAM.IAMUserCount, account.IAM.AccessKeyUserCount, account.IAM.SAMLProviderCount = 5, 2, intPtr(1)
	noUsers := evaluatedAccountFixture()
	noUsers.IAM.IAMUserCount, noUsers.IAM.AccessKeyUserCount = 0, 0
	noUsers.IAM.MFAEnabled, noUsers.IAM.AccessKeysRotated = nil, nil
	unread := evaluatedAccountFixture()
	unread.IAM.CredentialReportEvaluated = false
	unread.IAM.SAMLProviderCount = nil

	posture := (&Output{Accounts: []AccountPosture{account, noUsers, unread}}).ToCloudPosture()

	got := posture.Accounts[0].IAM
	if !pctIs(got.UserCount, 5) || !pctIs(got.AccessKeyUserCount, 2) || !pctIs(got.SAMLProviderCount, 1) {
		t.Errorf("counts %s, %s, %s; want 5, 2, 1", showPct(got.UserCount), showPct(got.AccessKeyUserCount), showPct(got.SAMLProviderCount))
	}
	got = posture.Accounts[1].IAM
	if !pctIs(got.UserCount, 0) || !pctIs(got.AccessKeyUserCount, 0) || got.MFACoveragePct != nil || got.AccessKeyRotationCompliantPct != nil {
		t.Errorf("no IAM users: counts %s and %s, percentages %v and %v; want 0, 0, and both left out",
			showPct(got.UserCount), showPct(got.AccessKeyUserCount), got.MFACoveragePct, got.AccessKeyRotationCompliantPct)
	}
	got = posture.Accounts[2].IAM
	if got.UserCount != nil || got.AccessKeyUserCount != nil || got.SAMLProviderCount != nil {
		t.Errorf("unread: counts %s, %s, %s; want all left out", showPct(got.UserCount), showPct(got.AccessKeyUserCount), showPct(got.SAMLProviderCount))
	}
}

// A failed account's stub leaves the counts out with the account's failure.
func TestCloudPosture_FailedAccountStubLeavesCountsOut(t *testing.T) {
	c := newTestCollector(Config{})
	failure := componentsdk.CodeError(componentsdk.CodePermissionDenied, errors.New("AccessDenied: not authorized to perform: sts:AssumeRoleWithWebIdentity"))
	output := &Output{
		Accounts:       []AccountPosture{evaluatedAccountFixture()},
		FailedAccounts: []FailedAccountRecord{{AccountID: "222222222222", ErrorCode: "AccessDenied", err: failure}},
	}

	posture := c.cloudPosture(output)

	if posture.Accounts[1].IAM.UserCount != nil {
		t.Error("the stub carries a user count")
	}
	for _, pointer := range []string{"/accounts/1/iam/user_count", "/accounts/1/iam/access_key_user_count", "/accounts/1/iam/saml_provider_count", "/workforce_sign_in/in_use"} {
		if g := normalizedGap(c, pointer); g == nil || g.Code != componentsdk.CodePermissionDenied {
			t.Errorf("%s: gap %+v, want the account's permission_denied", pointer, g)
		}
	}
}

// signInAccount returns an account scanned in us-east-1 with idc as its
// Identity Center evidence and the Identity Center roles and SAML providers
// counted as given.
func signInAccount(idc IdentityCenterStatus, roles, providers *int) AccountPosture {
	return AccountPosture{
		AccountID:      "111111111111",
		Regions:        []string{"us-east-1"},
		IAM:            IAMMetrics{SAMLProviderCount: intPtr(0), IdentityCenterRoleCount: roles, IdentityCenterSAMLProviderCount: providers},
		IdentityCenter: idc,
	}
}

// noInstance is an account's evidence where the listing answered in its
// only region and found no instance.
func noInstance() IdentityCenterStatus {
	return IdentityCenterStatus{RegionsChecked: []string{"us-east-1"}}
}

// orgInstance is an account's evidence of an active organization instance
// whose directory, store, has users of whom withExternalID have an external
// ID.
func orgInstance(store string, users, withExternalID int) IdentityCenterStatus {
	return IdentityCenterStatus{
		Enabled: true, InstanceStatus: "ACTIVE", InstanceType: "organization", IdentityStoreID: store,
		UserCount: users, ExternalIDUserCount: withExternalID, MFAEvidence: identityCenterMFAEvidence(users, withExternalID),
		RegionsChecked: []string{"us-east-1"},
	}
}

func TestNormalizedWorkforceSignIn(t *testing.T) {
	accountInstance := orgInstance("d-1", 2, 0)
	accountInstance.InstanceType = "account"
	creating := orgInstance("d-1", 2, 0)
	creating.InstanceStatus = "CREATE_IN_PROGRESS"
	typeUnread := orgInstance("d-1", 2, 0)
	typeUnread.InstanceType = ""
	directoryUnread := orgInstance("d-1", 0, 0)
	directoryUnread.MFAEvidence = ""
	listingIncomplete := signInAccount(noInstance(), intPtr(0), intPtr(0))
	listingIncomplete.Regions = []string{"us-east-1", "us-west-2"}

	cases := []struct {
		name      string
		accounts  []AccountPosture
		failed    int
		inUse     *bool
		users     *int
		mfaSource string
	}{
		{"an organization instance in one account, its roles in another",
			[]AccountPosture{signInAccount(orgInstance("d-1", 3, 0), intPtr(0), intPtr(0)), signInAccount(noInstance(), intPtr(2), intPtr(1))},
			0, boolPtr(true), intPtr(3), "sign_in_service"},
		{"no Identity Center in any account",
			[]AccountPosture{signInAccount(noInstance(), intPtr(0), intPtr(0)), signInAccount(noInstance(), intPtr(0), intPtr(0))},
			0, boolPtr(false), nil, ""},
		{"roles in a member account that cannot see the instance",
			[]AccountPosture{signInAccount(noInstance(), intPtr(1), intPtr(0))},
			0, boolPtr(true), nil, "unknown"},
		{"Identity Center's SAML provider alone",
			[]AccountPosture{signInAccount(noInstance(), intPtr(0), intPtr(1))},
			0, boolPtr(true), nil, "unknown"},
		{"SAML providers unread, the instance and role listings found neither",
			[]AccountPosture{signInAccount(noInstance(), intPtr(0), nil)},
			0, boolPtr(false), nil, ""},
		{"an account instance",
			[]AccountPosture{signInAccount(accountInstance, intPtr(0), intPtr(0))},
			0, boolPtr(false), nil, ""},
		{"an instance still being created",
			[]AccountPosture{signInAccount(creating, intPtr(0), intPtr(0))},
			0, boolPtr(false), nil, ""},
		{"two accounts see the same directory",
			[]AccountPosture{signInAccount(orgInstance("d-1", 2, 2), intPtr(0), intPtr(0)), signInAccount(orgInstance("d-1", 2, 2), intPtr(1), intPtr(1))},
			0, boolPtr(true), intPtr(2), "external_idp"},
		{"two directories",
			[]AccountPosture{signInAccount(orgInstance("d-1", 2, 2), intPtr(0), intPtr(0)), signInAccount(orgInstance("d-2", 1, 0), intPtr(0), intPtr(0))},
			0, boolPtr(true), intPtr(3), "unknown"},
		{"a directory with no users",
			[]AccountPosture{signInAccount(orgInstance("d-1", 0, 0), intPtr(0), intPtr(0))},
			0, boolPtr(true), intPtr(0), "unknown"},
		{"an instance listing that failed in a region",
			[]AccountPosture{listingIncomplete},
			0, nil, nil, ""},
		{"roles unread",
			[]AccountPosture{signInAccount(noInstance(), nil, intPtr(0))},
			0, nil, nil, ""},
		{"an instance whose type is unread",
			[]AccountPosture{signInAccount(typeUnread, intPtr(0), intPtr(0))},
			0, nil, nil, ""},
		{"roles show it in use where another account's listing failed",
			[]AccountPosture{signInAccount(noInstance(), intPtr(1), intPtr(1)), listingIncomplete},
			0, boolPtr(true), nil, ""},
		{"the directory unread",
			[]AccountPosture{signInAccount(directoryUnread, intPtr(0), intPtr(0))},
			0, boolPtr(true), nil, ""},
		{"an account that failed, nothing elsewhere",
			[]AccountPosture{signInAccount(noInstance(), intPtr(0), intPtr(0))},
			1, nil, nil, ""},
		{"an account that failed, roles elsewhere",
			[]AccountPosture{signInAccount(noInstance(), intPtr(1), intPtr(0))},
			1, boolPtr(true), nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output := &Output{Accounts: tc.accounts}
			for i := 0; i < tc.failed; i++ {
				output.FailedAccounts = append(output.FailedAccounts, FailedAccountRecord{ErrorCode: "AccessDenied"})
			}
			got := output.ToCloudPosture().WorkforceSignIn
			if !samePtr(got.InUse, tc.inUse) || !sameInt(got.UserCount, tc.users) || got.MFASource != tc.mfaSource {
				t.Errorf("in_use %v, user_count %s, mfa_source %q; want %v, %s, %q",
					showBool(got.InUse), showPct(got.UserCount), got.MFASource, showBool(tc.inUse), showPct(tc.users), tc.mfaSource)
			}
		})
	}
}

// A folded value left out carries the gap of the read that left it unknown.
func TestNormalizedWorkforceSignIn_LeftOutValuesCarryTheirGap(t *testing.T) {
	c := newTestCollector(Config{})
	listing := componentsdk.CodeError(componentsdk.CodeRateLimited, errors.New("Throttling: Rate exceeded"))
	c.gaps.leaveOut(listing, "/accounts/0/identity_center")
	account := signInAccount(IdentityCenterStatus{}, intPtr(0), intPtr(0))

	posture := c.cloudPosture(&Output{Accounts: []AccountPosture{account}})

	if posture.WorkforceSignIn.InUse != nil {
		t.Errorf("in_use = %v, want it left out", *posture.WorkforceSignIn.InUse)
	}
	for _, pointer := range []string{"/workforce_sign_in/in_use", "/workforce_sign_in/user_count", "/workforce_sign_in/mfa_source"} {
		if g := normalizedGap(c, pointer); g == nil || g.Code != componentsdk.CodeRateLimited {
			t.Errorf("%s: gap %+v, want the instance listing's rate_limited", pointer, g)
		}
	}

	c = newTestCollector(Config{})
	users := componentsdk.CodeError(componentsdk.CodePermissionDenied, errors.New("AccessDeniedException: not authorized to perform: identitystore:ListUsers"))
	c.gaps.leaveOut(users, "/accounts/0/identity_center/user_count")
	unread := orgInstance("d-1", 0, 0)
	unread.MFAEvidence = ""
	posture = c.cloudPosture(&Output{Accounts: []AccountPosture{signInAccount(unread, intPtr(0), intPtr(0))}})
	if !samePtr(posture.WorkforceSignIn.InUse, boolPtr(true)) {
		t.Errorf("in_use = %s, want true from the instance", showBool(posture.WorkforceSignIn.InUse))
	}
	if g := normalizedGap(c, "/workforce_sign_in/in_use"); g != nil {
		t.Errorf("in_use has a gap: %+v", g)
	}
	for _, pointer := range []string{"/workforce_sign_in/user_count", "/workforce_sign_in/mfa_source"} {
		if g := normalizedGap(c, pointer); g == nil || g.Code != componentsdk.CodePermissionDenied {
			t.Errorf("%s: gap %+v, want the user listing's permission_denied", pointer, g)
		}
	}
}

// normalizedGap returns the gap c recorded at pointer in the normalized
// artifact, or nil.
func normalizedGap(c *Collector, pointer string) *componentsdk.Gap {
	for _, g := range c.gaps.rec.Gaps() {
		if g.Path == cloudPosturePath && g.Pointer == pointer {
			return &g
		}
	}
	return nil
}

func sameInt(a, b *int) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

func showBool(p *bool) string {
	if p == nil {
		return "left out"
	}
	if *p {
		return "true"
	}
	return "false"
}
