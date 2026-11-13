package collector

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
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
			ConsoleUserCount:                10,
			ConsoleMFAEnabled:               intPtr(80),
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
			BucketListingEvaluated:              true,
			BucketCount:                         20,
			DefaultEncryptionEnabled:            intPtr(95),
			DefaultEncryptionEnabledBucketCount: 19,
			DefaultEncryptionEvaluatedCount:     20,
			PublicAccessBlocked:                 intPtr(100),
			PublicAccessBlockedBucketCount:      20,
			VersioningEnabled:                   intPtr(75),
		},
		RDS: RDSMetrics{
			RegionsEvaluatedCount:        2,
			DatabaseCount:                3,
			EncryptedAtRest:              intPtr(100),
			EncryptedAtRestDatabaseCount: 3,
			MultiAZEnabled:               intPtr(33),
			MultiAZEnabledDatabaseCount:  1,
			BackupRetentionAdequate:      intPtr(100),
			BackupRetentionMin:           intPtr(14),
		},
		Network: NetworkMetrics{
			RegionsEvaluatedCount:            2,
			SecurityGroupCount:               20,
			OpenToWorldSSH:                   intPtr(5),
			OpenToWorldSSHSecurityGroupCount: 1,
			OpenToWorldRDP:                   intPtr(0),
		},
		AccountSecurity: AccountSecurity{
			CloudTrail: CloudTrailStatus{
				TrailListingEvaluated: true,
				Enabled:               true,
				MultiRegionEnabled:    true,
			},
			GuardDuty: GuardDutyStatus{Enabled: true, EnabledInAllRegions: true},
			Inspector: InspectorStatus{
				StatusEvaluated:        true,
				Enabled:                true,
				UnpatchedServerPercent: intPtr(10),
				TotalAffectedResources: 10,
				UnpatchedResources:     1,
			},
		},
	}
}

func TestToCloudPosture(t *testing.T) {
	output := &Output{
		SchemaVersion:    "1.0.0",
		CollectedAt:      "2024-01-15T10:00:00Z",
		CollectedAtLevel: string(componentsdk.LevelAudit),
		Accounts:         []AccountPosture{evaluatedAccountFixture()},
	}

	cloudPosture := output.ToCloudPosture()

	if cloudPosture.SchemaVersion != "1.0.0" {
		t.Errorf("SchemaVersion = %q, want %q", cloudPosture.SchemaVersion, "1.0.0")
	}
	if cloudPosture.Provider != "aws" {
		t.Errorf("Provider = %q, want %q", cloudPosture.Provider, "aws")
	}
	if !pctIs(cloudPosture.AccountsExpected, 1) {
		t.Errorf("AccountsExpected = %s, want 1", showPct(cloudPosture.AccountsExpected))
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

	if v := acct.Storage.EncryptionPct.Value; v == nil || *v != 95 {
		t.Errorf("Storage.EncryptionPct = %v, want 95", v)
	}
	if v := acct.Storage.PublicAccessBlockedPct.Value; v == nil || *v != 100 {
		t.Errorf("Storage.PublicAccessBlockedPct = %v, want 100", v)
	}
	if v := acct.Database.EncryptionPct.Value; v == nil || *v != 100 {
		t.Errorf("Database.EncryptionPct = %v, want 100", v)
	}
	if v := acct.Database.MultiAZPct.Value; v == nil || *v != 33 {
		t.Errorf("Database.MultiAZPct = %v, want 33", v)
	}
	if acct.ThreatDetection.Enabled == nil || !*acct.ThreatDetection.Enabled {
		t.Error("ThreatDetection.Enabled != true, want true")
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

	if v := acct.Network.SSHOpenToWorldPct.Value; v == nil || *v != 5 {
		t.Errorf("Network.SSHOpenToWorldPct = %v, want 5", v)
	}
	if v := acct.Network.RDPOpenToWorldPct.Value; v == nil || *v != 0 {
		t.Errorf("Network.RDPOpenToWorldPct = %v, want 0", v)
	}

	if acct.Backup.RetentionDaysMin == nil || *acct.Backup.RetentionDaysMin != 14 {
		t.Errorf("Backup.RetentionDaysMin = %v, want 14", acct.Backup.RetentionDaysMin)
	}

}

func TestToCloudPosture_MultipleAccounts(t *testing.T) {
	output := &Output{
		SchemaVersion:    "1.0.0",
		CollectedAtLevel: string(componentsdk.LevelAudit),
		Accounts: []AccountPosture{
			{
				AccountID: "111111111111",
				S3:        S3Metrics{BucketListingEvaluated: true, BucketCount: 2, DefaultEncryptionEnabledBucketCount: 2},
			},
			{
				AccountID: "222222222222",
				S3:        S3Metrics{BucketListingEvaluated: true, BucketCount: 2, DefaultEncryptionEnabledBucketCount: 1},
			},
		},
	}

	cloudPosture := output.ToCloudPosture()

	if len(cloudPosture.Accounts) != 2 {
		t.Fatalf("len(Accounts) = %d, want 2", len(cloudPosture.Accounts))
	}
	if !pctIs(cloudPosture.AccountsExpected, 2) {
		t.Errorf("AccountsExpected = %s, want 2", showPct(cloudPosture.AccountsExpected))
	}

	if cloudPosture.Accounts[0].AccountID != "111111111111" {
		t.Errorf("Accounts[0].AccountID = %q, want %q", cloudPosture.Accounts[0].AccountID, "111111111111")
	}
	if got := cloudPosture.Accounts[0].Storage.EncryptionPct.Value; got == nil || *got != 100 {
		t.Errorf("Accounts[0].Storage.EncryptionPct = %v, want 100", got)
	}

	if cloudPosture.Accounts[1].AccountID != "222222222222" {
		t.Errorf("Accounts[1].AccountID = %q, want %q", cloudPosture.Accounts[1].AccountID, "222222222222")
	}
	if got := cloudPosture.Accounts[1].Storage.EncryptionPct.Value; got == nil || *got != 50 {
		t.Errorf("Accounts[1].Storage.EncryptionPct = %v, want 50", got)
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
	if storage.EncryptionPct.Read {
		t.Errorf("EncryptionPct = %v, want it left out", storage.EncryptionPct.Value)
	}
	if storage.PublicAccessBlockedPct.Read {
		t.Errorf("PublicAccessBlockedPct = %v, want it left out", storage.PublicAccessBlockedPct.Value)
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
				BucketListingEvaluated:              true,
				BucketCount:                         10,
				PublicAccessBlocked:                 intPtr(90),
				PublicAccessBlockedBucketCount:      9,
				PublicAccessBlockUnknownCount:       1,
				DefaultEncryptionEnabled:            intPtr(100),
				DefaultEncryptionEnabledBucketCount: 10,
				DefaultEncryptionEvaluatedCount:     10,
			},
		}},
	}

	storage := output.ToCloudPosture().Accounts[0].Storage
	if storage.PublicAccessBlockedPct.Read {
		t.Errorf("PublicAccessBlockedPct = %v, want it left out with unknown buckets", storage.PublicAccessBlockedPct.Value)
	}
	if v := storage.EncryptionPct.Value; v == nil || *v != 100 {
		t.Errorf("EncryptionPct = %v, want 100", v)
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
	if storage.EncryptionPct.Read {
		t.Errorf("EncryptionPct = %v, want it left out with no evaluated buckets", storage.EncryptionPct.Value)
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
	if network.SSHOpenToWorldPct.Read {
		t.Errorf("SSHOpenToWorldPct = %v, want it left out on partial regions", network.SSHOpenToWorldPct.Value)
	}
	if network.RDPOpenToWorldPct.Read {
		t.Errorf("RDPOpenToWorldPct = %v, want it left out on partial regions", network.RDPOpenToWorldPct.Value)
	}
}

func TestToCloudPosture_NetworkOmittedWhenNoRegionEvaluated(t *testing.T) {
	output := &Output{
		Accounts: []AccountPosture{{AccountID: "123456789012"}},
	}

	network := output.ToCloudPosture().Accounts[0].Network
	if network.SSHOpenToWorldPct.Read || network.RDPOpenToWorldPct.Read {
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
		SchemaVersion:    "1.0.0",
		CollectedAtLevel: string(componentsdk.LevelAudit),
		Accounts:         []AccountPosture{evaluatedAccountFixture()},
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
		"schema_version", "collected_at", "provider", "accounts", "accounts_expected", "all_accounts_collected",
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
		"account_id", "storage", "database", "logging", "network", "backup", "threat_detection",
	}
	for _, field := range acctRequired {
		if _, ok := acct[field]; !ok {
			t.Errorf("account missing required field: %s", field)
		}
	}

	groupFields := map[string][]string{
		"storage": {"storage_resources_present", "storage_resource_count", "encrypted_storage_resource_count",
			"public_access_blocked_storage_resource_count", "encryption_pct", "public_access_blocked_pct"},
		"database": {"databases_present", "database_count", "encrypted_database_count", "encryption_pct",
			"multi_az_database_count", "multi_az_pct"},
		"logging": {"audit_log_enabled", "audit_log_all_regions", "cloudtrail_enabled", "cloudtrail_multiregion"},
		"network": {"security_groups_present", "security_group_count", "ssh_open_security_group_count",
			"rdp_open_security_group_count", "ssh_open_to_world_pct", "rdp_open_to_world_pct"},
		"backup":           {"retention_days_min"},
		"threat_detection": {"enabled"},
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
		SchemaVersion:    "1.0.0",
		CollectedAtLevel: string(componentsdk.LevelAudit),
		Accounts:         []AccountPosture{evaluatedAccountFixture()},
		FailedAccounts: []FailedAccountRecord{
			{AccountID: "222222222222", RoleARN: "arn:aws:iam::222222222222:role/collector", ErrorCode: "AccessDenied"},
		},
	}

	cloudPosture := output.ToCloudPosture()

	if !pctIs(cloudPosture.AccountsExpected, 2) {
		t.Errorf("AccountsExpected = %s, want 2", showPct(cloudPosture.AccountsExpected))
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
	if stub.Storage.EncryptionPct.Read || stub.Logging.AuditLogEnabled != nil || stub.Logging.CloudTrailEnabled != nil {
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
	for _, group := range []string{"storage", "database", "logging", "network", "backup", "threat_detection"} {
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

// At the trust level the account IDs and counts are left out, and the
// present flags say whether each population is empty.
func TestToCloudPosture_TrustLeavesOutCounts(t *testing.T) {
	account := evaluatedAccountFixture()
	output := &Output{
		CollectedAtLevel: string(componentsdk.LevelTrust),
		Accounts:         []AccountPosture{account, signInAccount(orgInstance("d-1", 2, 0), intPtr(0), intPtr(0))},
		FailedAccounts:   []FailedAccountRecord{{AccountID: "222222222222", ErrorCode: "AccessDenied"}},
	}

	posture := output.ToCloudPosture()

	if posture.AccountsExpected != nil || !samePtr(posture.AllAccountsCollected, boolPtr(false)) {
		t.Errorf("accounts_expected %s, all_accounts_collected %s; want left out and false", showPct(posture.AccountsExpected), showBool(posture.AllAccountsCollected))
	}
	for i, acct := range posture.Accounts {
		if acct.AccountID != "" {
			t.Errorf("accounts[%d].account_id = %q, want it left out", i, acct.AccountID)
		}
	}
	got := posture.Accounts[0].Storage
	if got.StorageResourceCount != nil || got.EncryptedStorageResourceCount != nil {
		t.Error("a trust-level storage count was written")
	}
	if !samePtr(got.StorageResourcesPresent, boolPtr(true)) {
		t.Errorf("storage_resources_present = %s, want true", showBool(got.StorageResourcesPresent))
	}
}

// nullReading reports whether r was read and is null.
func nullReading(r Reading[float64]) bool { return r.Read && r.Value == nil }

// A failed account's stub leaves the counts out with the account's failure.
func TestCloudPosture_FailedAccountStubLeavesCountsOut(t *testing.T) {
	c := newTestCollector(Config{})
	failure := componentsdk.CodeError(componentsdk.CodePermissionDenied, errors.New("AccessDenied: not authorized to perform: sts:AssumeRoleWithWebIdentity"))
	output := &Output{
		CollectedAtLevel: string(componentsdk.LevelAudit),
		Accounts:         []AccountPosture{evaluatedAccountFixture()},
		FailedAccounts:   []FailedAccountRecord{{AccountID: "222222222222", ErrorCode: "AccessDenied", err: failure}},
	}

	posture := c.cloudPosture(output)

	if posture.Accounts[1].Storage.StorageResourceCount != nil {
		t.Error("the stub carries a storage count")
	}
	for _, pointer := range []string{"/accounts/1/storage/storage_resource_count", "/accounts/1/network/security_group_count", "/accounts/1/storage/storage_resources_present"} {
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
		Enabled: true, InstanceStatus: "ACTIVE", InstanceType: "organization", identityStoreID: store,
		UserCount: users, ExternalIDUserCount: withExternalID, MFAEvidence: identityCenterMFAEvidence(users, withExternalID),
		RegionsChecked: []string{"us-east-1"},
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

// A percentage over an empty population is null, with its present flag false
// and its counts 0 at the audit level.
func TestToCloudPosture_EmptyPopulationsWriteNull(t *testing.T) {
	account := AccountPosture{
		AccountID: "123456789012",
		Regions:   []string{"us-east-1"},
		S3:        S3Metrics{BucketListingEvaluated: true},
		RDS:       RDSMetrics{RegionsEvaluatedCount: 1},
		Network:   NetworkMetrics{RegionsEvaluatedCount: 1},
	}
	posture := (&Output{CollectedAtLevel: string(componentsdk.LevelAudit), Accounts: []AccountPosture{account}}).ToCloudPosture()
	got := posture.Accounts[0]

	for name, r := range map[string]Reading[float64]{
		"storage.encryption_pct":             got.Storage.EncryptionPct,
		"storage.public_access_blocked_pct":  got.Storage.PublicAccessBlockedPct,
		"database.encryption_pct":            got.Database.EncryptionPct,
		"database.public_access_blocked_pct": got.Database.PublicAccessBlockedPct,
		"database.multi_az_pct":              got.Database.MultiAZPct,
		"network.ssh_open_to_world_pct":      got.Network.SSHOpenToWorldPct,
		"network.rdp_open_to_world_pct":      got.Network.RDPOpenToWorldPct,
	} {
		if !nullReading(r) {
			t.Errorf("%s = %+v, want null", name, r)
		}
	}
	for name, present := range map[string]*bool{
		"storage_resources_present": got.Storage.StorageResourcesPresent,
		"databases_present":         got.Database.DatabasesPresent,
		"security_groups_present":   got.Network.SecurityGroupsPresent,
	} {
		if !samePtr(present, boolPtr(false)) {
			t.Errorf("%s = %s, want false", name, showBool(present))
		}
	}
	for name, count := range map[string]*int{
		"storage_resource_count": got.Storage.StorageResourceCount,
		"database_count":         got.Database.DatabaseCount,
		"security_group_count":   got.Network.SecurityGroupCount,
	} {
		if !pctIs(count, 0) {
			t.Errorf("%s = %s, want 0", name, showPct(count))
		}
	}
}

// Exposure percentages round up, so one open group in 150 reads 1, while
// coverage percentages round down.
func TestToCloudPosture_PercentagesRoundAsTheSchemaSays(t *testing.T) {
	account := evaluatedAccountFixture()
	account.Network.SecurityGroupCount = 150
	account.Network.OpenToWorldSSHSecurityGroupCount = 1
	account.Network.OpenToWorldRDPSecurityGroupCount = 0
	account.S3.BucketCount, account.S3.DefaultEncryptionEnabledBucketCount = 3, 2

	got := (&Output{CollectedAtLevel: string(componentsdk.LevelAudit), Accounts: []AccountPosture{account}}).ToCloudPosture().Accounts[0]

	for name, c := range map[string]struct {
		r    Reading[float64]
		want float64
	}{
		"ssh_open_to_world_pct": {got.Network.SSHOpenToWorldPct, 1},
		"rdp_open_to_world_pct": {got.Network.RDPOpenToWorldPct, 0},
		"encryption_pct":        {got.Storage.EncryptionPct, 66},
	} {
		if c.r.Value == nil || *c.r.Value != c.want {
			t.Errorf("%s = %+v, want %v", name, c.r, c.want)
		}
	}
}

// At the trust level the storage, database and network counts and
// multi_az_pct are left out, and the present flags are written.
func TestToCloudPosture_TrustLeavesOutSectionCounts(t *testing.T) {
	got := (&Output{CollectedAtLevel: string(componentsdk.LevelTrust), Accounts: []AccountPosture{evaluatedAccountFixture()}}).ToCloudPosture().Accounts[0]

	if got.Storage.StorageResourceCount != nil || got.Storage.EncryptedStorageResourceCount != nil || got.Storage.PublicAccessBlockedStorageResourceCount != nil {
		t.Error("a trust-level storage count was written")
	}
	if got.Database.DatabaseCount != nil || got.Database.EncryptedDatabaseCount != nil || got.Database.MultiAZDatabaseCount != nil || got.Database.MultiAZPct.Read {
		t.Error("a trust-level database count or multi_az_pct was written")
	}
	if got.Network.SecurityGroupCount != nil || got.Network.SSHOpenSecurityGroupCount != nil || got.Network.RDPOpenSecurityGroupCount != nil {
		t.Error("a trust-level network count was written")
	}
	for name, present := range map[string]*bool{
		"storage_resources_present": got.Storage.StorageResourcesPresent,
		"databases_present":         got.Database.DatabasesPresent,
		"security_groups_present":   got.Network.SecurityGroupsPresent,
	} {
		if !samePtr(present, boolPtr(true)) {
			t.Errorf("%s = %s, want true", name, showBool(present))
		}
	}
	if v := got.Database.EncryptionPct.Value; v == nil || *v != 100 {
		t.Errorf("database.encryption_pct = %v, want 100 at trust", v)
	}
}

// Threat detection is on only when every scanned region has an enabled
// detector, and is left out for an account with no region list.
func TestToCloudPosture_ThreatDetection(t *testing.T) {
	on := evaluatedAccountFixture()
	off := evaluatedAccountFixture()
	off.AccountSecurity.GuardDuty = GuardDutyStatus{Enabled: true}
	noRegions := evaluatedAccountFixture()
	noRegions.Regions = nil

	posture := (&Output{Accounts: []AccountPosture{on, off, noRegions}}).ToCloudPosture()

	if got := posture.Accounts[0].ThreatDetection.Enabled; !samePtr(got, boolPtr(true)) {
		t.Errorf("every region on: enabled = %s, want true", showBool(got))
	}
	if got := posture.Accounts[1].ThreatDetection.Enabled; !samePtr(got, boolPtr(false)) {
		t.Errorf("a region off: enabled = %s, want false", showBool(got))
	}
	if got := posture.Accounts[2].ThreatDetection.Enabled; got != nil {
		t.Errorf("no region list: enabled = %s, want it left out", showBool(got))
	}
}

// S3 has no setting that turns off public network access, so the storage
// network restriction values are left out as unsupported, the count only from
// the audit level, where the schema writes it.
func TestToCloudPosture_StorageNetworkRestrictionUnsupported(t *testing.T) {
	for _, tc := range []struct {
		level componentsdk.Level
		want  []string
	}{
		{componentsdk.LevelTrust, []string{"/accounts/0/storage/network_restricted_pct"}},
		{componentsdk.LevelAudit, []string{"/accounts/0/storage/network_restricted_pct", "/accounts/0/storage/network_restricted_storage_resource_count"}},
	} {
		gaps := newGapLog(nil)
		toCloudPosture(&Output{CollectedAtLevel: string(tc.level), Accounts: []AccountPosture{evaluatedAccountFixture()}}, gaps)

		var got []string
		for _, g := range gaps.gaps {
			if g.path == cloudPosturePath && strings.Contains(g.pointer, "/storage/network_restricted") {
				if code := componentsdk.Classify(g.err); code != componentsdk.CodeUnsupported {
					t.Errorf("%s at %s: gap code %s, want unsupported", tc.level, g.pointer, code)
				}
				got = append(got, g.pointer)
			}
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: gaps at %v, want %v", tc.level, got, tc.want)
		}
	}
}
