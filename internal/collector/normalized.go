// Package collector provides AWS account posture collection functionality.
package collector

import (
	"encoding/json"
	"fmt"

	"github.com/locktivity/epack/componentsdk"
)

// CloudPosture represents the normalized cloud infrastructure posture.
// This follows the evidencepack/cloud-posture@v1 schema specification.
// Fields are designed to be vendor-agnostic (works for AWS, GCP, Azure).
// The schema marks the account IDs and the counts as audit-level, so they are
// written from the audit level only. AllAccountsCollected and the present
// flags are written at every level. WorkforceSignIn and each account's IAM
// and VulnScanning are deprecated blocks, written at every level as before
// epack v0.10.0 (see deprecated.go).
type CloudPosture struct {
	SchemaVersion        string                      `json:"schema_version"`
	CollectedAt          string                      `json:"collected_at"`
	Provider             string                      `json:"provider"`
	AccountsExpected     *int                        `json:"accounts_expected,omitempty"`
	AllAccountsCollected *bool                       `json:"all_accounts_collected,omitempty"`
	Accounts             []CloudPostureAccount       `json:"accounts"`
	WorkforceSignIn      CloudPostureWorkforceSignIn `json:"workforce_sign_in,omitzero"`
}

// Reading is a normalized value that may have no reading in the detailed
// artifact. It is left out when Read is false. Otherwise it is written as
// Value, which is nil for a percentage over no users.
type Reading[T any] struct {
	Value *T
	Read  bool
}

// IsZero reports whether the value has no reading, for omitzero.
func (r Reading[T]) IsZero() bool { return !r.Read }

// MarshalJSON writes the value, or null.
func (r Reading[T]) MarshalJSON() ([]byte, error) { return json.Marshal(r.Value) }

// UnmarshalJSON reads a value or null as a reading.
func (r *Reading[T]) UnmarshalJSON(data []byte) error {
	r.Read = true
	return json.Unmarshal(data, &r.Value)
}

// CloudPostureAccount contains normalized metrics for a single cloud account.
// A metric group with no metric left in it is left out. A failed account
// appears as a stub entry with collection_error_code set and no metric
// groups, so a consumer can distinguish "account healthy with no findings"
// from "account never answered".
type CloudPostureAccount struct {
	AccountID           string                      `json:"account_id,omitempty"`
	AccountLabel        string                      `json:"account_label,omitempty"`
	CollectionErrorCode string                      `json:"collection_error_code,omitempty"`
	Storage             CloudPostureStorage         `json:"storage,omitzero"`
	Database            CloudPostureDatabase        `json:"database,omitzero"`
	Logging             CloudPostureLogging         `json:"logging,omitzero"`
	Network             CloudPostureNetwork         `json:"network,omitzero"`
	Backup              CloudPostureBackup          `json:"backup,omitzero"`
	ThreatDetection     CloudPostureThreatDetection `json:"threat_detection,omitzero"`
	IAM                 CloudPostureIAM             `json:"iam,omitzero"`
	VulnScanning        CloudPostureVulnScanning    `json:"vuln_scanning,omitzero"`
}

// CloudPostureStorage contains normalized storage security metrics over the
// S3 buckets, omitted when the bucket listing (or the specific metric's
// inputs) was not evaluated. The counts are written from the audit level, and
// the percentages are null when there are no buckets.
type CloudPostureStorage struct {
	StorageResourcesPresent                 *bool            `json:"storage_resources_present,omitempty"`
	StorageResourceCount                    *int             `json:"storage_resource_count,omitempty"`
	EncryptedStorageResourceCount           *int             `json:"encrypted_storage_resource_count,omitempty"`
	PublicAccessBlockedStorageResourceCount *int             `json:"public_access_blocked_storage_resource_count,omitempty"`
	EncryptionPct                           Reading[float64] `json:"encryption_pct,omitzero"`
	PublicAccessBlockedPct                  Reading[float64] `json:"public_access_blocked_pct,omitzero"`
}

// CloudPostureDatabase contains normalized metrics over the RDS instances and
// clusters, omitted unless every requested region evaluated. The counts and
// multi_az_pct are written from the audit level, and the percentages are null
// when there are no databases. A cluster has public access blocked when none
// of its instances is publicly accessible.
type CloudPostureDatabase struct {
	DatabasesPresent                 *bool            `json:"databases_present,omitempty"`
	DatabaseCount                    *int             `json:"database_count,omitempty"`
	EncryptedDatabaseCount           *int             `json:"encrypted_database_count,omitempty"`
	PublicAccessBlockedDatabaseCount *int             `json:"public_access_blocked_database_count,omitempty"`
	EncryptionPct                    Reading[float64] `json:"encryption_pct,omitzero"`
	PublicAccessBlockedPct           Reading[float64] `json:"public_access_blocked_pct,omitzero"`
	MultiAZDatabaseCount             *int             `json:"multi_az_database_count,omitempty"`
	MultiAZPct                       Reading[float64] `json:"multi_az_pct,omitzero"`
}

// CloudPostureLogging contains normalized logging configuration, omitted when
// the trail listing was not evaluated. A false value is emitted only when
// every trail status was readable: "no trail is logging" and "a trail's
// status was unreadable" must not look the same. The cloudtrail_* fields are
// the schema's deprecated names for the audit_log_* fields; they carry the
// same values until cloud-posture v2 removes them.
type CloudPostureLogging struct {
	AuditLogEnabled       *bool `json:"audit_log_enabled,omitempty"`
	AuditLogAllRegions    *bool `json:"audit_log_all_regions,omitempty"`
	CloudTrailEnabled     *bool `json:"cloudtrail_enabled,omitempty"`
	CloudTrailMultiregion *bool `json:"cloudtrail_multiregion,omitempty"`
}

// CloudPostureNetwork contains normalized network exposure metrics over the
// security groups, omitted unless every requested region evaluated, since a
// region that was not read could hold an exposed group. The counts are
// written from the audit level, and the percentages are null when there are
// no security groups.
type CloudPostureNetwork struct {
	SecurityGroupsPresent     *bool            `json:"security_groups_present,omitempty"`
	SecurityGroupCount        *int             `json:"security_group_count,omitempty"`
	SSHOpenSecurityGroupCount *int             `json:"ssh_open_security_group_count,omitempty"`
	RDPOpenSecurityGroupCount *int             `json:"rdp_open_security_group_count,omitempty"`
	SSHOpenToWorldPct         Reading[float64] `json:"ssh_open_to_world_pct,omitzero"`
	RDPOpenToWorldPct         Reading[float64] `json:"rdp_open_to_world_pct,omitzero"`
}

// CloudPostureBackup contains normalized backup configuration, omitted unless
// every requested region evaluated and at least one database exists. The
// minimum is over the databases with automated backups on, and null when
// none has them on.
type CloudPostureBackup struct {
	RetentionDaysMin Reading[int] `json:"retention_days_min,omitzero"`
}

// CloudPostureThreatDetection contains whether GuardDuty is on in every
// scanned region, omitted when a region's detectors could not be read and no
// region showed it off.
type CloudPostureThreatDetection struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// ToCloudPosture transforms detailed AWS output to normalized cloud-posture
// format at the level o was collected at.
func (o *Output) ToCloudPosture() *CloudPosture {
	return toCloudPosture(o, nil)
}

// cloudPosture builds the normalized artifact for output. A normalized value
// whose detailed source was left out is left out too, with the same gap.
func (c *Collector) cloudPosture(o *Output) *CloudPosture {
	return toCloudPosture(o, c.gaps)
}

// normalizedSources pairs each normalized metric with the detailed values it
// is derived from, by pointer under the account's entry. The first source is
// the one the metric copies, unless countedNormalized has it. audit is true
// for the counts the schema marks audit-level, which are written from the
// audit level only.
var normalizedSources = []struct {
	field   string
	sources []string
	audit   bool
}{
	{"storage/storage_resources_present", []string{"s3/bucket_count"}, false},
	{"storage/storage_resource_count", []string{"s3/bucket_count"}, true},
	{"storage/encrypted_storage_resource_count", []string{"s3/default_encryption_enabled_bucket_count"}, true},
	{"storage/public_access_blocked_storage_resource_count", []string{"s3/public_access_blocked_bucket_count"}, true},
	{"storage/encryption_pct", []string{"s3/default_encryption_enabled"}, false},
	{"storage/public_access_blocked_pct", []string{"s3/public_access_blocked"}, false},
	{"database/databases_present", []string{"rds/database_count"}, false},
	{"database/database_count", []string{"rds/database_count"}, true},
	{"database/encrypted_database_count", []string{"rds/encrypted_at_rest_database_count"}, true},
	{"database/encryption_pct", []string{"rds/encrypted_at_rest"}, false},
	{"database/public_access_blocked_database_count", []string{"rds/public_access_blocked_database_count"}, true},
	{"database/public_access_blocked_pct", []string{"rds/public_access_blocked"}, false},
	{"database/multi_az_database_count", []string{"rds/multi_az_enabled_database_count"}, true},
	{"database/multi_az_pct", []string{"rds/multi_az_enabled"}, true},
	{"logging/audit_log_enabled", []string{"account_security/cloudtrail/enabled"}, false},
	{"logging/audit_log_all_regions", []string{"account_security/cloudtrail/multi_region_enabled"}, false},
	{"logging/cloudtrail_enabled", []string{"account_security/cloudtrail/enabled"}, false},
	{"logging/cloudtrail_multiregion", []string{"account_security/cloudtrail/multi_region_enabled"}, false},
	{"network/security_groups_present", []string{"network/security_group_count"}, false},
	{"network/security_group_count", []string{"network/security_group_count"}, true},
	{"network/ssh_open_security_group_count", []string{"network/open_to_world_ssh_security_group_count"}, true},
	{"network/rdp_open_security_group_count", []string{"network/open_to_world_rdp_security_group_count"}, true},
	{"network/ssh_open_to_world_pct", []string{"network/open_to_world_ssh"}, false},
	{"network/rdp_open_to_world_pct", []string{"network/open_to_world_rdp"}, false},
	{"backup/retention_days_min", []string{"rds/backup_retention_min"}, false},
	{"threat_detection/enabled", []string{"account_security/guardduty/enabled_in_all_regions"}, false},
	// The deprecated blocks in deprecated.go.
	{"iam/mfa_coverage_pct", []string{"iam/console_mfa_enabled"}, false},
	{"iam/root_mfa_enabled", []string{"iam/root_mfa_enabled", "iam/root_credentials_present"}, false},
	{"iam/root_access_protected", []string{"iam/root_access_protected"}, false},
	{"iam/access_key_rotation_compliant_pct", []string{"iam/access_keys_rotated"}, false},
	{"iam/user_count", []string{"iam/console_user_count"}, false},
	{"iam/access_key_user_count", []string{"iam/access_key_user_count"}, false},
	{"iam/saml_provider_count", []string{"iam/saml_provider_count"}, false},
	{"vuln_scanning/enabled", []string{"account_security/inspector/enabled"}, false},
	{"vuln_scanning/unpatched_pct", []string{"account_security/inspector/unpatched_server_percent"}, false},
}

// countedNormalized are the metrics counted from the same reads as their
// detailed sources rather than copied from them: the deprecated access key
// values count the root user's keys too, and the retention minimum leaves
// out the databases with automated backups off. They carry their sources'
// gaps, and methods.json says how each is counted.
var countedNormalized = map[string]bool{
	"iam/access_key_user_count":             true,
	"iam/access_key_rotation_compliant_pct": true,
	"backup/retention_days_min":             true,
}

// storageNetworkUnsupported is why the storage network restriction values
// are left out: S3 has no setting that turns off public network access.
var storageNetworkUnsupported = unsupported("S3 has no setting that turns off public network access for a bucket or an account.")

// failedAccountsPointer is the detailed list the account totals come from.
const failedAccountsPointer = "/failed_accounts"

func toCloudPosture(o *Output, gaps *gapLog) *CloudPosture {
	audit := componentsdk.Level(o.CollectedAtLevel).AtLeast(componentsdk.LevelAudit)
	posture := &CloudPosture{
		SchemaVersion:        "1.0.0",
		CollectedAt:          o.CollectedAt,
		Provider:             "aws",
		AllAccountsCollected: boolPtr(len(o.FailedAccounts) == 0),
		Accounts:             make([]CloudPostureAccount, 0, len(o.Accounts)+len(o.FailedAccounts)),
	}
	if gaps != nil {
		gaps.copied(failedAccountsPointer, "/all_accounts_collected")
	}
	if audit {
		posture.AccountsExpected = intPtr(len(o.Accounts) + len(o.FailedAccounts))
		if gaps != nil {
			gaps.copied(failedAccountsPointer, "/accounts_expected")
		}
	}

	for i, acct := range o.Accounts {
		normalized := CloudPostureAccount{
			AccountLabel:    acct.AccountLabel,
			Storage:         normalizedStorage(acct.S3, audit),
			Database:        normalizedDatabase(acct.RDS, audit),
			Logging:         normalizedLogging(acct.AccountSecurity.CloudTrail),
			Network:         normalizedNetwork(acct.Network, audit),
			Backup:          normalizedBackup(acct.RDS),
			ThreatDetection: normalizedThreatDetection(acct.AccountSecurity.GuardDuty, acct.Regions),
			IAM:             normalizedIAM(acct.IAM),
			VulnScanning:    normalizedVulnScanning(acct.AccountSecurity.Inspector),
		}
		if audit {
			normalized.AccountID = acct.AccountID
		}
		if gaps != nil {
			mirrorNormalizedGaps(gaps, i, &normalized, audit)
			gaps.movedDeprecated(i)
			storage := fmt.Sprintf("/accounts/%d/storage/", i)
			storageNetworkUnsupported.record(gaps, cloudPosturePath, storage+"network_restricted_pct")
			if audit {
				storageNetworkUnsupported.record(gaps, cloudPosturePath, storage+"network_restricted_storage_resource_count")
			}
		}
		posture.Accounts = append(posture.Accounts, normalized)
	}

	for _, failed := range o.FailedAccounts {
		j := len(posture.Accounts)
		stub := CloudPostureAccount{
			AccountLabel:        failed.Label,
			CollectionErrorCode: failed.ErrorCode,
		}
		if audit {
			stub.AccountID = failed.AccountID
		}
		posture.Accounts = append(posture.Accounts, stub)
		if gaps != nil {
			gaps.movedDeprecated(j)
			for _, metric := range normalizedSources {
				if metric.audit && !audit {
					continue
				}
				gaps.leaveOutNormalized(failed.err, fmt.Sprintf("/accounts/%d/%s", j, metric.field))
			}
		}
	}

	workforceGaps := gaps
	if workforceGaps == nil {
		workforceGaps = newGapLog(nil)
	}
	posture.WorkforceSignIn = normalizedWorkforceSignIn(o, workforceGaps)
	if gaps != nil {
		gaps.rec.Moved(componentsdk.Location{Path: cloudPosturePath, Pointer: "/workforce_sign_in"}, accessPostureArtifact)
	}

	return posture
}

// mirrorNormalizedGaps leaves out each of account i's normalized metrics
// whose detailed source a gap covers, recording the source's gap at it. A
// metric no gap covers is recorded as a copy of its first source, unless it
// is counted. The counts are passed over below the audit level, where they
// are not written.
func mirrorNormalizedGaps(gaps *gapLog, i int, account *CloudPostureAccount, audit bool) {
	for _, metric := range normalizedSources {
		if metric.audit && !audit {
			continue
		}
		to := fmt.Sprintf("/accounts/%d/%s", i, metric.field)
		covered := false
		for _, source := range metric.sources {
			if gaps.mirror(fmt.Sprintf("/accounts/%d/%s", i, source), to) {
				clearNormalized(account, metric.field)
				covered = true
				break
			}
		}
		if !covered && !countedNormalized[metric.field] {
			gaps.copied(fmt.Sprintf("/accounts/%d/%s", i, metric.sources[0]), to)
		}
	}
}

// clearNormalized leaves one normalized metric out of account.
func clearNormalized(account *CloudPostureAccount, field string) {
	switch field {
	case "storage/storage_resources_present":
		account.Storage.StorageResourcesPresent = nil
	case "storage/storage_resource_count":
		account.Storage.StorageResourceCount = nil
	case "storage/encrypted_storage_resource_count":
		account.Storage.EncryptedStorageResourceCount = nil
	case "storage/public_access_blocked_storage_resource_count":
		account.Storage.PublicAccessBlockedStorageResourceCount = nil
	case "storage/encryption_pct":
		account.Storage.EncryptionPct = Reading[float64]{}
	case "storage/public_access_blocked_pct":
		account.Storage.PublicAccessBlockedPct = Reading[float64]{}
	case "database/databases_present":
		account.Database.DatabasesPresent = nil
	case "database/database_count":
		account.Database.DatabaseCount = nil
	case "database/encrypted_database_count":
		account.Database.EncryptedDatabaseCount = nil
	case "database/public_access_blocked_database_count":
		account.Database.PublicAccessBlockedDatabaseCount = nil
	case "database/encryption_pct":
		account.Database.EncryptionPct = Reading[float64]{}
	case "database/public_access_blocked_pct":
		account.Database.PublicAccessBlockedPct = Reading[float64]{}
	case "database/multi_az_database_count":
		account.Database.MultiAZDatabaseCount = nil
	case "database/multi_az_pct":
		account.Database.MultiAZPct = Reading[float64]{}
	case "logging/audit_log_enabled":
		account.Logging.AuditLogEnabled = nil
	case "logging/audit_log_all_regions":
		account.Logging.AuditLogAllRegions = nil
	case "logging/cloudtrail_enabled":
		account.Logging.CloudTrailEnabled = nil
	case "logging/cloudtrail_multiregion":
		account.Logging.CloudTrailMultiregion = nil
	case "network/security_groups_present":
		account.Network.SecurityGroupsPresent = nil
	case "network/security_group_count":
		account.Network.SecurityGroupCount = nil
	case "network/ssh_open_security_group_count":
		account.Network.SSHOpenSecurityGroupCount = nil
	case "network/rdp_open_security_group_count":
		account.Network.RDPOpenSecurityGroupCount = nil
	case "network/ssh_open_to_world_pct":
		account.Network.SSHOpenToWorldPct = Reading[float64]{}
	case "network/rdp_open_to_world_pct":
		account.Network.RDPOpenToWorldPct = Reading[float64]{}
	case "backup/retention_days_min":
		account.Backup.RetentionDaysMin = Reading[int]{}
	case "threat_detection/enabled":
		account.ThreatDetection.Enabled = nil
	case "iam/mfa_coverage_pct":
		account.IAM.MFACoveragePct = nil
	case "iam/root_mfa_enabled":
		account.IAM.RootMFAEnabled = nil
	case "iam/root_access_protected":
		account.IAM.RootAccessProtected = nil
	case "iam/access_key_rotation_compliant_pct":
		account.IAM.AccessKeyRotationCompliantPct = nil
	case "iam/user_count":
		account.IAM.UserCount = nil
	case "iam/access_key_user_count":
		account.IAM.AccessKeyUserCount = nil
	case "iam/saml_provider_count":
		account.IAM.SAMLProviderCount = nil
	case "vuln_scanning/enabled":
		account.VulnScanning.Enabled = nil
	case "vuln_scanning/unpatched_pct":
		account.VulnScanning.UnpatchedPct = nil
	}
}

// normalizedStorage emits the storage metrics only when their inputs were
// evaluated. Every bucket's encryption setting and effective public access
// block must be known, since unknowns otherwise drag a percentage toward
// failure. Both percentages are null for an account with no buckets. The
// counts are written when audit is true.
func normalizedStorage(s3 S3Metrics, audit bool) CloudPostureStorage {
	out := CloudPostureStorage{}
	if !s3.BucketListingEvaluated {
		return out
	}
	out.StorageResourcesPresent = boolPtr(s3.BucketCount > 0)
	if audit {
		out.StorageResourceCount = intPtr(s3.BucketCount)
	}
	if s3.DefaultEncryptionUnknownCount == 0 {
		out.EncryptionPct = percentOf(s3.DefaultEncryptionEnabledBucketCount, s3.BucketCount, componentsdk.RoundDown)
		if audit {
			out.EncryptedStorageResourceCount = intPtr(s3.DefaultEncryptionEnabledBucketCount)
		}
	}
	if s3.PublicAccessBlockUnknownCount == 0 {
		out.PublicAccessBlockedPct = percentOf(s3.PublicAccessBlockedBucketCount, s3.BucketCount, componentsdk.RoundDown)
		if audit {
			out.PublicAccessBlockedStorageResourceCount = intPtr(s3.PublicAccessBlockedBucketCount)
		}
	}
	return out
}

// normalizedDatabase emits the database metrics only when every requested
// region evaluated, since a region that was not read could hold a database.
// The percentages are null for an account with no databases. The counts and
// multi_az_pct are written when audit is true.
func normalizedDatabase(rds RDSMetrics, audit bool) CloudPostureDatabase {
	out := CloudPostureDatabase{}
	if rds.RegionsEvaluatedCount == 0 || len(rds.RegionsFailed) > 0 {
		return out
	}
	out.DatabasesPresent = boolPtr(rds.DatabaseCount > 0)
	out.EncryptionPct = percentOf(rds.EncryptedAtRestDatabaseCount, rds.DatabaseCount, componentsdk.RoundDown)
	out.PublicAccessBlockedPct = percentOf(rds.PublicAccessBlockedDatabaseCount, rds.DatabaseCount, componentsdk.RoundDown)
	if audit {
		out.DatabaseCount = intPtr(rds.DatabaseCount)
		out.EncryptedDatabaseCount = intPtr(rds.EncryptedAtRestDatabaseCount)
		out.PublicAccessBlockedDatabaseCount = intPtr(rds.PublicAccessBlockedDatabaseCount)
		out.MultiAZDatabaseCount = intPtr(rds.MultiAZEnabledDatabaseCount)
		out.MultiAZPct = percentOf(rds.MultiAZEnabledDatabaseCount, rds.DatabaseCount, componentsdk.RoundDown)
	}
	return out
}

// normalizedLogging emits the CloudTrail booleans, under both their names,
// only when the trail listing was evaluated. True values are definite (a
// logging trail was observed); false values are emitted only when every trail
// status was readable.
func normalizedLogging(ct CloudTrailStatus) CloudPostureLogging {
	out := CloudPostureLogging{}
	if !ct.TrailListingEvaluated {
		return out
	}
	if ct.Enabled || ct.TrailStatusUnknownCount == 0 {
		out.AuditLogEnabled = boolPtr(ct.Enabled)
		out.CloudTrailEnabled = boolPtr(ct.Enabled)
	}
	if ct.MultiRegionEnabled || ct.TrailStatusUnknownCount == 0 {
		out.AuditLogAllRegions = boolPtr(ct.MultiRegionEnabled)
		out.CloudTrailMultiregion = boolPtr(ct.MultiRegionEnabled)
	}
	return out
}

// normalizedNetwork emits the exposure metrics only when every requested
// region evaluated. A region that failed to answer could contain the exposed
// security group, so a partial percentage could read as a pass. The
// percentages round up, so one exposed group never reads as 0. The counts are
// written when audit is true.
func normalizedNetwork(n NetworkMetrics, audit bool) CloudPostureNetwork {
	out := CloudPostureNetwork{}
	if n.RegionsEvaluatedCount == 0 || len(n.RegionsFailed) > 0 {
		return out
	}
	out.SecurityGroupsPresent = boolPtr(n.SecurityGroupCount > 0)
	out.SSHOpenToWorldPct = percentOf(n.OpenToWorldSSHSecurityGroupCount, n.SecurityGroupCount, componentsdk.RoundUp)
	out.RDPOpenToWorldPct = percentOf(n.OpenToWorldRDPSecurityGroupCount, n.SecurityGroupCount, componentsdk.RoundUp)
	if audit {
		out.SecurityGroupCount = intPtr(n.SecurityGroupCount)
		out.SSHOpenSecurityGroupCount = intPtr(n.OpenToWorldSSHSecurityGroupCount)
		out.RDPOpenSecurityGroupCount = intPtr(n.OpenToWorldRDPSecurityGroupCount)
	}
	return out
}

// normalizedBackup emits the retention minimum only when every requested
// region evaluated and at least one database exists. It is the shortest
// retention among the databases with automated backups on, and null when
// none has them on, since a database with backups off keeps none.
func normalizedBackup(rds RDSMetrics) CloudPostureBackup {
	if rds.RegionsEvaluatedCount == 0 || len(rds.RegionsFailed) > 0 || rds.DatabaseCount == 0 {
		return CloudPostureBackup{}
	}
	return CloudPostureBackup{RetentionDaysMin: Reading[int]{Value: rds.backedUpRetentionMin, Read: true}}
}

// normalizedThreatDetection emits whether GuardDuty is on in every scanned
// region. A region whose detectors could not be read leaves it out unless
// another region already shows it off, which the detailed value's gap
// records. It is left out for an account with no region list.
func normalizedThreatDetection(gd GuardDutyStatus, regions []string) CloudPostureThreatDetection {
	if len(regions) == 0 {
		return CloudPostureThreatDetection{}
	}
	return CloudPostureThreatDetection{Enabled: boolPtr(gd.EnabledInAllRegions)}
}

func float64Ptr(v float64) *float64 { return &v }

// percentOf is count as a whole percentage of total, rounded as the
// normalized schema's x-epack-rounding says. It is read and null when total
// is 0.
func percentOf(count, total int, rounding componentsdk.Rounding) Reading[float64] {
	p := componentsdk.Percent(count, total, rounding)
	if p == nil {
		return Reading[float64]{Read: true}
	}
	return Reading[float64]{Value: float64Ptr(float64(*p)), Read: true}
}

func intPtr(v int) *int { return &v }
