// Package collector provides AWS account posture collection functionality.
package collector

import "fmt"

// CloudPosture represents the normalized cloud infrastructure posture.
// This follows the evidencepack/cloud-posture@v1 schema specification.
// Fields are designed to be vendor-agnostic (works for AWS, GCP, Azure).
type CloudPosture struct {
	SchemaVersion    string                `json:"schema_version"`
	CollectedAt      string                `json:"collected_at"`
	Provider         string                `json:"provider"`
	AccountsExpected int                   `json:"accounts_expected"`
	Accounts         []CloudPostureAccount `json:"accounts"`
}

// CloudPostureAccount contains normalized metrics for a single cloud account.
// A metric group with no metric left in it is left out. A failed account
// appears as a stub entry with collection_error_code set and no metric
// groups, so a consumer can distinguish "account healthy with no findings"
// from "account never answered".
type CloudPostureAccount struct {
	AccountID           string                   `json:"account_id,omitempty"`
	AccountLabel        string                   `json:"account_label,omitempty"`
	CollectionErrorCode string                   `json:"collection_error_code,omitempty"`
	IAM                 CloudPostureIAM          `json:"iam,omitzero"`
	Storage             CloudPostureStorage      `json:"storage,omitzero"`
	Logging             CloudPostureLogging      `json:"logging,omitzero"`
	Network             CloudPostureNetwork      `json:"network,omitzero"`
	Backup              CloudPostureBackup       `json:"backup,omitzero"`
	VulnScanning        CloudPostureVulnScanning `json:"vuln_scanning,omitzero"`
}

// CloudPostureIAM contains normalized IAM metrics. Fields are pointers so an
// uncollected metric (credential report or root state failed upstream) is
// omitted from the artifact rather than serialized as a worst-case zero/false.
type CloudPostureIAM struct {
	MFACoveragePct                *float64 `json:"mfa_coverage_pct,omitempty"`
	RootMFAEnabled                *bool    `json:"root_mfa_enabled,omitempty"`
	RootAccessProtected           *bool    `json:"root_access_protected,omitempty"`
	AccessKeyRotationCompliantPct *float64 `json:"access_key_rotation_compliant_pct,omitempty"`
}

// CloudPostureStorage contains normalized storage security metrics, omitted
// when the bucket listing (or the specific metric's inputs) was not evaluated.
type CloudPostureStorage struct {
	EncryptionPct          *float64 `json:"encryption_pct,omitempty"`
	PublicAccessBlockedPct *float64 `json:"public_access_blocked_pct,omitempty"`
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

// CloudPostureNetwork contains normalized network exposure metrics, omitted
// unless every requested region evaluated: partial coverage can only
// understate exposure, which would fabricate a passing metric.
type CloudPostureNetwork struct {
	SSHOpenToWorldPct *float64 `json:"ssh_open_to_world_pct,omitempty"`
	RDPOpenToWorldPct *float64 `json:"rdp_open_to_world_pct,omitempty"`
}

// CloudPostureBackup contains normalized backup configuration, omitted unless
// every requested region evaluated and at least one database exists.
type CloudPostureBackup struct {
	RetentionDaysMin *int `json:"retention_days_min,omitempty"`
}

// CloudPostureVulnScanning contains normalized vulnerability scanning status,
// omitted when the Inspector status was not evaluated.
type CloudPostureVulnScanning struct {
	Enabled      *bool    `json:"enabled,omitempty"`
	UnpatchedPct *float64 `json:"unpatched_pct,omitempty"`
}

// ToCloudPosture transforms detailed AWS output to normalized cloud-posture format.
func (o *Output) ToCloudPosture() *CloudPosture {
	return toCloudPosture(o, nil)
}

// cloudPosture builds the normalized artifact for output. A normalized value
// whose detailed source was left out is left out too, with the same gap.
func (c *Collector) cloudPosture(o *Output) *CloudPosture {
	return toCloudPosture(o, c.gaps)
}

// normalizedSources pairs each normalized metric with the detailed values it
// is derived from, by pointer under the account's entry.
var normalizedSources = []struct {
	field   string
	sources []string
}{
	{"iam/mfa_coverage_pct", []string{"iam/mfa_enabled"}},
	{"iam/root_mfa_enabled", []string{"iam/root_mfa_enabled", "iam/root_credentials_present"}},
	{"iam/root_access_protected", []string{"iam/root_access_protected"}},
	{"iam/access_key_rotation_compliant_pct", []string{"iam/access_keys_rotated"}},
	{"storage/encryption_pct", []string{"s3/default_encryption_enabled"}},
	{"storage/public_access_blocked_pct", []string{"s3/public_access_blocked"}},
	{"logging/audit_log_enabled", []string{"account_security/cloudtrail/enabled"}},
	{"logging/audit_log_all_regions", []string{"account_security/cloudtrail/multi_region_enabled"}},
	{"logging/cloudtrail_enabled", []string{"account_security/cloudtrail/enabled"}},
	{"logging/cloudtrail_multiregion", []string{"account_security/cloudtrail/multi_region_enabled"}},
	{"network/ssh_open_to_world_pct", []string{"network/open_to_world_ssh"}},
	{"network/rdp_open_to_world_pct", []string{"network/open_to_world_rdp"}},
	{"backup/retention_days_min", []string{"rds/backup_retention_min"}},
	{"vuln_scanning/enabled", []string{"account_security/inspector/enabled"}},
	{"vuln_scanning/unpatched_pct", []string{"account_security/inspector/unpatched_server_percent"}},
}

func toCloudPosture(o *Output, gaps *gapLog) *CloudPosture {
	posture := &CloudPosture{
		SchemaVersion:    "1.0.0",
		CollectedAt:      o.CollectedAt,
		Provider:         "aws",
		AccountsExpected: len(o.Accounts) + len(o.FailedAccounts),
		Accounts:         make([]CloudPostureAccount, 0, len(o.Accounts)+len(o.FailedAccounts)),
	}

	for i, acct := range o.Accounts {
		normalized := CloudPostureAccount{
			AccountID:    acct.AccountID,
			AccountLabel: acct.AccountLabel,
			IAM:          normalizedIAM(acct.IAM),
			Storage:      normalizedStorage(acct.S3),
			Logging:      normalizedLogging(acct.AccountSecurity.CloudTrail),
			Network:      normalizedNetwork(acct.Network),
			Backup:       normalizedBackup(acct.RDS),
			VulnScanning: normalizedVulnScanning(acct.AccountSecurity.Inspector),
		}
		if gaps != nil {
			mirrorNormalizedGaps(gaps, i, &normalized)
		}
		posture.Accounts = append(posture.Accounts, normalized)
	}

	for _, failed := range o.FailedAccounts {
		j := len(posture.Accounts)
		posture.Accounts = append(posture.Accounts, CloudPostureAccount{
			AccountID:           failed.AccountID,
			AccountLabel:        failed.Label,
			CollectionErrorCode: failed.ErrorCode,
		})
		if gaps != nil {
			for _, metric := range normalizedSources {
				gaps.leaveOutNormalized(failed.err, fmt.Sprintf("/accounts/%d/%s", j, metric.field))
			}
		}
	}

	return posture
}

// mirrorNormalizedGaps leaves out each of account i's normalized metrics
// whose detailed source a gap covers, recording the source's gap at it.
func mirrorNormalizedGaps(gaps *gapLog, i int, account *CloudPostureAccount) {
	for _, metric := range normalizedSources {
		for _, source := range metric.sources {
			from := fmt.Sprintf("/accounts/%d/%s", i, source)
			if gaps.mirror(from, fmt.Sprintf("/accounts/%d/%s", i, metric.field)) {
				clearNormalized(account, metric.field)
				break
			}
		}
	}
}

// clearNormalized leaves one normalized metric out of account.
func clearNormalized(account *CloudPostureAccount, field string) {
	switch field {
	case "iam/mfa_coverage_pct":
		account.IAM.MFACoveragePct = nil
	case "iam/root_mfa_enabled":
		account.IAM.RootMFAEnabled = nil
	case "iam/root_access_protected":
		account.IAM.RootAccessProtected = nil
	case "iam/access_key_rotation_compliant_pct":
		account.IAM.AccessKeyRotationCompliantPct = nil
	case "storage/encryption_pct":
		account.Storage.EncryptionPct = nil
	case "storage/public_access_blocked_pct":
		account.Storage.PublicAccessBlockedPct = nil
	case "logging/audit_log_enabled":
		account.Logging.AuditLogEnabled = nil
	case "logging/audit_log_all_regions":
		account.Logging.AuditLogAllRegions = nil
	case "logging/cloudtrail_enabled":
		account.Logging.CloudTrailEnabled = nil
	case "logging/cloudtrail_multiregion":
		account.Logging.CloudTrailMultiregion = nil
	case "network/ssh_open_to_world_pct":
		account.Network.SSHOpenToWorldPct = nil
	case "network/rdp_open_to_world_pct":
		account.Network.RDPOpenToWorldPct = nil
	case "backup/retention_days_min":
		account.Backup.RetentionDaysMin = nil
	case "vuln_scanning/enabled":
		account.VulnScanning.Enabled = nil
	case "vuln_scanning/unpatched_pct":
		account.VulnScanning.UnpatchedPct = nil
	}
}

// normalizedIAM projects IAM metrics into the normalized artifact, emitting
// only the metrics whose upstream source was actually evaluated.
func normalizedIAM(iam IAMMetrics) CloudPostureIAM {
	out := CloudPostureIAM{}
	if iam.CredentialReportEvaluated {
		out.MFACoveragePct = pctFloat(iam.MFAEnabled)
		out.AccessKeyRotationCompliantPct = pctFloat(iam.AccessKeysRotated)
	}
	if iam.RootCredentialStateEvaluated {
		// An account whose root credentials were removed through centralized
		// root access has no root login to protect, so the normalized MFA
		// answer is yes. The raw aws.json field stays literal.
		out.RootMFAEnabled = boolPtr(iam.RootMFAEnabled || !iam.RootCredentialsPresent)
		out.RootAccessProtected = boolPtr(iam.RootAccessProtected)
	}
	return out
}

// normalizedStorage emits the storage percentages only when their inputs were
// evaluated: every bucket's encryption setting and effective public access
// block must be known, since unknowns otherwise drag a percentage toward
// failure. Neither is emitted for an account with no buckets.
func normalizedStorage(s3 S3Metrics) CloudPostureStorage {
	out := CloudPostureStorage{}
	if !s3.BucketListingEvaluated {
		return out
	}
	if s3.DefaultEncryptionUnknownCount == 0 {
		out.EncryptionPct = pctFloat(s3.DefaultEncryptionEnabled)
	}
	if s3.PublicAccessBlockUnknownCount == 0 {
		out.PublicAccessBlockedPct = pctFloat(s3.PublicAccessBlocked)
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

// normalizedNetwork emits the exposure percentages only when every requested
// region evaluated. A region that failed to answer could contain the exposed
// security group; publishing a partial percentage would fabricate a pass.
func normalizedNetwork(n NetworkMetrics) CloudPostureNetwork {
	out := CloudPostureNetwork{}
	if n.RegionsEvaluatedCount == 0 || len(n.RegionsFailed) > 0 {
		return out
	}
	out.SSHOpenToWorldPct = pctFloat(n.OpenToWorldSSH)
	out.RDPOpenToWorldPct = pctFloat(n.OpenToWorldRDP)
	return out
}

// normalizedBackup emits the retention minimum only when every requested
// region evaluated and at least one database exists; a minimum over zero
// databases would read as "no backups".
func normalizedBackup(rds RDSMetrics) CloudPostureBackup {
	out := CloudPostureBackup{}
	if rds.RegionsEvaluatedCount == 0 || len(rds.RegionsFailed) > 0 || rds.DatabaseCount == 0 {
		return out
	}
	out.RetentionDaysMin = rds.BackupRetentionMin
	return out
}

// normalizedVulnScanning emits the Inspector status only when it was
// evaluated. Evaluated with Enabled false is genuine evidence of absence.
func normalizedVulnScanning(ins InspectorStatus) CloudPostureVulnScanning {
	out := CloudPostureVulnScanning{}
	if !ins.StatusEvaluated {
		return out
	}
	out.Enabled = boolPtr(ins.Enabled)
	out.UnpatchedPct = pctFloat(ins.UnpatchedServerPercent)
	return out
}

func float64Ptr(v float64) *float64 { return &v }

// pctFloat carries a whole percentage into the normalized artifact, where a
// percentage over an empty population is left out.
func pctFloat(pct *int) *float64 {
	if pct == nil {
		return nil
	}
	return float64Ptr(float64(*pct))
}

func intPtr(v int) *int { return &v }
