// Package collector provides AWS account posture collection functionality.
package collector

import "time"

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
// A failed account appears as a stub entry: collection_error_code set, every
// metric group present but empty, so a consumer can distinguish "account
// healthy with no findings" from "account never answered".
type CloudPostureAccount struct {
	AccountID           string                   `json:"account_id,omitempty"`
	AccountLabel        string                   `json:"account_label,omitempty"`
	CollectionErrorCode string                   `json:"collection_error_code,omitempty"`
	IAM                 CloudPostureIAM          `json:"iam"`
	Storage             CloudPostureStorage      `json:"storage"`
	Logging             CloudPostureLogging      `json:"logging"`
	Network             CloudPostureNetwork      `json:"network"`
	Backup              CloudPostureBackup       `json:"backup"`
	VulnScanning        CloudPostureVulnScanning `json:"vuln_scanning"`
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
// status was unreadable" must not look the same.
type CloudPostureLogging struct {
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
	posture := &CloudPosture{
		SchemaVersion:    "1.0.0",
		CollectedAt:      time.Now().UTC().Format(time.RFC3339),
		Provider:         "aws",
		AccountsExpected: len(o.Accounts) + len(o.FailedAccounts),
		Accounts:         make([]CloudPostureAccount, 0, len(o.Accounts)+len(o.FailedAccounts)),
	}

	for _, acct := range o.Accounts {
		posture.Accounts = append(posture.Accounts, CloudPostureAccount{
			AccountID:    acct.AccountID,
			AccountLabel: acct.AccountLabel,
			IAM:          normalizedIAM(acct.IAM),
			Storage:      normalizedStorage(acct.S3),
			Logging:      normalizedLogging(acct.AccountSecurity.CloudTrail),
			Network:      normalizedNetwork(acct.Network),
			Backup:       normalizedBackup(acct.RDS),
			VulnScanning: normalizedVulnScanning(acct.AccountSecurity.Inspector),
		})
	}

	for _, failed := range o.FailedAccounts {
		posture.Accounts = append(posture.Accounts, CloudPostureAccount{
			AccountID:           failed.AccountID,
			AccountLabel:        failed.Label,
			CollectionErrorCode: failed.ErrorCode,
		})
	}

	return posture
}

// normalizedIAM projects IAM metrics into the normalized artifact, emitting
// only the metrics whose upstream source was actually evaluated.
func normalizedIAM(iam IAMMetrics) CloudPostureIAM {
	out := CloudPostureIAM{}
	if iam.CredentialReportEvaluated {
		out.MFACoveragePct = float64Ptr(float64(iam.MFAEnabled))
		out.AccessKeyRotationCompliantPct = float64Ptr(float64(iam.AccessKeysRotated))
	}
	if iam.RootCredentialStateEvaluated {
		out.RootMFAEnabled = boolPtr(iam.RootMFAEnabled)
		out.RootAccessProtected = boolPtr(iam.RootAccessProtected)
	}
	return out
}

// normalizedStorage emits the storage percentages only when their inputs were
// evaluated: encryption needs at least one bucket with a readable encryption
// config (or no buckets at all, the vacuous case), and public-access-blocked
// needs every bucket's effective state to be known, since unknowns otherwise
// drag the percentage toward failure.
func normalizedStorage(s3 S3Metrics) CloudPostureStorage {
	out := CloudPostureStorage{}
	if !s3.BucketListingEvaluated {
		return out
	}
	if s3.BucketCount == 0 || s3.DefaultEncryptionEvaluatedCount > 0 {
		out.EncryptionPct = float64Ptr(float64(s3.DefaultEncryptionEnabled))
	}
	if s3.PublicAccessBlockUnknownCount == 0 {
		out.PublicAccessBlockedPct = float64Ptr(float64(s3.PublicAccessBlocked))
	}
	return out
}

// normalizedLogging emits the CloudTrail booleans only when the trail listing
// was evaluated. True values are definite (a logging trail was observed);
// false values are emitted only when every trail status was readable.
func normalizedLogging(ct CloudTrailStatus) CloudPostureLogging {
	out := CloudPostureLogging{}
	if !ct.TrailListingEvaluated {
		return out
	}
	if ct.Enabled || ct.TrailStatusUnknownCount == 0 {
		out.CloudTrailEnabled = boolPtr(ct.Enabled)
	}
	if ct.MultiRegionEnabled || ct.TrailStatusUnknownCount == 0 {
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
	out.SSHOpenToWorldPct = float64Ptr(float64(n.OpenToWorldSSH))
	out.RDPOpenToWorldPct = float64Ptr(float64(n.OpenToWorldRDP))
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
	out.RetentionDaysMin = intPtr(rds.BackupRetentionMin)
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
	out.UnpatchedPct = float64Ptr(float64(ins.UnpatchedServerPercent))
	return out
}

func float64Ptr(v float64) *float64 { return &v }

func intPtr(v int) *int { return &v }
