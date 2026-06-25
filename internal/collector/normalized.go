// Package collector provides AWS account posture collection functionality.
package collector

import "time"

// CloudPosture represents the normalized cloud infrastructure posture.
// This follows the evidencepack/cloud-posture@v1 schema specification.
// Fields are designed to be vendor-agnostic (works for AWS, GCP, Azure).
type CloudPosture struct {
	SchemaVersion string                `json:"schema_version"`
	CollectedAt   string                `json:"collected_at"`
	Provider      string                `json:"provider"`
	Accounts      []CloudPostureAccount `json:"accounts"`
}

// CloudPostureAccount contains normalized metrics for a single cloud account.
type CloudPostureAccount struct {
	AccountID    string                   `json:"account_id"`
	IAM          CloudPostureIAM          `json:"iam"`
	Storage      CloudPostureStorage      `json:"storage"`
	Logging      CloudPostureLogging      `json:"logging"`
	Network      CloudPostureNetwork      `json:"network"`
	Backup       CloudPostureBackup       `json:"backup"`
	VulnScanning CloudPostureVulnScanning `json:"vuln_scanning"`
}

// CloudPostureIAM contains normalized IAM metrics.
type CloudPostureIAM struct {
	MFACoveragePct                float64 `json:"mfa_coverage_pct"`
	RootMFAEnabled                bool    `json:"root_mfa_enabled"`
	RootAccessProtected           bool    `json:"root_access_protected"`
	AccessKeyRotationCompliantPct float64 `json:"access_key_rotation_compliant_pct"`
}

// CloudPostureStorage contains normalized storage security metrics.
type CloudPostureStorage struct {
	EncryptionPct          float64 `json:"encryption_pct"`
	PublicAccessBlockedPct float64 `json:"public_access_blocked_pct"`
}

// CloudPostureLogging contains normalized logging configuration.
type CloudPostureLogging struct {
	CloudTrailEnabled     bool `json:"cloudtrail_enabled"`
	CloudTrailMultiregion bool `json:"cloudtrail_multiregion"`
}

// CloudPostureNetwork contains normalized network security metrics.
type CloudPostureNetwork struct {
	SSHOpenToWorldPct float64 `json:"ssh_open_to_world_pct"`
	RDPOpenToWorldPct float64 `json:"rdp_open_to_world_pct"`
}

// CloudPostureBackup contains normalized backup configuration.
type CloudPostureBackup struct {
	RetentionDaysMin int `json:"retention_days_min"`
}

// CloudPostureVulnScanning contains normalized vulnerability scanning status.
type CloudPostureVulnScanning struct {
	Enabled      bool    `json:"enabled"`
	UnpatchedPct float64 `json:"unpatched_pct"`
}

// ToCloudPosture transforms detailed AWS output to normalized cloud-posture format.
func (o *Output) ToCloudPosture() *CloudPosture {
	posture := &CloudPosture{
		SchemaVersion: "1.0.0",
		CollectedAt:   time.Now().UTC().Format(time.RFC3339),
		Provider:      "aws",
		Accounts:      make([]CloudPostureAccount, 0, len(o.Accounts)),
	}

	for _, acct := range o.Accounts {
		normalized := CloudPostureAccount{
			AccountID: acct.AccountID,
			IAM: CloudPostureIAM{
				MFACoveragePct:                float64(acct.IAM.MFAEnabled),
				RootMFAEnabled:                acct.IAM.RootMFAEnabled,
				RootAccessProtected:           acct.IAM.RootAccessProtected,
				AccessKeyRotationCompliantPct: float64(acct.IAM.AccessKeysRotated),
			},
			Storage: CloudPostureStorage{
				EncryptionPct:          float64(acct.S3.DefaultEncryptionEnabled),
				PublicAccessBlockedPct: float64(acct.S3.PublicAccessBlocked),
			},
			Logging: CloudPostureLogging{
				CloudTrailEnabled:     acct.AccountSecurity.CloudTrail.Enabled,
				CloudTrailMultiregion: acct.AccountSecurity.CloudTrail.MultiRegionEnabled,
			},
			Network: CloudPostureNetwork{
				SSHOpenToWorldPct: float64(acct.Network.OpenToWorldSSH),
				RDPOpenToWorldPct: float64(acct.Network.OpenToWorldRDP),
			},
			Backup: CloudPostureBackup{
				RetentionDaysMin: acct.RDS.BackupRetentionMin,
			},
			VulnScanning: CloudPostureVulnScanning{
				Enabled:      acct.AccountSecurity.Inspector.Enabled,
				UnpatchedPct: float64(acct.AccountSecurity.Inspector.UnpatchedServerPercent),
			},
		}
		posture.Accounts = append(posture.Accounts, normalized)
	}

	return posture
}
