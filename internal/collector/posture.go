// Package collector provides AWS account posture collection functionality.
package collector

import "time"

// StatusFunc is called to report indeterminate status updates.
type StatusFunc func(message string)

// ProgressFunc is called to report determinate progress (current/total).
type ProgressFunc func(current, total int64, message string)

// Config holds the collector configuration passed via stdin.
type Config struct {
	Accounts []AccountConfig `json:"accounts"` // Accounts to collect from
	Regions  []string        `json:"regions"`  // Regions to scan (empty = all enabled)

	// Progress callbacks (optional, set by main to report status)
	OnStatus   StatusFunc   `json:"-"`
	OnProgress ProgressFunc `json:"-"`
}

// AccountConfig holds configuration for a single AWS account.
type AccountConfig struct {
	RoleARN    string `json:"role_arn"`    // IAM role to assume
	ExternalID string `json:"external_id"` // External ID for assume role (optional)
}

// Output represents the complete collector output.
type Output struct {
	SchemaVersion string           `json:"schema_version"`
	CollectedAt   string           `json:"collected_at"`
	Accounts      []AccountPosture `json:"accounts"`
}

// AccountPosture represents the collected security posture of a single AWS account.
type AccountPosture struct {
	AccountID       string          `json:"account_id"`
	AccountAlias    *string         `json:"account_alias,omitempty"`
	Regions         []string        `json:"regions"`
	IAM             IAMMetrics      `json:"iam"`
	S3              S3Metrics       `json:"s3"`
	RDS             RDSMetrics      `json:"rds"`
	Network         NetworkMetrics  `json:"network"`
	AccountSecurity AccountSecurity `json:"account_security"`
}

// IAMMetrics contains IAM security posture (percentages 0-100 and booleans only).
type IAMMetrics struct {
	IAMUsersPresent    bool `json:"iam_users_present"`
	MFAEnabled         int  `json:"mfa_enabled"`
	HardwareMFAEnabled int  `json:"hardware_mfa_enabled"`
	AccessKeysRotated  int  `json:"access_keys_rotated"`

	RootMFAEnabled      bool `json:"root_mfa_enabled"`
	RootAccessKeysExist bool `json:"root_access_keys_exist"`
}

// S3Metrics contains S3 security posture (percentages 0-100 and booleans only).
type S3Metrics struct {
	PublicAccessBlocked             int  `json:"public_access_blocked"`
	DefaultEncryptionEnabled        int  `json:"default_encryption_enabled"`
	VersioningEnabled               int  `json:"versioning_enabled"`
	LoggingEnabled                  int  `json:"logging_enabled"`
	AccountPublicAccessBlockEnabled bool `json:"account_public_access_block_enabled"`
}

// RDSMetrics contains RDS security posture (percentages 0-100 and booleans only).
type RDSMetrics struct {
	EncryptedAtRest         int `json:"encrypted_at_rest"`
	PubliclyAccessible      int `json:"publicly_accessible"`
	DeletionProtection      int `json:"deletion_protection"`
	BackupRetentionAdequate int `json:"backup_retention_adequate"` // % with retention >= 7 days
	MultiAZEnabled          int `json:"multi_az_enabled"`
}

// NetworkMetrics contains network security posture (percentages 0-100 only).
type NetworkMetrics struct {
	OpenToWorldSSH  int `json:"open_to_world_ssh"`
	OpenToWorldRDP  int `json:"open_to_world_rdp"`
	FlowLogsEnabled int `json:"flow_logs_enabled"`
}

// AccountSecurity contains account-level security services status.
type AccountSecurity struct {
	CloudTrail  CloudTrailStatus  `json:"cloudtrail"`
	Config      ConfigStatus      `json:"config"`
	GuardDuty   GuardDutyStatus   `json:"guardduty"`
	SecurityHub SecurityHubStatus `json:"security_hub"`
	Inspector   InspectorStatus   `json:"inspector"`
}

// CloudTrailStatus contains CloudTrail configuration status (booleans only).
type CloudTrailStatus struct {
	Enabled            bool `json:"enabled"`
	MultiRegionEnabled bool `json:"multi_region_enabled"`
}

// ConfigStatus contains AWS Config status (booleans only).
type ConfigStatus struct {
	Enabled         bool `json:"enabled"`
	RecorderRunning bool `json:"recorder_running"`
}

// GuardDutyStatus contains GuardDuty status and high-severity finding counts.
type GuardDutyStatus struct {
	Enabled                         bool `json:"enabled"`
	UnremediatedFindingsOver48Hours int  `json:"unremediated_findings_over_48h"`
}

// SecurityHubStatus contains Security Hub status and compliance metrics.
type SecurityHubStatus struct {
	Enabled                                bool                 `json:"enabled"`
	CISAWSFoundationsBenchmarkLevel1       CISComplianceByLevel `json:"cis_aws_foundations_benchmark_level_1"`
	CISAWSFoundationsBenchmarkLevel2       CISComplianceByLevel `json:"cis_aws_foundations_benchmark_level_2"`
	CISAWSFoundationsBenchmarkUnknownLevel CISComplianceByLevel `json:"cis_aws_foundations_benchmark_unknown_level"`
}

// CISComplianceByLevel contains compliance details for a CIS benchmark profile level.
type CISComplianceByLevel struct {
	Enabled              bool   `json:"enabled"`
	CompliancePercent    int    `json:"compliance_percent"`
	ComplianceState      string `json:"compliance_state"`
	PassedControls       int    `json:"passed_controls"`
	FailedControls       int    `json:"failed_controls"`
	WarningControls      int    `json:"warning_controls"`
	NotAvailableControls int    `json:"not_available_controls"`
}

// InspectorStatus contains Inspector vulnerability posture metrics.
type InspectorStatus struct {
	Enabled                bool `json:"enabled"`
	UnpatchedServerPercent int  `json:"unpatched_server_percent"`
}

// NewOutput creates a new Output with the current timestamp.
func NewOutput() *Output {
	return &Output{
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().UTC().Format(time.RFC3339),
		Accounts:      []AccountPosture{},
	}
}

// NewAccountPosture creates a new AccountPosture for the given account ID.
func NewAccountPosture(accountID string, regions []string) *AccountPosture {
	return &AccountPosture{
		AccountID: accountID,
		Regions:   regions,
	}
}
