// Package collector provides AWS account posture collection functionality.
package collector

import "time"

// Auth mode constants for AWS authentication strategy.
const (
	// AuthModeOIDC uses GitHub Actions OIDC to assume roles via AssumeRoleWithWebIdentity.
	// Each target role must trust the GitHub OIDC provider directly.
	AuthModeOIDC = "oidc"

	// AuthModeAssumeRole uses standard AssumeRole with optional external_id.
	// Requires bootstrap AWS credentials (e.g., from aws-actions/configure-aws-credentials).
	AuthModeAssumeRole = "assume_role"
)

// StatusFunc is called to report indeterminate status updates.
type StatusFunc func(message string)

// ProgressFunc is called to report determinate progress (current/total).
type ProgressFunc func(current, total int64, message string)

// Config holds the collector configuration passed via stdin.
type Config struct {
	AuthMode string          `json:"auth_mode"` // Authentication mode: "oidc" or "assume_role" (default: "assume_role")
	Accounts []AccountConfig `json:"accounts"`  // Accounts to collect from
	Regions  []string        `json:"regions"`   // Regions to scan (empty = all enabled)

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
	SchemaVersion    string           `json:"schema_version"`
	CollectedAt      string           `json:"collected_at"`
	CollectedAtLevel string           `json:"collected_at_level"`
	Accounts         []AccountPosture `json:"accounts"`
	Diagnostics      *Diagnostics     `json:"diagnostics,omitempty"`
}

// Diagnostics contains warnings and errors encountered during collection.
// This helps identify permission issues vs features that are genuinely disabled.
type Diagnostics struct {
	AccountErrors []string `json:"account_errors,omitempty"`
	Warnings      []string `json:"warnings,omitempty"`
}

// AccountPosture represents the collected security posture of a single AWS account.
type AccountPosture struct {
	AccountID       string                `json:"account_id"`
	AccountAlias    *string               `json:"account_alias,omitempty"`
	Regions         []string              `json:"regions"`
	IAM             IAMMetrics            `json:"iam"`
	S3              S3Metrics             `json:"s3"`
	RDS             RDSMetrics            `json:"rds"`
	Network         NetworkMetrics        `json:"network"`
	AccountSecurity AccountSecurity       `json:"account_security"`
	IdentityCenter  IdentityCenterStatus  `json:"identity_center"`
	Lambda          LambdaMetrics         `json:"lambda"`
	EC2             EC2Metrics            `json:"ec2"`
	CloudWatchLogs  CloudWatchLogsMetrics `json:"cloudwatch_logs"`
	KMS             KMSMetrics            `json:"kms"`
	SecretsManager  SecretsManagerMetrics `json:"secrets_manager"`
	SSMParameters   SSMParametersMetrics  `json:"ssm_parameters"`
}

// IAMMetrics contains IAM security posture.
//
// Trust-level fields are aggregates (percentages 0-100 and booleans). Audit-level
// fields surface per-user and per-role rows already derivable from the credential
// report and role-list calls. Internal-level fields add per-user temporal data
// (last login, key last used) drawn from the same credential report.
type IAMMetrics struct {
	// Trust:
	IAMUsersPresent    bool `json:"iam_users_present"`
	MFAEnabled         int  `json:"mfa_enabled"`
	HardwareMFAEnabled int  `json:"hardware_mfa_enabled"`
	AccessKeysRotated  int  `json:"access_keys_rotated"`

	RootMFAEnabled                 bool `json:"root_mfa_enabled"`
	RootCredentialsPresent         bool `json:"root_credentials_present"`
	RootPasswordPresent            bool `json:"root_password_present"`
	RootAccessKeysExist            bool `json:"root_access_keys_exist"`
	RootSigningCertificatesPresent bool `json:"root_signing_certificates_present"`
	RootAccessProtected            bool `json:"root_access_protected"`

	RootOrganizationsFeaturesEvaluated      bool   `json:"root_organizations_features_evaluated"`
	RootOrganizationID                      string `json:"root_organization_id,omitempty"`
	RootCredentialsManagementFeatureEnabled bool   `json:"root_credentials_management_feature_enabled"`
	RootSessionsFeatureEnabled              bool   `json:"root_sessions_feature_enabled"`
	RootOrganizationsFeaturesErrorCode      string `json:"root_organizations_features_error_code,omitempty"`

	// Audit: present (possibly []) when collected at audit+; null when not collected.
	Users []IAMUser `json:"users"`
	Roles []IAMRole `json:"roles"`

	// Internal: present (with possibly-empty Users) when collected at internal;
	// null when not collected.
	CredentialReport *IAMCredentialReport `json:"credential_report"`
}

// IAMCredentialReport is the internal-level per-user activity inventory derived
// from the IAM credential report (already fetched for the trust-level aggregates).
// Timestamps are emitted in RFC3339 UTC for stable cross-pack comparison.
type IAMCredentialReport struct {
	GeneratedAt string                    `json:"generated_at,omitempty"`
	Users       []IAMCredentialReportUser `json:"users"`
}

// IAMCredentialReportUser is a single user row from the credential report.
// Nil timestamps mean "never" (e.g., a key that has never been used, a password
// that has never been changed). The root account is reported with UserName
// "<root_account>" matching AWS's own naming.
type IAMCredentialReportUser struct {
	UserName                  string `json:"user_name"`
	UserCreationTime          string `json:"user_creation_time,omitempty"`
	PasswordEnabled           bool   `json:"password_enabled"`
	PasswordLastUsed          string `json:"password_last_used,omitempty"`
	PasswordLastChanged       string `json:"password_last_changed,omitempty"`
	PasswordNextRotation      string `json:"password_next_rotation,omitempty"`
	MFAActive                 bool   `json:"mfa_active"`
	AccessKey1Active          bool   `json:"access_key_1_active"`
	AccessKey1LastRotated     string `json:"access_key_1_last_rotated,omitempty"`
	AccessKey1LastUsedDate    string `json:"access_key_1_last_used_date,omitempty"`
	AccessKey1LastUsedRegion  string `json:"access_key_1_last_used_region,omitempty"`
	AccessKey1LastUsedService string `json:"access_key_1_last_used_service,omitempty"`
	AccessKey2Active          bool   `json:"access_key_2_active"`
	AccessKey2LastRotated     string `json:"access_key_2_last_rotated,omitempty"`
	AccessKey2LastUsedDate    string `json:"access_key_2_last_used_date,omitempty"`
	AccessKey2LastUsedRegion  string `json:"access_key_2_last_used_region,omitempty"`
	AccessKey2LastUsedService string `json:"access_key_2_last_used_service,omitempty"`
}

// IAMUser is a per-user audit-level inventory row.
// Timestamps (last login, key last used, etc.) live on CredentialReport at internal.
type IAMUser struct {
	UserName         string `json:"user_name"`
	ARN              string `json:"arn"`
	MFAActive        bool   `json:"mfa_active"`
	HasConsoleAccess bool   `json:"has_console_access"`
	HasAccessKeys    bool   `json:"has_access_keys"`
}

// IAMRole is a per-role audit-level inventory row.
// HasExternalTrust indicates the role's trust policy permits principals outside
// the current account (cross-account or wildcard principals).
type IAMRole struct {
	RoleName         string `json:"role_name"`
	ARN              string `json:"arn"`
	HasExternalTrust bool   `json:"has_external_trust"`
}

// S3Metrics contains S3 security posture.
// DefaultEncryptionEnabled includes AWS's SSE-S3 baseline for new objects.
//
// Trust-level fields are aggregates. Audit-level Buckets surfaces the per-bucket
// rows the percentages were computed from (no extra API calls; the collector
// already iterates buckets to derive the aggregates).
type S3Metrics struct {
	// Trust:
	PublicAccessBlocked             int  `json:"public_access_blocked"`
	DefaultEncryptionEnabled        int  `json:"default_encryption_enabled"`
	DefaultEncryptionEvaluatedCount int  `json:"default_encryption_evaluated_count"`
	DefaultEncryptionInferredCount  int  `json:"default_encryption_inferred_count"`
	DefaultEncryptionUnknownCount   int  `json:"default_encryption_unknown_count"`
	VersioningEnabled               int  `json:"versioning_enabled"`
	LoggingEnabled                  int  `json:"logging_enabled"`
	AccountPublicAccessBlockEnabled bool `json:"account_public_access_block_enabled"`

	// Audit: present (possibly []) when collected at audit+; null when not collected.
	Buckets []S3Bucket `json:"buckets"`
}

// S3Bucket is a per-bucket audit-level inventory row.
// Policy / ACL / Lifecycle are internal-only and omitted at audit.
type S3Bucket struct {
	// Audit:
	Name                       string `json:"name"`
	Region                     string `json:"region,omitempty"`
	PublicAccessBlocked        bool   `json:"public_access_blocked"`
	DefaultEncryptionEnabled   *bool  `json:"default_encryption_enabled"`
	DefaultEncryptionEvaluated bool   `json:"default_encryption_evaluated"`
	DefaultEncryptionErrorCode string `json:"default_encryption_error_code,omitempty"`
	VersioningEnabled          bool   `json:"versioning_enabled"`
	LoggingEnabled             bool   `json:"logging_enabled"`

	// Internal:
	Policy    *S3BucketPolicy    `json:"policy,omitempty"`
	ACL       *S3BucketACL       `json:"acl,omitempty"`
	Lifecycle *S3BucketLifecycle `json:"lifecycle,omitempty"`
}

// S3BucketPolicy carries the raw bucket policy document. Absent buckets (no
// policy attached) are represented as a nil pointer on S3Bucket, not as a
// present-but-empty policy.
type S3BucketPolicy struct {
	Document string `json:"document"`
}

// S3BucketACL is the per-bucket ACL summary. HasPublicGrant is true if any
// grant targets `AllUsers` or `AuthenticatedUsers` (the canonical "public"
// groups).
type S3BucketACL struct {
	OwnerID        string             `json:"owner_id,omitempty"`
	Grants         []S3BucketACLGrant `json:"grants,omitempty"`
	HasPublicGrant bool               `json:"has_public_grant"`
}

// S3BucketACLGrant is a single ACL grant entry. Either GranteeURI (for groups)
// or GranteeID (for canonical users) is set, not both.
type S3BucketACLGrant struct {
	GranteeType string `json:"grantee_type"`
	GranteeURI  string `json:"grantee_uri,omitempty"`
	GranteeID   string `json:"grantee_id,omitempty"`
	Permission  string `json:"permission"`
}

// S3BucketLifecycle is the per-bucket lifecycle configuration summary.
// Absent lifecycle configs are represented as a nil pointer on S3Bucket.
type S3BucketLifecycle struct {
	Rules []S3LifecycleRule `json:"rules"`
}

// S3LifecycleRule is one rule from a bucket's lifecycle configuration.
type S3LifecycleRule struct {
	ID          string   `json:"id,omitempty"`
	Status      string   `json:"status"`
	Prefix      string   `json:"prefix,omitempty"`
	Transitions []string `json:"transitions,omitempty"`
	Expiration  string   `json:"expiration,omitempty"`
}

// RDSMetrics contains RDS security posture.
//
// Trust-level fields are aggregates across regions. Audit-level Instances /
// Clusters surface the per-resource rows the percentages were computed from.
type RDSMetrics struct {
	// Trust:
	EncryptedAtRest         int `json:"encrypted_at_rest"`
	PubliclyAccessible      int `json:"publicly_accessible"`
	DeletionProtection      int `json:"deletion_protection"`
	BackupRetentionAdequate int `json:"backup_retention_adequate"` // % with retention >= 7 days
	BackupRetentionMin      int `json:"backup_retention_min"`      // Minimum retention days across all instances
	MultiAZEnabled          int `json:"multi_az_enabled"`

	// Audit: present (possibly []) when collected at audit+; null when not collected.
	Instances []RDSInstance `json:"instances"`
	Clusters  []RDSCluster  `json:"clusters"`
}

// RDSInstance is a per-instance audit-level inventory row.
// LatestRestorableTime is internal-only.
type RDSInstance struct {
	// Audit:
	Identifier            string `json:"identifier"`
	Region                string `json:"region"`
	Engine                string `json:"engine"`
	EngineVersion         string `json:"engine_version,omitempty"`
	StorageEncrypted      bool   `json:"storage_encrypted"`
	PubliclyAccessible    bool   `json:"publicly_accessible"`
	DeletionProtection    bool   `json:"deletion_protection"`
	BackupRetentionPeriod int    `json:"backup_retention_period"`
	MultiAZ               bool   `json:"multi_az"`

	// Internal:
	LatestRestorableTime string `json:"latest_restorable_time,omitempty"`
}

// RDSCluster is a per-cluster audit-level inventory row. Clusters are not
// publicly addressable as a unit (instances within are), so there is no
// PubliclyAccessible field here.
type RDSCluster struct {
	// Audit:
	Identifier            string `json:"identifier"`
	Region                string `json:"region"`
	Engine                string `json:"engine"`
	EngineVersion         string `json:"engine_version,omitempty"`
	StorageEncrypted      bool   `json:"storage_encrypted"`
	DeletionProtection    bool   `json:"deletion_protection"`
	BackupRetentionPeriod int    `json:"backup_retention_period"`
	MultiAZ               bool   `json:"multi_az"`

	// Internal:
	LatestRestorableTime string `json:"latest_restorable_time,omitempty"`
}

// NetworkMetrics contains network security posture.
//
// Trust-level fields are exposure aggregates across regions. Audit-level VPCs
// and SecurityGroups surface per-resource rows. Per-VPC flow log status and
// per-SG ingress rule detail are internal-level only.
type NetworkMetrics struct {
	// Trust:
	OpenToWorldSSH int `json:"open_to_world_ssh"`
	OpenToWorldRDP int `json:"open_to_world_rdp"`

	// Audit: present (possibly []) when collected at audit+; null when not collected.
	VPCs           []VPCSummary           `json:"vpcs"`
	SecurityGroups []SecurityGroupSummary `json:"security_groups"`
}

// VPCSummary is a per-VPC audit-level inventory row.
type VPCSummary struct {
	VPCID             string `json:"vpc_id"`
	Region            string `json:"region"`
	IsDefault         bool   `json:"is_default"`
	FlowLogsEnabled   *bool  `json:"flow_logs_enabled,omitempty"`
	FlowLogsEvaluated *bool  `json:"flow_logs_evaluated,omitempty"`
	FlowLogsErrorCode string `json:"flow_logs_error_code,omitempty"`
}

// SecurityGroupSummary is a per-SG audit-level inventory row. The OpenToWorld*
// booleans flag exposed ingress at audit; full ingress-rule detail (CIDRs,
// ports, protocols) lands on the internal-level IngressRules slice.
type SecurityGroupSummary struct {
	// Audit:
	GroupID        string `json:"group_id"`
	GroupName      string `json:"group_name,omitempty"`
	Region         string `json:"region"`
	VPCID          string `json:"vpc_id,omitempty"`
	IsDefault      bool   `json:"is_default"`
	OpenToWorldSSH bool   `json:"open_to_world_ssh"`
	OpenToWorldRDP bool   `json:"open_to_world_rdp"`

	// Internal:
	IngressRules []SGIngressRule `json:"ingress_rules,omitempty"`
}

// SGIngressRule is one ingress rule from a security group. Protocol "-1" means
// all protocols; FromPort 0 / ToPort 0 with protocol "-1" means all ports.
// CIDRBlocks may include both v4 and v6 (0.0.0.0/0 / ::/0 for world-open).
// SourceSGIDs lists other security groups granted ingress (common in default
// SGs and tier-to-tier rules). A rule with neither CIDRBlocks nor SourceSGIDs
// populated is degenerate.
type SGIngressRule struct {
	Protocol    string   `json:"protocol"`
	FromPort    int      `json:"from_port"`
	ToPort      int      `json:"to_port"`
	CIDRBlocks  []string `json:"cidr_blocks,omitempty"`
	SourceSGIDs []string `json:"source_sg_ids,omitempty"`
}

// AccountSecurity contains account-level security services status.
type AccountSecurity struct {
	CloudTrail  CloudTrailStatus  `json:"cloudtrail"`
	Config      ConfigStatus      `json:"config"`
	GuardDuty   GuardDutyStatus   `json:"guardduty"`
	SecurityHub SecurityHubStatus `json:"security_hub"`
	Inspector   InspectorStatus   `json:"inspector"`
}

// CloudTrailStatus contains CloudTrail configuration status.
//
// Trust fields are summary booleans across all trails. Audit-level Trails
// surfaces the per-trail rows the booleans were derived from; no extra API
// calls are needed.
type CloudTrailStatus struct {
	// Trust:
	Enabled                   bool `json:"enabled"`
	MultiRegionEnabled        bool `json:"multi_region_enabled"`
	OrganizationTrailEnabled  bool `json:"organization_trail_enabled"`
	TrailStatusEvaluatedCount int  `json:"trail_status_evaluated_count"`
	TrailStatusInferredCount  int  `json:"trail_status_inferred_count"`
	TrailStatusUnknownCount   int  `json:"trail_status_unknown_count"`

	// Audit: present (possibly []) when collected at audit+ and CloudTrail is
	// enabled; null when not collected or when DescribeTrails failed.
	Trails []CloudTrailTrail `json:"trails"`
}

// CloudTrailTrail is a per-trail audit-level inventory row.
// KMSEncrypted is the audit-level boolean; the internal-level KMSKeyARN exposes
// the actual key reference for forensic correlation against KMS policy / usage.
// CloudWatchLogsARN is internal-only for the same reason.
type CloudTrailTrail struct {
	// Audit:
	Name                     string `json:"name"`
	TrailARN                 string `json:"trail_arn,omitempty"`
	HomeRegion               string `json:"home_region,omitempty"`
	S3BucketName             string `json:"s3_bucket_name,omitempty"`
	IsMultiRegionTrail       bool   `json:"is_multi_region_trail"`
	IsOrganizationTrail      bool   `json:"is_organization_trail"`
	LogFileValidationEnabled bool   `json:"log_file_validation_enabled"`
	KMSEncrypted             bool   `json:"kms_encrypted"`
	CloudWatchLogsEnabled    bool   `json:"cloudwatch_logs_enabled"`
	IsLogging                bool   `json:"is_logging"`
	TrailStatusEvaluated     bool   `json:"trail_status_evaluated"`
	TrailStatusInferred      bool   `json:"trail_status_inferred,omitempty"`
	TrailStatusErrorCode     string `json:"trail_status_error_code,omitempty"`

	// Internal:
	KMSKeyARN         string `json:"kms_key_arn,omitempty"`
	CloudWatchLogsARN string `json:"cloudwatch_logs_arn,omitempty"`
}

// ConfigStatus contains AWS Config status.
//
// Trust fields summarize whether any recorder exists and is recording. Audit
// surfaces the per-region recorder list — useful to spot regions that have a
// recorder configured but stopped, or recorders that aren't capturing all
// resource types.
type ConfigStatus struct {
	// Trust:
	Enabled         bool `json:"enabled"`
	RecorderRunning bool `json:"recorder_running"`

	// Audit: present (possibly []) when collected at audit+ and Config is
	// enabled; null when not collected.
	Recorders []ConfigRecorderRow `json:"recorders"`

	// Internal: rule-by-rule compliance state. Lets a reviewer see which
	// specific managed or custom rules are firing without needing console
	// access. Truncated at ConfigRulesCap to keep artifact size bounded.
	// Present (possibly []) when collected at internal and Config is enabled;
	// null when not collected. Truncation companions emit at the same level.
	Rules             []ConfigRuleRow `json:"rules"`
	RulesTruncated    bool            `json:"rules_truncated"`
	RulesDroppedCount int             `json:"rules_dropped_count"`
}

// ConfigRecorderRow is a per-recorder audit-level row.
type ConfigRecorderRow struct {
	Name          string `json:"name"`
	Region        string `json:"region"`
	RoleARN       string `json:"role_arn,omitempty"`
	AllSupported  bool   `json:"all_supported"`
	IncludeGlobal bool   `json:"include_global"`
	Recording     bool   `json:"recording"`
}

// ConfigRuleRow is a per-rule internal-level row. ComplianceState is the
// AWS-side string (COMPLIANT / NON_COMPLIANT / INSUFFICIENT_DATA / NOT_APPLICABLE)
// passed through untyped so future states surface as-is.
type ConfigRuleRow struct {
	Name             string `json:"name"`
	Region           string `json:"region"`
	ARN              string `json:"arn,omitempty"`
	SourceOwner      string `json:"source_owner,omitempty"`
	SourceIdentifier string `json:"source_identifier,omitempty"`
	ComplianceState  string `json:"compliance_state,omitempty"`
	LastEvaluated    string `json:"last_evaluated,omitempty"`
}

// GuardDutyStatus contains GuardDuty status and high-severity finding counts.
//
// Trust fields summarize across regions. Audit surfaces per-region detector
// state — important because GuardDuty is regional and a single account can
// have it enabled in some regions but not others.
type GuardDutyStatus struct {
	// Trust:
	Enabled                         bool `json:"enabled"`
	UnremediatedFindingsOver48Hours int  `json:"unremediated_findings_over_48h"`

	// Audit: present (possibly []) when collected at audit+ and GuardDuty is
	// enabled in at least one region; null when not collected.
	Detectors []GuardDutyDetectorRow `json:"detectors"`

	// Internal: unarchived high-or-critical findings across all detectors,
	// suitable for breach-investigation triage. Sorted severity-desc then
	// updated-desc; truncated per-detector at GuardDutyFindingsCap. Present
	// (possibly []) when collected at internal; null when not collected.
	// Truncation companions emit at the same level.
	Findings             []GuardDutyFindingRow `json:"findings"`
	FindingsTruncated    bool                  `json:"findings_truncated"`
	FindingsDroppedCount int                   `json:"findings_dropped_count"`
}

// GuardDutyDetectorRow is a per-region GuardDuty detector audit-level row.
type GuardDutyDetectorRow struct {
	DetectorID                             string `json:"detector_id"`
	Region                                 string `json:"region"`
	Status                                 string `json:"status,omitempty"`
	FindingPublishingFreq                  string `json:"finding_publishing_freq,omitempty"`
	S3LogsEnabled                          bool   `json:"s3_logs_enabled"`
	EKSAuditLogsEnabled                    bool   `json:"eks_audit_logs_enabled"`
	MalwareScanEnabled                     bool   `json:"malware_scan_enabled"`
	HighOrCriticalFindings                 int    `json:"high_or_critical_findings"`
	HighOrCriticalFindingsOlderThan48Hours int    `json:"high_or_critical_findings_older_than_48h"`
}

// GuardDutyFindingRow is a per-finding internal-level row. Severity is the raw
// AWS 0.1-8.9 float; we don't bucket it here so future bucket changes don't
// require collector reissues.
type GuardDutyFindingRow struct {
	ID           string  `json:"id"`
	DetectorID   string  `json:"detector_id"`
	Region       string  `json:"region"`
	Severity     float64 `json:"severity"`
	Type         string  `json:"type,omitempty"`
	Title        string  `json:"title,omitempty"`
	ResourceType string  `json:"resource_type,omitempty"`
	ResourceID   string  `json:"resource_id,omitempty"`
	CreatedAt    string  `json:"created_at,omitempty"`
	UpdatedAt    string  `json:"updated_at,omitempty"`
}

// SecurityHubStatus contains Security Hub status and compliance metrics.
//
// Trust fields summarize CIS compliance. Audit surfaces the enabled-standards
// inventory + integration counts — useful to spot a SecurityHub install with
// no standards enabled (a common silent misconfiguration).
type SecurityHubStatus struct {
	// Trust:
	Enabled                                bool                 `json:"enabled"`
	CISAWSFoundationsBenchmarkLevel1       CISComplianceByLevel `json:"cis_aws_foundations_benchmark_level_1"`
	CISAWSFoundationsBenchmarkLevel2       CISComplianceByLevel `json:"cis_aws_foundations_benchmark_level_2"`
	CISAWSFoundationsBenchmarkUnknownLevel CISComplianceByLevel `json:"cis_aws_foundations_benchmark_unknown_level"`

	// Audit: arrays present (possibly []) when collected at audit+ and
	// SecurityHub is enabled; null when not collected. Scalars retain their
	// resource-conditional omitempty since false/0 has no meaning when
	// SecurityHub itself isn't enabled.
	AutoEnableControls   bool     `json:"auto_enable_controls,omitempty"`
	StandardsARNs        []string `json:"standards_arns"`
	IntegrationCount     int      `json:"integration_count,omitempty"`
	ProductSubscriptions []string `json:"product_subscriptions"`
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
//
// Trust fields summarize. Audit surfaces the raw finding-and-resource counts
// already computed by the SecurityHub-Inspector derivation, so consumers can
// distinguish "no findings" from "few unpatched resources out of many" without
// re-deriving from the percentage.
type InspectorStatus struct {
	// Trust:
	Enabled                bool `json:"enabled"`
	UnpatchedServerPercent int  `json:"unpatched_server_percent"`

	// Audit:
	TotalFindings          int `json:"total_findings,omitempty"`
	PatchedFindings        int `json:"patched_findings,omitempty"`
	UnpatchedFindings      int `json:"unpatched_findings,omitempty"`
	TotalAffectedResources int `json:"total_affected_resources,omitempty"`
	UnpatchedResources     int `json:"unpatched_resources,omitempty"`
}

// IdentityCenterStatus contains AWS IAM Identity Center (formerly AWS SSO)
// posture.
//
// Trust fields tell you whether IdC is enabled and how big it is. Audit
// surfaces per-permission-set rows (the unit of access an admin grants);
// internal adds per-user and per-group inventory plus the managed-policy ARNs
// attached to each permission set so a reviewer can answer "who can do what".
type IdentityCenterStatus struct {
	// Trust: resource-conditional sub-fields keep omitempty because their
	// absence means "the IdC resource itself doesn't exist" (Enabled=false),
	// not "wasn't collected at this level".
	Enabled            bool   `json:"enabled"`
	InstanceARN        string `json:"instance_arn,omitempty"`
	InstanceRegion     string `json:"instance_region,omitempty"`
	IdentityStoreID    string `json:"identity_store_id,omitempty"`
	UserCount          int    `json:"user_count,omitempty"`
	GroupCount         int    `json:"group_count,omitempty"`
	PermissionSetCount int    `json:"permission_set_count,omitempty"`

	// Audit: present (possibly []) when collected at audit+ and IdC is
	// enabled; null when not collected.
	PermissionSets []IdentityCenterPermissionSetRow `json:"permission_sets"`

	// Internal: present (possibly []) when collected at internal and IdC is
	// enabled; null when not collected.
	Users  []IdentityCenterUserRow  `json:"users"`
	Groups []IdentityCenterGroupRow `json:"groups"`
}

// IdentityCenterPermissionSetRow is a per-permission-set audit-level row.
// SessionDurationISO8601 is the raw "PT8H" style string AWS returns; ManagedPolicyARNs
// is empty at audit and populated at internal. HasInlinePolicy is presence-only
// (never the document) since inline policies may encode tenant-specific authz logic.
type IdentityCenterPermissionSetRow struct {
	Name                   string   `json:"name"`
	ARN                    string   `json:"arn"`
	Description            string   `json:"description,omitempty"`
	SessionDurationISO8601 string   `json:"session_duration_iso8601,omitempty"`
	ManagedPoliciesCount   int      `json:"managed_policies_count"`
	AccountsAssignedCount  int      `json:"accounts_assigned_count"`
	ManagedPolicyARNs      []string `json:"managed_policy_arns,omitempty"`
	HasInlinePolicy        bool     `json:"has_inline_policy,omitempty"`
}

// IdentityCenterUserRow is a per-user internal-level row from the identity
// store. PrimaryEmail is empty when no email is marked Primary on the user.
type IdentityCenterUserRow struct {
	UserID       string `json:"user_id"`
	UserName     string `json:"user_name"`
	DisplayName  string `json:"display_name,omitempty"`
	PrimaryEmail string `json:"primary_email,omitempty"`
}

// IdentityCenterGroupRow is a per-group internal-level row. MemberCount is
// the number of direct members (users + nested groups treated equally).
type IdentityCenterGroupRow struct {
	GroupID     string `json:"group_id"`
	DisplayName string `json:"display_name"`
	Description string `json:"description,omitempty"`
	MemberCount int    `json:"member_count"`
}

// LambdaMetrics contains Lambda posture across all collected regions.
//
// Trust-level aggregates summarize fleet shape and known risk signals
// (deprecated runtimes, publicly-invokable function URLs). Audit surfaces the
// per-function inventory the aggregates were computed from plus per-function
// resource-policy presence and function-URL auth type. Internal projects more
// fields from the same ListFunctions response (role / KMS / layers / env var
// KEYS) without additional API calls.
type LambdaMetrics struct {
	// Trust:
	FunctionCount          int `json:"function_count"`
	DeprecatedRuntimeCount int `json:"deprecated_runtime_count"`

	// Audit: array present (possibly []) when collected at audit+; null when
	// not collected. PublicFunctionURLCount is an audit-only enrichment
	// (requires per-function URL config calls). Truncation companions emit
	// at the same level.
	PublicFunctionURLCount int                 `json:"public_function_url_count,omitempty"`
	Functions              []LambdaFunctionRow `json:"functions"`
	FunctionsTruncated     bool                `json:"functions_truncated"`
	FunctionsDroppedCount  int                 `json:"functions_dropped_count"`
}

// LambdaFunctionRow is a per-function audit-level row. Internal-level fields
// (role/KMS/layers/env var KEYS/architectures/package_type) are populated from
// the same ListFunctions response when the collector is running at internal
// level — no additional API calls.
//
// EnvVarNames is environment variable KEYS only; values are dropped at the
// SDK boundary per aws.LambdaFunction's contract.
type LambdaFunctionRow struct {
	// Audit:
	Name                string `json:"name"`
	Region              string `json:"region"`
	Runtime             string `json:"runtime,omitempty"`
	LastModified        string `json:"last_modified,omitempty"`
	MemorySize          int    `json:"memory_size,omitempty"`
	Timeout             int    `json:"timeout,omitempty"`
	CodeSize            int64  `json:"code_size,omitempty"`
	HasVPCConfig        bool   `json:"has_vpc_config,omitempty"`
	HasResourcePolicy   bool   `json:"has_resource_policy,omitempty"`
	HasFunctionURL      bool   `json:"has_function_url,omitempty"`
	FunctionURLAuthType string `json:"function_url_auth_type,omitempty"`
	DeprecatedRuntime   bool   `json:"deprecated_runtime,omitempty"`

	// Internal:
	ARN           string   `json:"arn,omitempty"`
	RoleARN       string   `json:"role_arn,omitempty"`
	KMSKeyARN     string   `json:"kms_key_arn,omitempty"`
	LayerARNs     []string `json:"layer_arns,omitempty"`
	Architectures []string `json:"architectures,omitempty"`
	PackageType   string   `json:"package_type,omitempty"`
	DeadLetterARN string   `json:"dead_letter_arn,omitempty"`
	EnvVarNames   []string `json:"env_var_names,omitempty"`
}

// EC2Metrics contains EC2 posture across all collected regions.
//
// Trust aggregates count the fleet shape and the load-bearing risk signals
// (IMDSv2 enforcement, public IPs, default-VPC residency, unencrypted volumes).
// Audit surfaces per-instance rows the aggregates were computed from; internal
// adds tags, the IAM instance profile ARN, the SSH key name, and the full
// attached-volume list — fields that pair an instance with the identities and
// blast-radius surfaces that touch it.
type EC2Metrics struct {
	// Trust:
	InstanceCount                       int `json:"instance_count"`
	IMDSv2RequiredCount                 int `json:"imdsv2_required_count"`
	PublicIPCount                       int `json:"public_ip_count"`
	DefaultVPCCount                     int `json:"default_vpc_count"`
	InstancesWithUnencryptedVolumeCount int `json:"instances_with_unencrypted_volume_count"`

	// Audit: present (possibly []) when collected at audit+; null when not
	// collected. Truncation companions emit at the same level.
	Instances             []EC2InstanceRow `json:"instances"`
	InstancesTruncated    bool             `json:"instances_truncated"`
	InstancesDroppedCount int              `json:"instances_dropped_count"`
}

// EC2InstanceRow is a per-instance audit-level row. Internal-level fields
// (arn / iam_instance_profile_arn / key_name / tags / attached_volume_ids)
// are populated when level >= internal — extracted from the same
// DescribeInstances response with no additional API calls.
//
// RootVolumeEncrypted is best-effort: requires a separate DescribeVolumes call
// joined in the collector. Left zero (false) if the join fails.
type EC2InstanceRow struct {
	// Audit:
	InstanceID          string   `json:"instance_id"`
	Region              string   `json:"region"`
	InstanceType        string   `json:"instance_type,omitempty"`
	State               string   `json:"state,omitempty"`
	LaunchTime          string   `json:"launch_time,omitempty"`
	ImageID             string   `json:"image_id,omitempty"`
	VPCID               string   `json:"vpc_id,omitempty"`
	SubnetID            string   `json:"subnet_id,omitempty"`
	InDefaultVPC        bool     `json:"in_default_vpc,omitempty"`
	HasPublicIP         bool     `json:"has_public_ip,omitempty"`
	PublicIP            string   `json:"public_ip,omitempty"`
	HTTPTokens          string   `json:"imds_http_tokens,omitempty"`
	HTTPHopLimit        int      `json:"imds_http_hop_limit,omitempty"`
	SecurityGroupIDs    []string `json:"security_group_ids,omitempty"`
	RootVolumeEncrypted bool     `json:"root_volume_encrypted,omitempty"`

	// Internal:
	IAMInstanceProfileARN string            `json:"iam_instance_profile_arn,omitempty"`
	KeyName               string            `json:"key_name,omitempty"`
	Tags                  map[string]string `json:"tags,omitempty"`
	AttachedVolumeIDs     []string          `json:"attached_volume_ids,omitempty"`
}

// CloudWatchLogsMetrics contains CloudWatch Logs posture across all collected
// regions.
//
// Trust aggregates count the fleet and the two load-bearing posture signals:
// log groups without a retention policy (logs accumulate forever — cost and
// compliance smell) and log groups using AWS-managed encryption rather than a
// customer-managed KMS key. Audit surfaces per-group rows; internal adds the
// log-group ARN and the customer KMS key ARN (when set). No log content is
// ever collected.
type CloudWatchLogsMetrics struct {
	// Trust:
	LogGroupCount                    int `json:"log_group_count"`
	LogGroupsWithoutRetentionCount   int `json:"log_groups_without_retention_count"`
	LogGroupsWithoutCustomerKMSCount int `json:"log_groups_without_customer_kms_count"`

	// Audit: present (possibly []) when collected at audit+; null when not
	// collected. Truncation companions emit at the same level.
	LogGroups             []CloudWatchLogGroupRow `json:"log_groups"`
	LogGroupsTruncated    bool                    `json:"log_groups_truncated"`
	LogGroupsDroppedCount int                     `json:"log_groups_dropped_count"`
}

// CloudWatchLogGroupRow is a per-log-group audit-level row. Internal-level
// fields (ARN, kms_key_arn) come from the same DescribeLogGroups response —
// no additional API calls.
//
// RetentionInDays of 0 represents "Never expire" per the AWS API; the
// trust-level aggregate counts these specifically.
type CloudWatchLogGroupRow struct {
	// Audit:
	Name            string `json:"name"`
	Region          string `json:"region"`
	RetentionInDays int32  `json:"retention_in_days"`
	StoredBytes     int64  `json:"stored_bytes"`
	CreationTime    string `json:"creation_time,omitempty"`
	HasCustomerKMS  bool   `json:"has_customer_kms"`

	// Internal:
	ARN       string `json:"arn,omitempty"`
	KMSKeyARN string `json:"kms_key_arn,omitempty"`
}

// KMSMetrics contains KMS posture across all collected regions, scoped to
// CUSTOMER-managed keys only (AWS-managed keys offer no posture lever).
//
// Trust aggregates count the fleet and two load-bearing signals: symmetric
// CMKs without automatic rotation (compliance + key-compromise blast radius),
// and keys pending deletion (often unintentional). Audit surfaces per-key rows;
// internal adds the description string.
type KMSMetrics struct {
	// Trust:
	CustomerManagedKeyCount       int `json:"customer_managed_key_count"`
	CMKsWithRotationDisabledCount int `json:"cmks_with_rotation_disabled_count"`
	CMKsPendingDeletionCount      int `json:"cmks_pending_deletion_count"`

	// Audit: present (possibly []) when collected at audit+; null when not
	// collected. Truncation companions emit at the same level.
	Keys             []KMSKeyRow `json:"keys"`
	KeysTruncated    bool        `json:"keys_truncated"`
	KeysDroppedCount int         `json:"keys_dropped_count"`
}

// KMSKeyRow is a per-CMK audit-level row. Internal-level fields (Description)
// come from the same DescribeKey response — no additional API calls.
//
// RotationEnabled is only meaningful for symmetric_default keys; for other
// specs (asymmetric, HMAC) the field stays false because rotation doesn't
// apply, not because rotation is "off".
type KMSKeyRow struct {
	// Audit:
	KeyID           string   `json:"key_id"`
	Region          string   `json:"region"`
	ARN             string   `json:"arn"`
	KeyState        string   `json:"key_state,omitempty"`
	KeyUsage        string   `json:"key_usage,omitempty"`
	KeySpec         string   `json:"key_spec,omitempty"`
	Origin          string   `json:"origin,omitempty"`
	MultiRegion     bool     `json:"multi_region"`
	CreationDate    string   `json:"creation_date,omitempty"`
	DeletionDate    string   `json:"deletion_date,omitempty"`
	RotationEnabled bool     `json:"rotation_enabled"`
	Aliases         []string `json:"aliases,omitempty"`

	// Internal:
	Description string `json:"description,omitempty"`
}

// SecretsManagerMetrics contains Secrets Manager posture across all collected
// regions. Secret VALUES are never collected — only metadata.
//
// Trust aggregates count the fleet and three load-bearing posture signals:
// secrets without auto-rotation (compliance smell — secrets should rotate),
// secrets using AWS-managed encryption rather than a customer-managed KMS key,
// and secrets pending deletion (often unintentional). Audit surfaces per-secret
// rows; internal adds description, KMS ARN, rotation Lambda ARN, and tags.
type SecretsManagerMetrics struct {
	// Trust:
	SecretCount                    int `json:"secret_count"`
	SecretsWithoutRotationCount    int `json:"secrets_without_rotation_count"`
	SecretsWithoutCustomerKMSCount int `json:"secrets_without_customer_kms_count"`
	SecretsPendingDeletionCount    int `json:"secrets_pending_deletion_count"`

	// Audit: present (possibly []) when collected at audit+; null when not
	// collected. Truncation companions emit at the same level.
	Secrets             []SecretsManagerSecretRow `json:"secrets"`
	SecretsTruncated    bool                      `json:"secrets_truncated"`
	SecretsDroppedCount int                       `json:"secrets_dropped_count"`
}

// SecretsManagerSecretRow is a per-secret audit-level row. Internal-level
// fields (Description, KMSKeyARN, RotationLambdaARN, Tags) come from the same
// ListSecrets response — no additional API calls.
//
// Secret VALUES are never on this type. Description is borderline — customers
// sometimes embed sensitive context like "Stripe production API key for X" —
// so it's internal-level only.
type SecretsManagerSecretRow struct {
	// Audit:
	Name             string `json:"name"`
	Region           string `json:"region"`
	ARN              string `json:"arn"`
	CreatedDate      string `json:"created_date,omitempty"`
	LastChangedDate  string `json:"last_changed_date,omitempty"`
	LastAccessedDate string `json:"last_accessed_date,omitempty"`
	NextRotationDate string `json:"next_rotation_date,omitempty"`
	DeletionDate     string `json:"deletion_date,omitempty"`
	RotationEnabled  bool   `json:"rotation_enabled"`
	RotationDays     int64  `json:"rotation_days,omitempty"`
	HasCustomerKMS   bool   `json:"has_customer_kms"`
	PrimaryRegion    string `json:"primary_region,omitempty"`
	OwningService    string `json:"owning_service,omitempty"`

	// Internal:
	Description       string            `json:"description,omitempty"`
	KMSKeyARN         string            `json:"kms_key_arn,omitempty"`
	RotationLambdaARN string            `json:"rotation_lambda_arn,omitempty"`
	Tags              map[string]string `json:"tags,omitempty"`
}

// SSMParametersMetrics contains SSM Parameter Store posture across all
// collected regions. Parameter VALUES are never collected — only metadata.
//
// Trust aggregates count the fleet plus the security-relevant subset:
// SecureString parameters (encrypted, the ones holding sensitive material)
// and the subset of those using AWS-managed encryption rather than a
// customer-managed KMS key. String and StringList parameters are
// plaintext-at-rest and don't carry the same posture weight.
type SSMParametersMetrics struct {
	// Trust:
	ParameterCount                       int `json:"parameter_count"`
	SecureStringCount                    int `json:"secure_string_count"`
	SecureStringsWithoutCustomerKMSCount int `json:"secure_strings_without_customer_kms_count"`

	// Audit: present (possibly []) when collected at audit+; null when not
	// collected. Truncation companions emit at the same level.
	Parameters             []SSMParameterRow `json:"parameters"`
	ParametersTruncated    bool              `json:"parameters_truncated"`
	ParametersDroppedCount int               `json:"parameters_dropped_count"`
}

// SSMParameterRow is a per-parameter audit-level row. Internal-level fields
// (Description, KMSKeyARN) come from the same DescribeParameters response —
// no additional API calls.
//
// Description is borderline sensitive — customers occasionally embed context
// like "Stripe live key for X" — so it's gated to internal. HasCustomerKMS
// is only meaningful for SecureString; for String / StringList it stays false
// because encryption doesn't apply, not because customer KMS is missing.
type SSMParameterRow struct {
	// Audit:
	Name             string `json:"name"`
	Region           string `json:"region"`
	ARN              string `json:"arn"`
	Type             string `json:"type,omitempty"`
	DataType         string `json:"data_type,omitempty"`
	Version          int64  `json:"version,omitempty"`
	Tier             string `json:"tier,omitempty"`
	LastModifiedDate string `json:"last_modified_date,omitempty"`
	LastModifiedUser string `json:"last_modified_user,omitempty"`
	HasCustomerKMS   bool   `json:"has_customer_kms"`

	// Internal:
	Description string `json:"description,omitempty"`
	KMSKeyARN   string `json:"kms_key_arn,omitempty"`
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
