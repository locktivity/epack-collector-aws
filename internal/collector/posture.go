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
	Label      string `json:"label"`       // Operator-supplied label (e.g. production, staging) carried into the artifacts (optional)
}

// Output represents the complete collector output.
type Output struct {
	SchemaVersion    string                `json:"schema_version"`
	CollectedAt      string                `json:"collected_at"`
	CollectedAtLevel string                `json:"collected_at_level"`
	Accounts         []AccountPosture      `json:"accounts"`
	FailedAccounts   []FailedAccountRecord `json:"failed_accounts,omitempty"`
	Diagnostics      *Diagnostics          `json:"diagnostics,omitempty"`
}

// FailedAccountRecord is a configured account whose collection failed
// entirely, so no AccountPosture exists for it. AccountID is parsed from the
// configured role ARN when derivable; ErrorCode is the upstream error code.
// Consumers use these to distinguish "N healthy accounts" from "N of M
// answered".
type FailedAccountRecord struct {
	AccountID string `json:"account_id,omitempty"`
	RoleARN   string `json:"role_arn,omitempty"`
	Label     string `json:"label,omitempty"`
	ErrorCode string `json:"error_code"`
}

// Diagnostics contains warnings and errors encountered during collection.
// This helps identify permission issues vs features that are genuinely disabled.
type Diagnostics struct {
	AccountErrors []string `json:"account_errors,omitempty"`
	Warnings      []string `json:"warnings,omitempty"`
}

// AccountPosture represents the collected security posture of a single AWS account.
// AccountLabel is the operator-supplied label from the account's config entry,
// passed through verbatim so downstream consumers can segment accounts
// (production, staging, management) without an external mapping.
type AccountPosture struct {
	AccountID       string                `json:"account_id"`
	AccountAlias    *string               `json:"account_alias,omitempty"`
	AccountLabel    string                `json:"account_label,omitempty"`
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
	Monitoring      MonitoringMetrics     `json:"monitoring"`
	StoredImages    StoredImageMetrics    `json:"stored_images"`
	LoadBalancers   LoadBalancerMetrics   `json:"load_balancers"`
	CloudFront      CloudFrontMetrics     `json:"cloudfront"`
	SES             SESMetrics            `json:"ses"`
	ECS             ECSMetrics            `json:"ecs"`
	AutoScaling     AutoScalingMetrics    `json:"auto_scaling"`
	WAF             WAFMetrics            `json:"waf"`
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
	// Trust: the user aggregates below are derived from the IAM credential
	// report and are meaningful only when credential_report_evaluated is true.
	// On collection failure they hold zero values (which would otherwise read
	// as worst-case posture) and credential_report_error_code carries the cause.
	CredentialReportEvaluated bool   `json:"credential_report_evaluated"`
	CredentialReportErrorCode string `json:"credential_report_error_code,omitempty"`

	// The account password policy governs IAM console passwords only, so it is
	// meaningful only where iam_users_present is true. Three states, kept
	// distinct because conflating any pair states something untrue:
	// evaluated=false means the call failed; evaluated=true with no policy
	// object means no policy is configured and AWS's own default applies (eight
	// characters, no complexity requirement, no expiry), which is a finding
	// rather than missing data; a policy object means it is configured.
	PasswordPolicyEvaluated bool               `json:"password_policy_evaluated"`
	PasswordPolicyErrorCode string             `json:"password_policy_error_code,omitempty"`
	PasswordPolicy          *IAMPasswordPolicy `json:"password_policy,omitempty"`

	IAMUsersPresent    bool `json:"iam_users_present"`
	MFAEnabled         int  `json:"mfa_enabled"`
	HardwareMFAEnabled int  `json:"hardware_mfa_enabled"`
	AccessKeysRotated  int  `json:"access_keys_rotated"`

	// Root credential state comes from the credential report's root row or the
	// account summary; the Root* fields below are meaningful only when
	// root_credential_state_evaluated is true (i.e., at least one source
	// succeeded).
	RootCredentialStateEvaluated bool `json:"root_credential_state_evaluated"`

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

	// Audit: the per-role external_trust_in_org determinations are meaningful
	// only when organization_accounts_evaluated is true. Expected failures
	// (member accounts without Organizations visibility) record the error code
	// without a warning.
	OrganizationAccountsEvaluated bool   `json:"organization_accounts_evaluated"`
	OrganizationAccountsErrorCode string `json:"organization_accounts_error_code,omitempty"`

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
//
// HasExternalTrust indicates the role's trust policy permits principals
// outside the current account (cross-account or wildcard principals).
// ExternalTrustAccountIDs lists the foreign account IDs found as principals;
// HasWildcardPrincipal separately flags a wildcard principal, which is not
// account-scoped. ExternalTrustInOrg is a three-state determination: true
// when every foreign account is a member of the same AWS Organization, false
// when at least one is not, absent when membership could not be determined
// (no Organizations visibility, or the external trust is wildcard-only).
// TrustPolicyJSON carries the decoded trust policy document at internal only.
type IAMRole struct {
	RoleName                string   `json:"role_name"`
	ARN                     string   `json:"arn"`
	HasExternalTrust        bool     `json:"has_external_trust"`
	HasWildcardPrincipal    bool     `json:"has_wildcard_principal"`
	ExternalTrustAccountIDs []string `json:"external_trust_account_ids,omitempty"`
	ExternalTrustInOrg      *bool    `json:"external_trust_in_org,omitempty"`

	// Internal:
	TrustPolicyJSON string `json:"trust_policy_json,omitempty"`
}

// S3Metrics contains S3 security posture.
// DefaultEncryptionEnabled includes AWS's SSE-S3 baseline for new objects.
//
// Trust-level fields are aggregates. Audit-level Buckets surfaces the per-bucket
// rows the percentages were computed from (no extra API calls; the collector
// already iterates buckets to derive the aggregates).
type S3Metrics struct {
	// Trust: the bucket aggregates below are derived from the bucket listing
	// and are meaningful only when bucket_listing_evaluated is true. On listing
	// failure they hold zero values (which would otherwise read as worst-case
	// posture) and bucket_listing_error_code carries the cause.
	BucketListingEvaluated bool   `json:"bucket_listing_evaluated"`
	BucketListingErrorCode string `json:"bucket_listing_error_code,omitempty"`

	// AccountPublicAccessBlockEnabled is meaningful only when
	// account_public_access_block_evaluated is true.
	AccountPublicAccessBlockEvaluated bool `json:"account_public_access_block_evaluated"`

	BucketCount int `json:"bucket_count"`

	// Transport enforcement at the bucket layer. S3 endpoints answer HTTP and
	// HTTPS alike, so only a policy deny on aws:SecureTransport forces TLS.
	// Unenforced is determinate (nothing in the policy addresses transport);
	// partial means a transport statement exists but does not conclusively
	// cover every principal, action, and resource; unknown means the policy
	// could not be read and must never be reported as unenforced.
	TLSEnforcedBucketCount           int  `json:"tls_enforced_bucket_count"`
	TLSEnforcementPartialBucketCount int  `json:"tls_enforcement_partial_bucket_count"`
	TLSUnenforcedBucketCount         int  `json:"tls_unenforced_bucket_count"`
	TLSEnforcementUnknownBucketCount int  `json:"tls_enforcement_unknown_bucket_count,omitempty"`
	PublicAccessBlocked              int  `json:"public_access_blocked"`
	PublicAccessBlockUnknownCount    int  `json:"public_access_block_unknown_count"`
	DefaultEncryptionEnabled         int  `json:"default_encryption_enabled"`
	DefaultEncryptionEvaluatedCount  int  `json:"default_encryption_evaluated_count"`
	DefaultEncryptionInferredCount   int  `json:"default_encryption_inferred_count"`
	DefaultEncryptionUnknownCount    int  `json:"default_encryption_unknown_count"`
	VersioningEnabled                int  `json:"versioning_enabled"`
	LoggingEnabled                   int  `json:"logging_enabled"`
	LogSinkBucketCount               int  `json:"log_sink_bucket_count"`
	AccountPublicAccessBlockEnabled  bool `json:"account_public_access_block_enabled"`

	// Audit: present (possibly []) when collected at audit+; null when not collected.
	Buckets []S3Bucket `json:"buckets"`
}

// S3Bucket is a per-bucket audit-level inventory row.
// Policy / ACL / Lifecycle are internal-only and omitted at audit.
type S3Bucket struct {
	// Audit:
	Name                       string `json:"name"`
	TLSEnforcement             string `json:"tls_enforcement,omitempty"`
	Region                     string `json:"region,omitempty"`
	PublicAccessBlocked        bool   `json:"public_access_blocked"`
	DefaultEncryptionEnabled   *bool  `json:"default_encryption_enabled"`
	DefaultEncryptionEvaluated bool   `json:"default_encryption_evaluated"`
	DefaultEncryptionErrorCode string `json:"default_encryption_error_code,omitempty"`
	VersioningEnabled          bool   `json:"versioning_enabled"`
	LoggingEnabled             bool   `json:"logging_enabled"`
	IsLogSink                  bool   `json:"is_log_sink,omitempty"`

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
	// Trust: the aggregates cover only regions that evaluated successfully.
	// They are meaningful only when regions_failed is empty. DatabaseCount is
	// the instance + cluster total, so a consumer can tell vacuous aggregates
	// (zero databases) from real ones.
	RegionsEvaluatedCount int      `json:"regions_evaluated_count"`
	RegionsFailed         []string `json:"regions_failed,omitempty"`

	// Backup-failure alerting: the chain is a subscription enabled and
	// covering backup failures, delivering to a topic with a confirmed
	// subscriber. Empty event categories cover everything, so the covering
	// count includes subscribe-to-all subscriptions.
	EventSubscriptionCount                       int `json:"event_subscription_count"`
	BackupFailureAlertingSubscriptionCount       int `json:"backup_failure_alerting_subscription_count"`
	BackupFailureAlertingReachingSubscriberCount int `json:"backup_failure_alerting_reaching_subscriber_count"`
	BackupAlertingTopicsUnresolvedCount          int `json:"backup_alerting_topics_unresolved_count,omitempty"`
	EventSubscriptionsUnresolvedRegionCount      int `json:"event_subscriptions_unresolved_region_count,omitempty"`

	// Data-change logging classification across postgres instances.
	DMLLoggingConfiguredCount    int `json:"dml_logging_configured_count"`
	DMLLoggingNotExportedCount   int `json:"dml_logging_not_exported_count"`
	DMLLoggingPendingCount       int `json:"dml_logging_pending_count"`
	DMLLoggingNotConfiguredCount int `json:"dml_logging_not_configured_count"`
	DMLLoggingUnknownCount       int `json:"dml_logging_unknown_count,omitempty"`
	DMLLoggingNotClassifiedCount int `json:"dml_logging_not_classified_count"`
	DatabaseCount                int `json:"database_count"`

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
	PreferredBackupWindow string `json:"preferred_backup_window,omitempty"`
	MultiAZ               bool   `json:"multi_az"`
	DMLLogging            string `json:"dml_logging,omitempty"`

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
	// Trust: the exposure aggregates cover only regions that evaluated
	// successfully. They are meaningful only when regions_failed is empty,
	// since partial coverage can only understate exposure.
	RegionsEvaluatedCount int      `json:"regions_evaluated_count"`
	RegionsFailed         []string `json:"regions_failed,omitempty"`

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
	CloudTrail     CloudTrailStatus     `json:"cloudtrail"`
	Config         ConfigStatus         `json:"config"`
	GuardDuty      GuardDutyStatus      `json:"guardduty"`
	AccessAnalyzer AccessAnalyzerStatus `json:"access_analyzer"`
	SecurityHub    SecurityHubStatus    `json:"security_hub"`
	Inspector      InspectorStatus      `json:"inspector"`
}

// CloudTrailStatus contains CloudTrail configuration status.
//
// Trust fields are summary booleans across all trails. Audit-level Trails
// surfaces the per-trail rows the booleans were derived from; no extra API
// calls are needed.
type CloudTrailStatus struct {
	// Retention of the trail delivery buckets themselves: the S3 side of
	// CloudTrail retention. Not-in-account is the normal shape for
	// organization trails delivering to a log archive account.
	TrailBucketsRetainedIndefinitelyCount int   `json:"trail_buckets_retained_indefinitely_count"`
	TrailBucketsExpiringCount             int   `json:"trail_buckets_expiring_count"`
	TrailBucketMinExpirationDays          int32 `json:"trail_bucket_min_expiration_days,omitempty"`
	TrailBucketsNotInAccountCount         int   `json:"trail_buckets_not_in_account_count"`
	TrailBucketsRetentionUnknownCount     int   `json:"trail_buckets_retention_unknown_count,omitempty"`
	TrailBucketsObjectLockedCount         int   `json:"trail_buckets_object_locked_count"`

	// Public access on the delivery buckets. A trail bucket has no legitimate
	// public readership, so not-blocked here is an unambiguous finding.
	TrailBucketsPublicAccessBlockedCount    int `json:"trail_buckets_public_access_blocked_count"`
	TrailBucketsPublicAccessNotBlockedCount int `json:"trail_buckets_public_access_not_blocked_count"`
	TrailBucketsPublicAccessUnknownCount    int `json:"trail_buckets_public_access_unknown_count,omitempty"`

	// Trust: the summary booleans below are derived from the trail listing and
	// are meaningful only when trail_listing_evaluated is true. On listing
	// failure they hold zero values (which would otherwise read as worst-case
	// posture) and trail_listing_error_code carries the cause.
	TrailListingEvaluated bool   `json:"trail_listing_evaluated"`
	TrailListingErrorCode string `json:"trail_listing_error_code,omitempty"`

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
	S3KeyPrefix              string `json:"s3_key_prefix,omitempty"`
	BucketRetention          string `json:"bucket_retention,omitempty"`
	BucketExpirationDays     int32  `json:"bucket_expiration_days,omitempty"`
	BucketObjectLockMode     string `json:"bucket_object_lock_mode,omitempty"`
	BucketPublicAccess       string `json:"bucket_public_access,omitempty"`
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

// AccessAnalyzerStatus contains IAM Access Analyzer coverage: whether
// unintended external access is being analyzed, region by region. In an
// organization the analyzer often lives in a delegated administrator account,
// so an absence here is not an absence of coverage.
type AccessAnalyzerStatus struct {
	// Trust:
	Enabled                        bool `json:"enabled"`
	AnalyzerCount                  int  `json:"analyzer_count"`
	RegionsEvaluatedCount          int  `json:"regions_evaluated_count"`
	RegionsWithActiveAnalyzerCount int  `json:"regions_with_active_analyzer_count"`
	RegionsUnresolvedCount         int  `json:"regions_unresolved_count,omitempty"`

	// An analyzer that is creating, disabled, or failed analyzes nothing:
	// configuration present, coverage absent.
	InactiveAnalyzerCount       int  `json:"inactive_analyzer_count"`
	OrganizationAnalyzerPresent bool `json:"organization_analyzer_present"`

	// Findings split by triage state. Archived findings mean someone looks;
	// stale active ones mean nobody does. Unresolved analyzers are excluded
	// from both counts rather than counted as zero.
	ActiveFindingsCount                  int `json:"active_findings_count"`
	ArchivedFindingsCount                int `json:"archived_findings_count"`
	AnalyzersWithUnresolvedFindingsCount int `json:"analyzers_with_unresolved_findings_count,omitempty"`

	// Audit:
	Analyzers []AccessAnalyzerRow `json:"analyzers,omitempty"`
}

// AccessAnalyzerRow is an audit-level analyzer inventory row.
type AccessAnalyzerRow struct {
	Name                  string `json:"name"`
	Region                string `json:"region"`
	Type                  string `json:"type"`
	Status                string `json:"status"`
	ActiveFindingsCount   int    `json:"active_findings_count"`
	ArchivedFindingsCount int    `json:"archived_findings_count"`
	FindingsUnresolved    bool   `json:"findings_unresolved,omitempty"`
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
	// Trust: Enabled and UnpatchedServerPercent are meaningful only when
	// status_evaluated is true. On collection failure they hold zero values
	// and status_error_code carries the cause. Evaluated true with Enabled
	// false means Inspector was genuinely observed as not enabled.
	StatusEvaluated bool   `json:"status_evaluated"`
	StatusErrorCode string `json:"status_error_code,omitempty"`

	Enabled                bool `json:"enabled"`
	UnpatchedServerPercent int  `json:"unpatched_server_percent"`

	// Audit:
	TotalFindings          int `json:"total_findings,omitempty"`
	PatchedFindings        int `json:"patched_findings,omitempty"`
	UnpatchedFindings      int `json:"unpatched_findings,omitempty"`
	TotalAffectedResources int `json:"total_affected_resources,omitempty"`
	UnpatchedResources     int `json:"unpatched_resources,omitempty"`
}

// AutoScalingMetrics covers EC2 auto scaling groups: the instance-based
// sibling of the ECS capacity evidence.
type AutoScalingMetrics struct {
	GroupCount int `json:"group_count"`

	// A minimum of one instance is zero redundancy. Sometimes deliberate: the
	// bastion pattern uses a single-instance group for self-healing rather
	// than capacity, so read this against what each group is for.
	SingleInstanceGroupCount int `json:"single_instance_group_count"`
	SingleZoneGroupCount     int `json:"single_zone_group_count"`

	// A group with no policy holds capacity but only changes it when told to.
	GroupsWithScalingPolicyCount int `json:"groups_with_scaling_policy_count"`
	// Suspended scaling processes mean the configuration is present but
	// inert, which reads as scaled while acting as fixed.
	GroupsWithSuspendedProcessesCount int `json:"groups_with_suspended_processes_count"`

	GroupsWithELBHealthCheckCount int `json:"groups_with_elb_health_check_count"`
	// Load-balanced groups still on EC2-only health checks: the target group
	// stops routing to a hung application, but the instance is never replaced
	// because the VM reports healthy. Detection without response.
	LoadBalancedGroupsWithoutELBHealthCheckCount int `json:"load_balanced_groups_without_elb_health_check_count"`
	GroupsOnLaunchConfigurationsCount            int `json:"groups_on_launch_configurations_count"`

	Groups []AutoScalingGroupRow `json:"groups,omitempty"`
}

// AutoScalingGroupRow is an audit-level group inventory row.
type AutoScalingGroupRow struct {
	Name                          string `json:"name"`
	Region                        string `json:"region"`
	MinSize                       int32  `json:"min_size"`
	MaxSize                       int32  `json:"max_size"`
	DesiredCapacity               int32  `json:"desired_capacity"`
	AvailabilityZoneCount         int    `json:"availability_zone_count"`
	HealthCheckType               string `json:"health_check_type,omitempty"`
	HealthCheckGracePeriodSeconds int32  `json:"health_check_grace_period_seconds,omitempty"`
	UsesLaunchTemplate            bool   `json:"uses_launch_template"`
	LoadBalanced                  bool   `json:"load_balanced"`
	SuspendedProcessCount         int    `json:"suspended_process_count,omitempty"`
	PolicyCount                   int    `json:"policy_count"`
}

// ECSMetrics covers container service capacity: how services scale and how
// deployments fail safe. Task definitions are never read, because container
// definitions embed environment variables that routinely hold credentials.
type ECSMetrics struct {
	ClusterCount        int `json:"cluster_count"`
	ServiceCount        int `json:"service_count"`
	FargateServiceCount int `json:"fargate_service_count"`

	// Autoscaling counts a registered capacity range; the scaling-policy count
	// requires the chain complete: bounds registered and a policy that moves
	// the service between them.
	ServicesWithAutoscalingCount   int `json:"services_with_autoscaling_count"`
	ServicesWithScalingPolicyCount int `json:"services_with_scaling_policy_count"`

	// A capacity floor of one task: no redundancy. The floor is the scaling
	// minimum where registered, otherwise the desired count.
	SingleTaskServiceCount int `json:"single_task_service_count"`

	ServicesWithCircuitBreakerCount int `json:"services_with_circuit_breaker_count"`
	ServicesWithPublicIPCount       int `json:"services_with_public_ip_count"`
	LoadBalancedServiceCount        int `json:"load_balanced_service_count"`

	// Services whose scaling state could not be read. They are excluded from
	// the autoscaling and single-task findings rather than counted unscaled.
	ScalingUnresolvedServiceCount int `json:"scaling_unresolved_service_count,omitempty"`

	Services []ECSServiceRow `json:"services,omitempty"`
}

// ECSServiceRow is an audit-level service inventory row.
type ECSServiceRow struct {
	Cluster                       string   `json:"cluster"`
	Name                          string   `json:"name"`
	Region                        string   `json:"region"`
	LaunchType                    string   `json:"launch_type,omitempty"`
	DesiredCount                  int32    `json:"desired_count"`
	RunningCount                  int32    `json:"running_count"`
	AutoScaled                    bool     `json:"auto_scaled"`
	MinCapacity                   int32    `json:"min_capacity,omitempty"`
	MaxCapacity                   int32    `json:"max_capacity,omitempty"`
	ScalingPolicyTypes            []string `json:"scaling_policy_types,omitempty"`
	ScalingMetrics                []string `json:"scaling_metrics,omitempty"`
	CircuitBreakerEnabled         bool     `json:"circuit_breaker_enabled"`
	CircuitBreakerRollback        bool     `json:"circuit_breaker_rollback"`
	MinimumHealthyPercent         int32    `json:"minimum_healthy_percent,omitempty"`
	MaximumPercent                int32    `json:"maximum_percent,omitempty"`
	AssignsPublicIP               bool     `json:"assigns_public_ip"`
	SubnetCount                   int      `json:"subnet_count,omitempty"`
	LoadBalanced                  bool     `json:"load_balanced"`
	HealthCheckGracePeriodSeconds int32    `json:"health_check_grace_period_seconds,omitempty"`
	ScalingUnresolved             bool     `json:"scaling_unresolved,omitempty"`
}

// SESMetrics covers outbound mail transport enforcement. SES attempts TLS on
// every delivery and falls back to plaintext unless a configuration set says
// REQUIRE, so only REQUIRE counts as enforced here.
type SESMetrics struct {
	ConfigurationSetCount                  int `json:"configuration_set_count"`
	ConfigurationSetsRequiringTLSCount     int `json:"configuration_sets_requiring_tls_count"`
	ConfigurationSetsOpportunisticTLSCount int `json:"configuration_sets_opportunistic_tls_count"`
	ConfigurationSetsUnresolvedCount       int `json:"configuration_sets_unresolved_count,omitempty"`

	IdentityCount int `json:"identity_count"`
	// Identities whose default configuration set requires TLS, so mail that
	// names no set at send time is covered. A send that names its own set can
	// still override this; that choice is per message and not visible in
	// config.
	IdentitiesRequiringTLSCount  int `json:"identities_requiring_tls_count"`
	SendingDisabledIdentityCount int `json:"sending_disabled_identity_count"`
	IdentitiesUnresolvedCount    int `json:"identities_unresolved_count,omitempty"`

	ConfigurationSets []SESConfigurationSetRow `json:"configuration_sets,omitempty"`
	Identities        []SESIdentityRow         `json:"identities,omitempty"`
}

// SESConfigurationSetRow is an audit-level configuration set row.
type SESConfigurationSetRow struct {
	Name       string `json:"name"`
	Region     string `json:"region"`
	TLSPolicy  string `json:"tls_policy,omitempty"`
	Unresolved bool   `json:"unresolved,omitempty"`
}

// SESIdentityRow is an audit-level sending identity row.
type SESIdentityRow struct {
	Name                    string `json:"name"`
	Region                  string `json:"region"`
	Type                    string `json:"type"`
	SendingEnabled          bool   `json:"sending_enabled"`
	DefaultConfigurationSet string `json:"default_configuration_set,omitempty"`
	DefaultRequiresTLS      bool   `json:"default_requires_tls"`
	Unresolved              bool   `json:"unresolved,omitempty"`
}

// WAFMetrics covers WAFv2 coverage of the account's internet-facing entry
// points: which application load balancers and CloudFront distributions have
// a web ACL attached, and whether an attached web ACL enforces request-rate
// limiting.
type WAFMetrics struct {
	WebACLCount int `json:"web_acl_count"`

	// RegionsEvaluatedCount is how many regions answered the REGIONAL-scope
	// scan; CloudFrontScopeEvaluated is the same signal for the global scope.
	// The coverage readings only cover the scopes that answered.
	RegionsEvaluatedCount    int  `json:"regions_evaluated_count"`
	CloudFrontScopeEvaluated bool `json:"cloudfront_scope_evaluated"`

	// Coverage pairs: the denominator plus the share, so an empty fleet's 0%
	// is legible. Exact protected counts live on the audit rows.
	InternetFacingALBCount       int `json:"internet_facing_alb_count"`
	InternetFacingALBCoveragePct int `json:"internet_facing_alb_coverage_pct"`

	EnabledDistributionCount int `json:"enabled_distribution_count"`
	DistributionCoveragePct  int `json:"distribution_coverage_pct"`

	// RateLimitingEnforced is true when at least one web ACL with an attached
	// resource carries an active rate-based rule whose action is block.
	RateLimitingEnforced bool `json:"rate_limiting_enforced"`

	WebACLs             []WebACLRow `json:"web_acls,omitempty"`
	WebACLsTruncated    bool        `json:"web_acls_truncated"`
	WebACLsDroppedCount int         `json:"web_acls_dropped_count"`
}

// WebACLRow is an audit-level web ACL inventory row. Arn, associated resource
// ARNs, and the logging destination appear at internal level only.
type WebACLRow struct {
	Name                    string       `json:"name"`
	Scope                   string       `json:"scope"`
	Region                  string       `json:"region,omitempty"`
	DefaultAction           string       `json:"default_action"`
	AssociatedResourceCount int          `json:"associated_resource_count"`
	LoggingEvaluated        bool         `json:"logging_evaluated"`
	LoggingEnabled          bool         `json:"logging_enabled"`
	Rules                   []WAFRuleRow `json:"rules"`

	Arn                    string   `json:"arn,omitempty"`
	AssociatedResourceArns []string `json:"associated_resource_arns,omitempty"`
	LoggingDestinationArn  string   `json:"logging_destination_arn,omitempty"`
}

// WAFRuleRow is one rule's enforcement posture within a web ACL.
type WAFRuleRow struct {
	Name                 string `json:"name"`
	Priority             int32  `json:"priority"`
	Action               string `json:"action"`
	RateBased            bool   `json:"rate_based,omitempty"`
	RateLimit            int64  `json:"rate_limit,omitempty"`
	AggregateKeyType     string `json:"aggregate_key_type,omitempty"`
	ManagedRuleGroupName string `json:"managed_rule_group_name,omitempty"`
}

// CloudFrontMetrics covers distribution transport enforcement on both hops:
// viewer to edge, and edge to origin. Meaningful only when
// distributions_evaluated is true; on failure the error code carries the cause
// so an unread account is never mistaken for one with no distributions.
type CloudFrontMetrics struct {
	DistributionsEvaluated bool   `json:"distributions_evaluated"`
	DistributionsErrorCode string `json:"distributions_error_code,omitempty"`

	DistributionCount         int `json:"distribution_count"`
	DisabledDistributionCount int `json:"disabled_distribution_count"`

	// Findings cover enabled distributions only. A distribution allows
	// plaintext viewers when any cache behavior, default or path-scoped, is
	// set to allow-all.
	DistributionsAllowingPlaintextViewersCount int `json:"distributions_allowing_plaintext_viewers_count"`

	// The edge-to-origin hop. An http-only custom origin is fetched in
	// plaintext regardless of the viewer policy; match-viewer is plaintext
	// whenever the viewer request was. S3 REST origins declare no protocol in
	// config, so they are counted in rows rather than classified.
	DistributionsWithHTTPOnlyOriginCount    int `json:"distributions_with_http_only_origin_count"`
	DistributionsWithMatchViewerOriginCount int `json:"distributions_with_match_viewer_origin_count"`

	DistributionsByMinimumTLS map[string]int `json:"distributions_by_minimum_tls,omitempty"`

	Distributions []CloudFrontDistributionRow `json:"distributions,omitempty"`
}

// CloudFrontDistributionRow is an audit-level distribution inventory row.
type CloudFrontDistributionRow struct {
	ID                     string   `json:"id"`
	Domain                 string   `json:"domain"`
	Aliases                []string `json:"aliases,omitempty"`
	Enabled                bool     `json:"enabled"`
	AllowsPlaintextViewers bool     `json:"allows_plaintext_viewers"`
	MinimumProtocolVersion string   `json:"minimum_protocol_version,omitempty"`
	HTTPOnlyOriginCount    int      `json:"http_only_origin_count,omitempty"`
	MatchViewerOriginCount int      `json:"match_viewer_origin_count,omitempty"`
	HTTPSOnlyOriginCount   int      `json:"https_only_origin_count,omitempty"`
	S3OriginCount          int      `json:"s3_origin_count,omitempty"`
}

// LoadBalancerMetrics covers load balancer transport enforcement: which hops
// force TLS toward the client and which accept plaintext.
type LoadBalancerMetrics struct {
	LoadBalancerCount int `json:"load_balancer_count"`

	ALBCount int `json:"alb_count"`
	// Judged by each HTTP listener's default action. Listener rules are not
	// inspected, so a path-scoped plaintext rule behind a redirecting default
	// action is not visible here.
	ALBsServingPlaintextCount               int `json:"albs_serving_plaintext_count"`
	InternetFacingALBsServingPlaintextCount int `json:"internet_facing_albs_serving_plaintext_count"`
	ALBsWithoutHTTPSListenerCount           int `json:"albs_without_https_listener_count"`

	NLBCount            int `json:"nlb_count"`
	NLBTLSListenerCount int `json:"nlb_tls_listener_count"`
	// TCP and UDP listeners forward bytes untouched, so whether the stream is
	// encrypted is decided by the endpoints, not by this hop.
	NLBTCPPassthroughListenerCount int `json:"nlb_tcp_passthrough_listener_count"`

	// Zone redundancy. One zone is a categorical boundary: ALBs cannot be
	// single-zone by AWS rule, so this in practice counts network LBs.
	SingleZoneLoadBalancerCount int `json:"single_zone_load_balancer_count"`

	TargetGroupCount                    int `json:"target_group_count"`
	TargetGroupsWithoutHealthCheckCount int `json:"target_groups_without_health_check_count"`
	TargetGroupListingFailedRegionCount int `json:"target_group_listing_failed_region_count,omitempty"`

	TLSListenersByPolicy map[string]int `json:"tls_listeners_by_policy,omitempty"`

	// Load balancers whose listeners could not be read. Their transport
	// posture is unproven rather than clean.
	ListenersUnresolvedCount int `json:"listeners_unresolved_count,omitempty"`

	LoadBalancers []LoadBalancerRow `json:"load_balancers,omitempty"`
	TargetGroups  []TargetGroupRow  `json:"target_groups,omitempty"`
}

// LoadBalancerRow is an audit-level load balancer inventory row.
type LoadBalancerRow struct {
	Name                  string        `json:"name"`
	Region                string        `json:"region"`
	Type                  string        `json:"type"`
	Scheme                string        `json:"scheme"`
	AvailabilityZoneCount int           `json:"availability_zone_count"`
	Listeners             []ListenerRow `json:"listeners,omitempty"`
	ListenersUnresolved   bool          `json:"listeners_unresolved,omitempty"`
}

// TargetGroupRow is an audit-level target group row: how the load balancer
// decides a backend is dead.
type TargetGroupRow struct {
	Name                       string `json:"name"`
	Region                     string `json:"region"`
	Protocol                   string `json:"protocol,omitempty"`
	TargetType                 string `json:"target_type,omitempty"`
	HealthCheckEnabled         bool   `json:"health_check_enabled"`
	HealthCheckIntervalSeconds int32  `json:"health_check_interval_seconds,omitempty"`
	HealthyThresholdCount      int32  `json:"healthy_threshold_count,omitempty"`
	UnhealthyThresholdCount    int32  `json:"unhealthy_threshold_count,omitempty"`
	Attached                   bool   `json:"attached"`
}

// ListenerRow is one listener's transport configuration.
type ListenerRow struct {
	Port             int32  `json:"port"`
	Protocol         string `json:"protocol"`
	SSLPolicy        string `json:"ssl_policy,omitempty"`
	RedirectsToHTTPS bool   `json:"redirects_to_https"`
}

// StoredImageMetrics covers owned EBS snapshots and AMIs: whether they are
// exposed publicly and whether they are encrypted. Volumes attached to running
// instances are covered by EC2Metrics instead.
//
// The *ExposureUnknown flags exist so a failed lookup is never readable as
// "nothing is public", which is the reading that would matter most.
type StoredImageMetrics struct {
	SnapshotCount            int  `json:"snapshot_count"`
	UnencryptedSnapshotCount int  `json:"unencrypted_snapshot_count"`
	PublicSnapshotCount      int  `json:"public_snapshot_count"`
	SnapshotExposureUnknown  bool `json:"snapshot_exposure_unknown,omitempty"`

	ImageCount                       int  `json:"image_count"`
	ImagesWithUnencryptedVolumeCount int  `json:"images_with_unencrypted_volume_count"`
	PublicImageCount                 int  `json:"public_image_count"`
	ImageExposureUnknown             bool `json:"image_exposure_unknown,omitempty"`

	// Audit: only the exposed resources, which are the actionable ones.
	PublicSnapshots []PublicResourceRow `json:"public_snapshots,omitempty"`
	PublicImages    []PublicResourceRow `json:"public_images,omitempty"`
}

// PublicResourceRow identifies a resource anyone can read.
type PublicResourceRow struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	Region    string `json:"region"`
	Encrypted bool   `json:"encrypted"`
	CreatedAt string `json:"created_at,omitempty"`
}

// MonitoringMetrics covers CloudWatch alarms and how far their notifications
// travel. Zero alarms is not evidence that nobody is paged: many teams escalate
// through EventBridge or a third-party monitor instead, which this surface does
// not see.
type MonitoringMetrics struct {
	AlarmCount                     int `json:"alarm_count"`
	AlarmsWithActionsDisabledCount int `json:"alarms_with_actions_disabled_count"`
	AlarmsWithoutNotificationCount int `json:"alarms_without_notification_count"`
	AlarmsInsufficientDataCount    int `json:"alarms_insufficient_data_count"`

	// The end-to-end answer: actions enabled, a notification topic attached,
	// and that topic holding at least one confirmed subscriber.
	AlarmsReachingSubscriberCount int `json:"alarms_reaching_subscriber_count"`

	NotificationTopicCount                int `json:"notification_topic_count"`
	TopicsWithoutConfirmedSubscriberCount int `json:"topics_without_confirmed_subscriber_count"`
	TopicsUnresolvedCount                 int `json:"topics_unresolved_count,omitempty"`

	// Counts only. Subscription endpoints are never collected: they are email
	// addresses and phone numbers, and an HTTPS endpoint is routinely a webhook
	// URL that is itself a credential.
	SubscriptionsByProtocol               map[string]int `json:"subscriptions_by_protocol,omitempty"`
	SubscriptionsPendingConfirmationCount int            `json:"subscriptions_pending_confirmation_count"`

	Alarms             []CloudWatchAlarmRow `json:"alarms,omitempty"`
	AlarmsTruncated    bool                 `json:"alarms_truncated,omitempty"`
	AlarmsDroppedCount int                  `json:"alarms_dropped_count,omitempty"`
}

// CloudWatchAlarmRow is an audit-level alarm definition.
type CloudWatchAlarmRow struct {
	Name               string   `json:"name"`
	Region             string   `json:"region"`
	Namespace          string   `json:"namespace"`
	MetricName         string   `json:"metric_name"`
	ComparisonOperator string   `json:"comparison_operator"`
	Threshold          *float64 `json:"threshold,omitempty"`
	EvaluationPeriods  int32    `json:"evaluation_periods"`
	ActionsEnabled     bool     `json:"actions_enabled"`
	StateValue         string   `json:"state_value"`
	NotificationTopics int      `json:"notification_topics"`
	ReachesSubscriber  bool     `json:"reaches_subscriber"`
	OtherActionCount   int      `json:"other_action_count,omitempty"`
}

// IAMPasswordPolicy is the account password policy for IAM console sign-in.
// Present only when one is configured; see IAMMetrics for the absent case.
type IAMPasswordPolicy struct {
	MinimumLength              int  `json:"minimum_length"`
	RequireSymbols             bool `json:"require_symbols"`
	RequireNumbers             bool `json:"require_numbers"`
	RequireUppercase           bool `json:"require_uppercase"`
	RequireLowercase           bool `json:"require_lowercase"`
	AllowUsersToChangePassword bool `json:"allow_users_to_change_password"`
	ExpirePasswords            bool `json:"expire_passwords"`
	HardExpiry                 bool `json:"hard_expiry"`

	// Present only when set. Absent means passwords do not expire and previous
	// passwords may be reused respectively.
	MaxPasswordAgeDays      *int `json:"max_password_age_days,omitempty"`
	PasswordReusePrevention *int `json:"password_reuse_prevention,omitempty"`
}

// IdentityCenterStatus contains AWS IAM Identity Center (formerly AWS SSO)
// posture.
//
// Trust fields tell you whether IdC is enabled and how big it is. Audit
// surfaces the access model itself: per-permission-set rows (the unit of
// access an admin grants), the user and group inventory, group membership
// edges, and the account assignment edges. Joining users, member_user_ids,
// account_assignments, and permission_sets reconstructs who can access which
// account with which permission set, entirely within the pack. Internal adds
// the managed-policy ARNs attached to each permission set.
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
	// enabled; null when not collected at this level. AccountAssignments rows
	// are meaningful only when assignments_evaluated is true: on listing
	// failure the array is empty, the marker is false, and a diagnostic names
	// the cause. Truncation companions emit at the same level.
	PermissionSets          []IdentityCenterPermissionSetRow `json:"permission_sets"`
	Users                   []IdentityCenterUserRow          `json:"users"`
	Groups                  []IdentityCenterGroupRow         `json:"groups"`
	AccountAssignments      []IdentityCenterAssignmentRow    `json:"account_assignments"`
	AssignmentsEvaluated    bool                             `json:"assignments_evaluated"`
	AssignmentsTruncated    bool                             `json:"assignments_truncated"`
	AssignmentsDroppedCount int                              `json:"assignments_dropped_count"`
}

// IdentityCenterPermissionSetRow is a per-permission-set audit-level row.
// SessionDurationISO8601 is the raw "PT8H" style string AWS returns;
// ProvisionedAccountIDs lists the accounts the set is provisioned to.
// ManagedPolicyARNs is empty at audit and populated at internal.
// HasInlinePolicy is presence-only (never the document) since inline policies
// may encode tenant-specific authz logic.
type IdentityCenterPermissionSetRow struct {
	Name                   string   `json:"name"`
	ARN                    string   `json:"arn"`
	Description            string   `json:"description,omitempty"`
	SessionDurationISO8601 string   `json:"session_duration_iso8601,omitempty"`
	ManagedPoliciesCount   int      `json:"managed_policies_count"`
	AccountsAssignedCount  int      `json:"accounts_assigned_count"`
	ProvisionedAccountIDs  []string `json:"provisioned_account_ids"`
	ManagedPolicyARNs      []string `json:"managed_policy_arns,omitempty"`
	HasInlinePolicy        bool     `json:"has_inline_policy,omitempty"`
}

// IdentityCenterUserRow is a per-user audit-level row from the identity
// store. PrimaryEmail is empty when no email is marked Primary on the user.
// No PII beyond the primary email is collected at any level.
type IdentityCenterUserRow struct {
	UserID       string `json:"user_id"`
	UserName     string `json:"user_name"`
	DisplayName  string `json:"display_name,omitempty"`
	PrimaryEmail string `json:"primary_email,omitempty"`
}

// IdentityCenterGroupRow is a per-group audit-level row. MemberUserIDs holds
// the direct user members (join against users[].user_id); MemberCount is its
// length. Both are null when membership enrichment failed.
type IdentityCenterGroupRow struct {
	GroupID       string   `json:"group_id"`
	DisplayName   string   `json:"display_name"`
	Description   string   `json:"description,omitempty"`
	MemberCount   int      `json:"member_count"`
	MemberUserIDs []string `json:"member_user_ids"`
}

// IdentityCenterAssignmentRow is one principal-to-permission-set-to-account
// edge at audit level. PrincipalType is USER or GROUP; GROUP edges resolve to
// users via groups[].member_user_ids.
type IdentityCenterAssignmentRow struct {
	AccountID        string `json:"account_id"`
	PermissionSetARN string `json:"permission_set_arn"`
	PrincipalType    string `json:"principal_type"`
	PrincipalID      string `json:"principal_id"`
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

	// Volumes attached to nothing. They keep their data, are invisible to the
	// instance join above, and are where forgotten unencrypted data sits.
	UnattachedVolumeCount            int `json:"unattached_volume_count"`
	UnattachedUnencryptedVolumeCount int `json:"unattached_unencrypted_volume_count"`

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
	LogGroupCount int `json:"log_group_count"`
	// No retention setting in CloudWatch Logs means retain indefinitely, so this
	// counts groups that never delete anything. That satisfies a retain-for-N
	// requirement and fails a delete-after-N one; the name reads like a gap in
	// only the second sense. Kept as-is because packs already in the field carry
	// this key.
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
