package collector

// SchemaVersion is the AWS-collector output schema version. See
// docs/schema/v1.0.0.json for the field-level contract and docs/levels.md
// for how `collected_at_level` gates which fields appear.
const SchemaVersion = "1.0.0"

// Credential thresholds (days).
const (
	InactiveDaysThreshold      = 90 // Days after which credentials are considered inactive
	AccessKeyAgeThreshold      = 90 // Days after which access keys should be rotated
	MinBackupRetentionDays     = 7  // Minimum acceptable RDS backup retention
	GuardDutyStaleFindingHours = 48 // Findings older than this are considered stale
)

// Default region for global services.
const DefaultPrimaryRegion = "us-east-1"

// Service-specific constants.
const (
	GuardDutyHighSeverityThreshold = 7
	CISStandardsARNMarker          = "cis"
	InspectorProductNamePrefix     = "Inspector"
)

// Percentage constants.
const (
	MaxPercentage = 100
)

// Per-surface truncation caps for internal-level inventories. Surfaces apply
// their cap via the Truncate helper; accounts beyond the cap surface a
// truncation warning and emit the highest-priority N rows per the surface's
// sort order.
const (
	// S3BucketsCap is the maximum number of buckets surfaced in the
	// audit/internal inventory. Accounts above this need follow-up batched
	// collection.
	S3BucketsCap = 10000

	// ConfigRulesCap is the maximum number of AWS Config rules surfaced per
	// region at internal level. AWS hard-limits accounts to 1000 rules per
	// region; the cap exists only as a defensive guard.
	ConfigRulesCap = 1000

	// GuardDutyFindingsCap is the maximum number of unarchived high-or-critical
	// GuardDuty findings surfaced per detector at internal level. Accounts that
	// hit this cap are almost certainly under active investigation; the cap
	// keeps artifact size bounded for the long-tail unmaintained account.
	GuardDutyFindingsCap = 5000

	// LambdaFunctionsCap is the maximum number of Lambda functions surfaced in
	// the audit/internal inventory across all regions. Accounts above this need
	// follow-up batched collection.
	LambdaFunctionsCap = 5000

	// EC2InstancesCap is the maximum number of EC2 instances surfaced in the
	// audit/internal inventory across all regions. The cap exists to keep
	// artifacts bounded for large fleets.
	EC2InstancesCap = 10000

	// EC2InstanceTagsCap is the maximum number of tags emitted per instance at
	// internal level. AWS caps tags at 50 per resource, so the cap is mostly
	// defensive against arbitrary tag-bombing schemes.
	EC2InstanceTagsCap = 50

	// CloudWatchLogGroupsCap is the maximum number of log groups surfaced in
	// the audit/internal inventory across all regions. Sort key is stored_bytes
	// DESC so large groups (the cost and compliance signal) survive truncation.
	CloudWatchLogGroupsCap = 10000

	// KMSKeysCap is the maximum number of customer-managed KMS keys surfaced
	// in the audit/internal inventory across all regions. Sort key is
	// creation_date DESC so the most recently-provisioned keys survive
	// truncation.
	KMSKeysCap = 5000

	// SecretsManagerSecretsCap is the maximum number of Secrets Manager
	// secrets surfaced in the audit/internal inventory across all regions.
	// Sort key is last_changed_date DESC so recently-rotated/edited secrets
	// (the most posture-interesting) survive truncation.
	SecretsManagerSecretsCap = 5000

	// SecretsManagerTagsCap is the maximum number of tags emitted per secret
	// at internal level. AWS caps tags at 50 per resource; this is defensive.
	SecretsManagerTagsCap = 50

	// SSMParametersCap is the maximum number of Parameter Store parameters
	// surfaced in the audit/internal inventory across all regions. Parameter
	// Store can hold tens of thousands of entries; this keeps artifacts bounded.
	// Sort key is last_modified_date DESC so recently-touched parameters
	// (the most posture-interesting) survive truncation.
	SSMParametersCap = 10000
)

// SSM parameter type constants.
const (
	SSMParameterTypeSecureString = "SecureString"
)

// EC2 IMDS constants.
const (
	// IMDSHTTPTokensRequired is the IMDSv2-enforced value of HttpTokens. Any
	// other value (including the empty string and "optional") permits IMDSv1.
	IMDSHTTPTokensRequired = "required"
)

// DeprecatedLambdaRuntimes lists Lambda runtimes AWS has marked as deprecated.
// Membership in this set is the signal we use for the trust-level
// `deprecated_runtime_count` aggregate. Update as AWS publishes new deprecations:
// https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
var DeprecatedLambdaRuntimes = map[string]bool{
	"nodejs":         true,
	"nodejs4.3":      true,
	"nodejs4.3-edge": true,
	"nodejs6.10":     true,
	"nodejs8.10":     true,
	"nodejs10.x":     true,
	"nodejs12.x":     true,
	"nodejs14.x":     true,
	"nodejs16.x":     true,
	"python2.7":      true,
	"python3.6":      true,
	"python3.7":      true,
	"python3.8":      true,
	"ruby2.5":        true,
	"ruby2.7":        true,
	"java8":          true,
	"go1.x":          true,
	"dotnetcore1.0":  true,
	"dotnetcore2.0":  true,
	"dotnetcore2.1":  true,
	"dotnetcore3.1":  true,
	"dotnet5.0":      true,
	"dotnet6":        true,
}

// IAM trust policy constants.
const (
	TrustPolicyEffectAllow    = "Allow"
	TrustPolicyPrincipalAll   = "*"
	TrustPolicyARNPrefix      = "arn:aws:iam::"
	AccessAnalyzerTypeAccount = "ACCOUNT"
)
