package collector

// Schema version.
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

// IAM trust policy constants.
const (
	TrustPolicyEffectAllow    = "Allow"
	TrustPolicyPrincipalAll   = "*"
	TrustPolicyARNPrefix      = "arn:aws:iam::"
	AccessAnalyzerTypeAccount = "ACCOUNT"
)
