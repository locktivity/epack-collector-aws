// Package aws provides AWS API client functionality.
package aws

import "time"

// CredentialReport represents a parsed IAM credential report.
type CredentialReport struct {
	Users []CredentialReportUser
}

// AccountSummary represents root-account credential presence from IAM
// GetAccountSummary.
type AccountSummary struct {
	AccountMFAEnabled                 bool
	AccountPasswordPresent            bool
	AccountAccessKeysPresent          bool
	AccountSigningCertificatesPresent bool
}

// OrganizationFeatures represents IAM centralized root access features enabled
// for the AWS Organization.
type OrganizationFeatures struct {
	OrganizationID                          string
	RootCredentialsManagementFeatureEnabled bool
	RootSessionsFeatureEnabled              bool
}

// CredentialReportUser represents a single user row in the credential report.
type CredentialReportUser struct {
	User                      string
	ARN                       string
	UserCreationTime          time.Time
	PasswordEnabled           bool
	PasswordLastUsed          *time.Time
	PasswordLastChanged       *time.Time
	PasswordNextRotation      *time.Time
	MFAActive                 bool
	AccessKey1Active          bool
	AccessKey1LastRotated     *time.Time
	AccessKey1LastUsedDate    *time.Time
	AccessKey1LastUsedRegion  string
	AccessKey1LastUsedService string
	AccessKey2Active          bool
	AccessKey2LastRotated     *time.Time
	AccessKey2LastUsedDate    *time.Time
	AccessKey2LastUsedRegion  string
	AccessKey2LastUsedService string
	Cert1Active               bool
	Cert1LastRotated          *time.Time
	Cert2Active               bool
	Cert2LastRotated          *time.Time
}

// IsRootUser returns true if this is the root account user.
func (u CredentialReportUser) IsRootUser() bool {
	return u.User == "<root_account>"
}

// HasConsoleAccess returns true if the user has console (password) access.
func (u CredentialReportUser) HasConsoleAccess() bool {
	return u.PasswordEnabled
}

// HasAccessKeys returns true if the user has any active access keys.
func (u CredentialReportUser) HasAccessKeys() bool {
	return u.AccessKey1Active || u.AccessKey2Active
}

// HasSigningCertificates returns true if the root user has any active signing certificates.
func (u CredentialReportUser) HasSigningCertificates() bool {
	return u.Cert1Active || u.Cert2Active
}

// HasLongTermCredentials returns true if the root user has console, access-key,
// or signing-certificate credentials present.
func (u CredentialReportUser) HasLongTermCredentials() bool {
	return u.PasswordEnabled || u.HasAccessKeys() || u.HasSigningCertificates()
}

// PasswordPolicy represents an IAM password policy.
type PasswordPolicy struct {
	MinimumPasswordLength      int
	RequireSymbols             bool
	RequireNumbers             bool
	RequireUppercase           bool
	RequireLowercase           bool
	AllowUsersToChangePassword bool
	ExpirePasswords            bool
	MaxPasswordAge             *int
	PasswordReusePrevention    *int
	HardExpiry                 bool
}

// EBSVolumeState is the per-volume state the collector joins onto instances
// and aggregates for unattached volumes. Deliberately two booleans rather than
// the full Volume object, which would bloat memory in volume-heavy regions.
type EBSVolumeState struct {
	Encrypted bool
	Attached  bool
}

// MFADevice represents an MFA device assigned to an IAM user.
type MFADevice struct {
	UserName     string
	SerialNumber string
	EnableDate   time.Time
}

// Role represents an IAM role with trust policy info.
type Role struct {
	RoleName                 string
	ARN                      string
	AssumeRolePolicyDocument string
	HasExternalTrust         bool // Computed from trust policy
}

// Bucket represents an S3 bucket with security settings.
// DefaultEncryptionEnabled includes AWS's SSE-S3 baseline for new objects.
type Bucket struct {
	Name                         string
	Region                       string
	EffectivePublicAccessBlocked bool
	PublicAccessBlock            PublicAccessBlockSettings
	DefaultEncryptionEnabled     bool
	DefaultEncryptionEvaluated   bool
	DefaultEncryptionErrorCode   string
	VersioningEnabled            bool
	MFADeleteEnabled             bool
	LoggingEnabled               bool
	LoggingTargetBucket          string
	SSLOnlyPolicy                bool
}

// PublicAccessBlockSettings represents S3 Block Public Access flags read from
// either account-level or bucket-level configuration.
type PublicAccessBlockSettings struct {
	BlockPublicACLs       bool
	IgnorePublicACLs      bool
	BlockPublicPolicy     bool
	RestrictPublicBuckets bool
	Evaluated             bool
	ErrorCode             string
}

// BlocksPublicAccess returns true when all four S3 Block Public Access flags
// are enabled.
func (p PublicAccessBlockSettings) BlocksPublicAccess() bool {
	return p.BlockPublicACLs &&
		p.IgnorePublicACLs &&
		p.BlockPublicPolicy &&
		p.RestrictPublicBuckets
}

// DBInstance represents an RDS instance with security settings.
type DBInstance struct {
	DBInstanceIdentifier    string
	Engine                  string
	EngineVersion           string
	PubliclyAccessible      bool
	StorageEncrypted        bool
	DeletionProtection      bool
	BackupRetentionPeriod   int
	MultiAZ                 bool
	AutoMinorVersionUpgrade bool
	PreferredBackupWindow   string

	// EndpointPort and VpcSecurityGroupIDs feed the database-port ingress
	// evaluation: which sources the security groups allow on the database's
	// listening port.
	EndpointPort        int
	VpcSecurityGroupIDs []string

	// ParameterApplyStatus matters for any claim built on parameter values:
	// pending-reboot means the group's desired values are not in force.
	ParameterGroupName   string
	ParameterApplyStatus string
	LogExports           []string

	// LatestRestorableTime is the most recent point-in-time recovery target
	// (PITR). Nil for instances without PITR support or when AWS has not yet
	// computed a restorable time for a newly-created instance.
	LatestRestorableTime *time.Time
}

// DBCluster represents an RDS cluster with security settings.
type DBCluster struct {
	DBClusterIdentifier   string
	Engine                string
	EngineVersion         string
	StorageEncrypted      bool
	DeletionProtection    bool
	BackupRetentionPeriod int
	MultiAZ               bool // Inferred from cluster type

	// LatestRestorableTime is the most recent point-in-time recovery target.
	// Nil semantics match DBInstance above.
	LatestRestorableTime *time.Time
}

// BucketPolicy is a raw S3 bucket policy document. Nil means no policy
// (NoSuchBucketPolicy from the API), distinct from an empty document.
type BucketPolicy struct {
	Document string
}

// BucketACL is the parsed ACL for an S3 bucket. HasPublicGrant is true if
// any grant targets the AllUsers or AuthenticatedUsers canonical groups.
type BucketACL struct {
	OwnerID        string
	Grants         []BucketACLGrant
	HasPublicGrant bool
}

// BucketACLGrant is a single grant entry. For canonical-user grantees,
// GranteeID is populated. For group grantees (AllUsers, AuthenticatedUsers,
// LogDelivery), GranteeURI is populated. The two are mutually exclusive.
type BucketACLGrant struct {
	GranteeType string // "CanonicalUser", "Group", "AmazonCustomerByEmail"
	GranteeURI  string
	GranteeID   string
	Permission  string // FULL_CONTROL, WRITE, WRITE_ACP, READ, READ_ACP
}

// BucketLifecycle is the parsed lifecycle configuration. Nil means no
// lifecycle config (NoSuchLifecycleConfiguration from the API).
type BucketLifecycle struct {
	Rules []BucketLifecycleRule
}

// BucketLifecycleRule is one rule from a lifecycle configuration. Transitions
// and Expiration are normalized to human-readable strings (e.g., "30d→STANDARD_IA",
// "365d") rather than the SDK's raw nested types, since the consumer use case
// is forensic / audit-trail not lifecycle-rule editing.
type BucketLifecycleRule struct {
	ID          string
	Status      string // Enabled / Disabled
	Prefix      string
	Transitions []string
	Expiration  string

	// Structured expiration for classification: the display string above is
	// for reading, these are for deciding. Days is zero when the rule expires
	// by date or not at all; ExpirationIsDate distinguishes the two.
	ExpirationDays   int32
	ExpirationIsDate bool
}

// ObjectLockConfig is a bucket's object lock default retention. A locked
// trail bucket is the immutability claim: nobody shortens retention, not even
// an administrator when the mode is COMPLIANCE.
type ObjectLockConfig struct {
	Mode  string
	Days  int32
	Years int32
}

// VPC represents a VPC with security settings.
type VPC struct {
	VPCID             string
	IsDefault         bool
	FlowLogsEnabled   bool
	FlowLogsEvaluated bool
	FlowLogsErrorCode string
}

// SecurityGroup represents an EC2 security group.
type SecurityGroup struct {
	GroupID      string
	GroupName    string
	VPCID        string
	IsDefault    bool
	IngressRules []SecurityGroupRule
}

// SecurityGroupRule represents a security group ingress rule.
//
// CIDRBlocks captures IPv4/IPv6 ingress sources. SourceSGIDs captures rules
// that allow ingress from other security groups (the common pattern in default
// SGs and tier-to-tier rules). A rule can have either, both, or neither
// populated; an empty rule (both nil) is a degenerate config worth flagging.
type SecurityGroupRule struct {
	Protocol    string // "tcp", "udp", "icmp", "-1" (all)
	FromPort    int
	ToPort      int
	CIDRBlocks  []string
	SourceSGIDs []string
}

// IsOpenToWorld returns true if the rule allows traffic from 0.0.0.0/0 or ::/0.
func (r SecurityGroupRule) IsOpenToWorld() bool {
	for _, cidr := range r.CIDRBlocks {
		if cidr == "0.0.0.0/0" || cidr == "::/0" {
			return true
		}
	}
	return false
}

// IsSSH returns true if the rule covers SSH port 22.
func (r SecurityGroupRule) IsSSH() bool {
	return r.Protocol == "tcp" && r.FromPort <= 22 && r.ToPort >= 22
}

// IsRDP returns true if the rule covers RDP port 3389.
func (r SecurityGroupRule) IsRDP() bool {
	return r.Protocol == "tcp" && r.FromPort <= 3389 && r.ToPort >= 3389
}

// IsAllPorts returns true if the rule allows all ports.
func (r SecurityGroupRule) IsAllPorts() bool {
	return r.Protocol == "-1" || (r.FromPort == 0 && r.ToPort == 65535) || (r.FromPort == -1 && r.ToPort == -1)
}

// Trail represents a CloudTrail trail.
type Trail struct {
	Name                      string
	TrailARN                  string
	HomeRegion                string
	S3BucketName              string
	S3KeyPrefix               string
	IsMultiRegionTrail        bool
	IsOrganizationTrail       bool
	LogFileValidationEnabled  bool
	CloudWatchLogsLogGroupArn *string
	KMSKeyId                  *string
	IsLogging                 bool
	TrailStatusEvaluated      bool
	TrailStatusInferred       bool
	TrailStatusErrorCode      string
}

// ConfigRecorder represents an AWS Config recorder.
type ConfigRecorder struct {
	Name          string
	RoleARN       string
	AllSupported  bool
	IncludeGlobal bool
	Recording     bool
}

// ConfigRule represents a single AWS Config rule and its most recent
// evaluation state. Compliance state is intentionally a string (rather than a
// typed enum) so that future AWS-side additions surface as-is instead of
// being silently downgraded to an "unknown" bucket.
type ConfigRule struct {
	Name             string
	ARN              string
	SourceOwner      string
	SourceIdentifier string
	ComplianceState  string
	LastEvaluated    *time.Time
}

// GuardDutyDetector represents a GuardDuty detector.
type GuardDutyDetector struct {
	DetectorID                             string
	Status                                 string
	FindingPublishingFreq                  string
	S3LogsEnabled                          bool
	EKSAuditLogsEnabled                    bool
	MalwareScanEnabled                     bool
	HighOrCriticalFindings                 int
	HighOrCriticalFindingsOlderThan48Hours int
}

// GuardDutyFinding is a single unarchived high-or-critical GuardDuty finding,
// stripped to the fields useful for a breach-investigation triage list.
// Severity follows AWS's 0.1-8.9 scale; 7+ is the high/critical band we filter on.
type GuardDutyFinding struct {
	ID           string
	DetectorID   string
	Severity     float64
	Type         string
	Title        string
	ResourceType string
	ResourceID   string
	CreatedAt    *time.Time
	UpdatedAt    *time.Time
}

// SecurityHubConfig represents Security Hub configuration.
type SecurityHubConfig struct {
	Enabled              bool
	AutoEnableControls   bool
	StandardsARNs        []string
	IntegrationCount     int
	ProductSubscriptions []string
}

// SecurityHubCISCompliance contains CIS control compliance counts.
type SecurityHubCISCompliance struct {
	PassedControls       int
	FailedControls       int
	WarningControls      int
	NotAvailableControls int
}

// SecurityHubCISComplianceByLevel contains CIS control compliance counts split by benchmark level.
type SecurityHubCISComplianceByLevel struct {
	Level1  SecurityHubCISCompliance
	Level2  SecurityHubCISCompliance
	Unknown SecurityHubCISCompliance
}

// InspectorSummary contains Inspector posture derived from Security Hub findings.
type InspectorSummary struct {
	Enabled                bool
	TotalFindings          int
	PatchedFindings        int
	UnpatchedFindings      int
	TotalAffectedResources int
	UnpatchedResources     int
}

// AccessAnalyzer represents an IAM Access Analyzer.
type AccessAnalyzer struct {
	Name   string
	ARN    string
	Type   string // ACCOUNT or ORGANIZATION
	Status string

	// Findings split by triage state: archived findings mean someone looks at
	// them. FindingsUnresolved marks a failed listing, so an unreadable
	// analyzer is never mistaken for a clean one.
	ActiveFindingsCount   int
	ArchivedFindingsCount int
	FindingsUnresolved    bool
}

// IdentityCenterInstance is a single AWS IAM Identity Center (formerly AWS SSO)
// instance. There is at most one instance per account, deployed in one home
// region.
type IdentityCenterInstance struct {
	InstanceARN     string
	IdentityStoreID string
	Region          string
}

// IdentityCenterPermissionSet is one permission set provisioned to the
// instance. ManagedPolicyARNs is empty unless the caller requested internal-
// level enrichment; HasInlinePolicy is similarly populated at internal level
// (presence only, not contents — the policy document may encode tenant-specific
// authorization logic).
type IdentityCenterPermissionSet struct {
	ARN                    string
	Name                   string
	Description            string
	SessionDurationISO8601 string
	ManagedPoliciesCount   int
	AccountsAssignedCount  int
	ProvisionedAccountIDs  []string
	ManagedPolicyARNs      []string
	HasInlinePolicy        bool
}

// IdentityStoreUser is one user in the identity store. PrimaryEmail is the
// email marked Primary on the user. The identity store API exposes no
// enabled/disabled status; consumers wanting activity signals correlate
// against IdP-side evidence instead.
type IdentityStoreUser struct {
	UserID       string
	UserName     string
	DisplayName  string
	PrimaryEmail string
}

// IdentityStoreGroup is one group in the identity store. MemberCount and
// MemberUserIDs are populated only when membership enrichment was requested
// (an extra paginated call per group).
type IdentityStoreGroup struct {
	GroupID       string
	DisplayName   string
	Description   string
	MemberCount   int
	MemberUserIDs []string
}

// IdentityCenterAssignment is one principal-to-permission-set-to-account edge
// from ListAccountAssignments. PrincipalType is "USER" or "GROUP".
type IdentityCenterAssignment struct {
	AccountID        string
	PermissionSetARN string
	PrincipalType    string
	PrincipalID      string
}

// SSMParameter is a single Parameter Store parameter's posture-relevant
// metadata. Parameter VALUES are never collected — only the metadata returned
// by DescribeParameters. The forbidden-API lint enforces this at build time.
//
// KMSKeyARN is only meaningful for SecureString parameters; String and
// StringList types aren't encrypted (their values are stored as plaintext).
// For SecureString, an empty KMSKeyARN means the parameter uses the AWS-managed
// `aws/ssm` key (still encrypted, but no customer key control).
type SSMParameter struct {
	Name             string
	Type             string // String / StringList / SecureString
	DataType         string // text / aws:ec2:image / aws:ssm:integration
	Version          int64
	Tier             string // Standard / Advanced / Intelligent-Tiering
	Description      string
	KMSKeyARN        string
	LastModifiedDate *time.Time
	LastModifiedUser string
}

// SecretsManagerSecret is a single Secrets Manager secret's posture-relevant
// metadata. Secret VALUES are never collected — this type intentionally has
// no fields that could carry SecretString or SecretBinary, and the surface's
// AWS client never invokes value-reading APIs (enforced structurally by this
// type and at build time by the forbidden-API lint).
//
// KMSKeyARN is the customer-managed key ARN when the secret encrypts with one;
// empty when the secret uses the default `aws/secretsmanager` AWS-managed key.
//
// DeletionDate is set only when the secret is scheduled for deletion (the
// AWS recovery-window state).
type SecretsManagerSecret struct {
	Name              string
	ARN               string
	Description       string
	KMSKeyARN         string
	RotationEnabled   bool
	RotationLambdaARN string
	RotationDays      int64
	NextRotationDate  *time.Time
	CreatedDate       *time.Time
	LastChangedDate   *time.Time
	LastAccessedDate  *time.Time
	DeletionDate      *time.Time
	PrimaryRegion     string
	OwningService     string
	Tags              map[string]string
}

// KMSKey is a single CUSTOMER-managed KMS key's posture-relevant metadata.
// AWS-managed keys are intentionally excluded — the customer has no posture
// lever over them. KeyManager will always be "CUSTOMER" here.
//
// RotationEnabled is only meaningful for symmetric CMKs (KeySpec
// SYMMETRIC_DEFAULT); asymmetric keys don't support rotation. Callers that
// compute the "rotation disabled" trust aggregate must filter on KeySpec.
//
// DeletionDate is set only when KeyState is "PendingDeletion".
type KMSKey struct {
	KeyID           string
	ARN             string
	KeyState        string
	KeyUsage        string
	KeySpec         string
	Origin          string
	MultiRegion     bool
	CreationDate    *time.Time
	DeletionDate    *time.Time
	RotationEnabled bool
	Description     string
	Aliases         []string
}

// CloudWatchLogGroup is a single CloudWatch Logs log group's posture-relevant
// metadata. RetentionInDays of 0 represents "Never expire" — log groups
// without a retention policy. KMSKeyARN is the customer-managed key when set;
// empty means the group uses AWS-managed encryption (still encrypted, but
// without customer key control).
type CloudWatchLogGroup struct {
	Name            string
	ARN             string
	CreationTime    *time.Time
	RetentionInDays int32
	StoredBytes     int64
	KMSKeyARN       string
}

// EC2Instance is a single EC2 instance's posture-relevant metadata.
//
// HTTPTokens carries the raw IMDS enforcement value ("required" for IMDSv2,
// "optional" otherwise). The collector exposes this as a typed boolean trust
// aggregate plus the raw string at audit so reviewers can verify the source.
//
// Tags and AttachedVolumeIDs are populated only at internal level (extracted
// from the same DescribeInstances response, no extra API calls). IAMInstanceProfileARN
// likewise comes from the base call but is internal-only because it pairs an
// instance with the role that can act on its behalf.
type EC2Instance struct {
	InstanceID   string
	InstanceType string
	State        string
	LaunchTime   *time.Time
	ImageID      string

	VPCID       string
	SubnetID    string
	HasPublicIP bool
	PublicIP    string

	HTTPTokens   string
	HTTPHopLimit int

	SecurityGroupIDs      []string
	IAMInstanceProfileARN string
	KeyName               string

	// AttachedVolumeIDs is populated from BlockDeviceMappings; the corresponding
	// encryption flags come from a separate DescribeVolumes call joined in the
	// collector. RootVolumeID is the volume backing the root device, used to
	// surface root-volume encryption specifically (vs any-attached).
	AttachedVolumeIDs []string
	RootVolumeID      string
	Tags              map[string]string
}

// LambdaFunction is a single Lambda function's posture-relevant metadata.
//
// EnvVarNames carries the environment variable KEYS only; values are dropped
// at the SDK boundary so they cannot leak into the artifact. This is the only
// safe answer for env vars: keys reveal which integrations a function is wired
// to (useful for posture review) without exposing the secret material that
// values typically hold.
//
// HasResourcePolicy, HasFunctionURL, and FunctionURLAuthType are not populated
// by ListFunctions; they require per-function follow-up calls and are filled
// in by the collector at audit level or higher.
type LambdaFunction struct {
	Name          string
	ARN           string
	Runtime       string
	Architectures []string
	LastModified  *time.Time
	MemorySize    int
	Timeout       int
	PackageType   string // "Zip" or "Image"
	CodeSize      int64

	RoleARN       string
	KMSKeyARN     string // env var encryption key (only set when customer KMS is in use)
	LayerARNs     []string
	HasVPCConfig  bool
	DeadLetterARN string
	EnvVarNames   []string
}
