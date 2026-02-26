// Package aws provides AWS API client functionality.
package aws

import "time"

// CredentialReport represents a parsed IAM credential report.
type CredentialReport struct {
	Users []CredentialReportUser
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

// Role represents an IAM role with trust policy info.
type Role struct {
	RoleName                 string
	ARN                      string
	AssumeRolePolicyDocument string
	HasExternalTrust         bool // Computed from trust policy
}

// Bucket represents an S3 bucket with security settings.
type Bucket struct {
	Name                     string
	Region                   string
	PublicAccessBlocked      bool
	DefaultEncryptionEnabled bool
	VersioningEnabled        bool
	MFADeleteEnabled         bool
	LoggingEnabled           bool
	SSLOnlyPolicy            bool
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
}

// VPC represents a VPC with security settings.
type VPC struct {
	VPCID           string
	IsDefault       bool
	FlowLogsEnabled bool
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
type SecurityGroupRule struct {
	Protocol   string // "tcp", "udp", "icmp", "-1" (all)
	FromPort   int
	ToPort     int
	CIDRBlocks []string
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
	S3BucketName              string
	IsMultiRegionTrail        bool
	LogFileValidationEnabled  bool
	CloudWatchLogsLogGroupArn *string
	KMSKeyId                  *string
	IsLogging                 bool
}

// ConfigRecorder represents an AWS Config recorder.
type ConfigRecorder struct {
	Name          string
	RoleARN       string
	AllSupported  bool
	IncludeGlobal bool
	Recording     bool
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
	Name          string
	ARN           string
	Type          string // ACCOUNT or ORGANIZATION
	Status        string
	FindingsCount int
}
