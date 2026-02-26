package aws

import (
	"context"
	"encoding/csv"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	configservice "github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	guarddutytypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	securityhubtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Client provides access to AWS APIs.
type Client interface {
	// GetCallerIdentity returns the account ID of the current credentials.
	GetCallerIdentity(ctx context.Context) (string, error)

	// GetAccountAlias returns the account alias if set.
	GetAccountAlias(ctx context.Context) (*string, error)

	// GetEnabledRegions returns the list of enabled regions.
	GetEnabledRegions(ctx context.Context) ([]string, error)

	// IAM
	GetCredentialReport(ctx context.Context) (*CredentialReport, error)
	GetPasswordPolicy(ctx context.Context) (*PasswordPolicy, error)
	ListRoles(ctx context.Context, callback func([]Role) error) error

	// S3
	ListBuckets(ctx context.Context) ([]Bucket, error)
	GetAccountPublicAccessBlock(ctx context.Context, accountID string) (bool, error)

	// RDS (regional)
	ListDBInstances(ctx context.Context, region string) ([]DBInstance, error)
	ListDBClusters(ctx context.Context, region string) ([]DBCluster, error)

	// Network (regional)
	ListVPCs(ctx context.Context, region string) ([]VPC, error)
	ListSecurityGroups(ctx context.Context, region string) ([]SecurityGroup, error)

	// Account Security (regional for some)
	DescribeTrails(ctx context.Context) ([]Trail, error)
	DescribeConfigRecorders(ctx context.Context, region string) ([]ConfigRecorder, error)
	ListGuardDutyDetectors(ctx context.Context, region string) ([]GuardDutyDetector, error)
	GetSecurityHubConfig(ctx context.Context, region string) (*SecurityHubConfig, error)
	GetSecurityHubCISComplianceByLevel(ctx context.Context, region, standardID string) (*SecurityHubCISComplianceByLevel, error)
	GetInspectorSummaryFromSecurityHub(ctx context.Context, region string) (*InspectorSummary, error)
	ListAccessAnalyzers(ctx context.Context, region string) ([]AccessAnalyzer, error)
}

// AWSClient implements the Client interface using AWS SDK v2.
type AWSClient struct {
	cfg aws.Config
}

// NewClient creates a new AWS client using the default credential chain.
func NewClient(ctx context.Context) (*AWSClient, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	return &AWSClient{cfg: cfg}, nil
}

// NewClientWithRole creates a new AWS client that assumes the specified role.
func NewClientWithRole(ctx context.Context, roleARN, externalID string) (*AWSClient, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	stsClient := sts.NewFromConfig(cfg)
	creds := stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(o *stscreds.AssumeRoleOptions) {
		if externalID != "" {
			o.ExternalID = &externalID
		}
		o.Duration = 1 * time.Hour
	})

	cfg.Credentials = aws.NewCredentialsCache(creds)

	return &AWSClient{cfg: cfg}, nil
}

// GetCallerIdentity returns the account ID of the current credentials.
func (c *AWSClient) GetCallerIdentity(ctx context.Context) (string, error) {
	stsClient := sts.NewFromConfig(c.cfg)
	output, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("getting caller identity: %w", err)
	}
	return *output.Account, nil
}

// GetAccountAlias returns the account alias if set.
func (c *AWSClient) GetAccountAlias(ctx context.Context) (*string, error) {
	iamClient := iam.NewFromConfig(c.cfg)
	output, err := iamClient.ListAccountAliases(ctx, &iam.ListAccountAliasesInput{})
	if err != nil {
		return nil, fmt.Errorf("listing account aliases: %w", err)
	}
	if len(output.AccountAliases) > 0 {
		return &output.AccountAliases[0], nil
	}
	return nil, nil
}

// GetEnabledRegions returns the list of enabled regions.
func (c *AWSClient) GetEnabledRegions(ctx context.Context) ([]string, error) {
	ec2Client := ec2.NewFromConfig(c.cfg)
	output, err := ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(false), // Only enabled regions
	})
	if err != nil {
		return nil, fmt.Errorf("describing regions: %w", err)
	}

	regions := make([]string, 0, len(output.Regions))
	for _, r := range output.Regions {
		regions = append(regions, *r.RegionName)
	}
	return regions, nil
}

// GetCredentialReport generates and retrieves the IAM credential report.
func (c *AWSClient) GetCredentialReport(ctx context.Context) (*CredentialReport, error) {
	iamClient := iam.NewFromConfig(c.cfg)

	// Generate the report (may need multiple attempts)
	for attempts := 0; attempts < 10; attempts++ {
		_, err := iamClient.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
		if err != nil {
			return nil, fmt.Errorf("generating credential report: %w", err)
		}

		// Wait for report to be ready
		time.Sleep(2 * time.Second)

		output, err := iamClient.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
		if err != nil {
			// Check if report is still being generated
			if strings.Contains(err.Error(), "ReportInProgress") ||
				strings.Contains(err.Error(), "ReportNotPresent") {
				continue
			}
			return nil, fmt.Errorf("getting credential report: %w", err)
		}

		return parseCredentialReport(output.Content)
	}

	return nil, fmt.Errorf("credential report generation timed out")
}

// parseCredentialReport parses the CSV credential report.
func parseCredentialReport(content []byte) (*CredentialReport, error) {
	reader := csv.NewReader(strings.NewReader(string(content)))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parsing CSV: %w", err)
	}

	if len(records) < 2 {
		return &CredentialReport{Users: []CredentialReportUser{}}, nil
	}

	// Parse header to get column indices
	header := records[0]
	colIndex := make(map[string]int)
	for i, col := range header {
		colIndex[col] = i
	}

	report := &CredentialReport{
		Users: make([]CredentialReportUser, 0, len(records)-1),
	}

	for _, row := range records[1:] {
		user := CredentialReportUser{
			User:             getCol(row, colIndex, "user"),
			ARN:              getCol(row, colIndex, "arn"),
			MFAActive:        getCol(row, colIndex, "mfa_active") == "true",
			PasswordEnabled:  getCol(row, colIndex, "password_enabled") == "true",
			AccessKey1Active: getCol(row, colIndex, "access_key_1_active") == "true",
			AccessKey2Active: getCol(row, colIndex, "access_key_2_active") == "true",
			Cert1Active:      getCol(row, colIndex, "cert_1_active") == "true",
			Cert2Active:      getCol(row, colIndex, "cert_2_active") == "true",
		}

		// Parse timestamps
		user.UserCreationTime = parseTime(getCol(row, colIndex, "user_creation_time"))
		user.PasswordLastUsed = parseTimePtr(getCol(row, colIndex, "password_last_used"))
		user.PasswordLastChanged = parseTimePtr(getCol(row, colIndex, "password_last_changed"))
		user.PasswordNextRotation = parseTimePtr(getCol(row, colIndex, "password_next_rotation"))
		user.AccessKey1LastRotated = parseTimePtr(getCol(row, colIndex, "access_key_1_last_rotated"))
		user.AccessKey1LastUsedDate = parseTimePtr(getCol(row, colIndex, "access_key_1_last_used_date"))
		user.AccessKey2LastRotated = parseTimePtr(getCol(row, colIndex, "access_key_2_last_rotated"))
		user.AccessKey2LastUsedDate = parseTimePtr(getCol(row, colIndex, "access_key_2_last_used_date"))
		user.Cert1LastRotated = parseTimePtr(getCol(row, colIndex, "cert_1_last_rotated"))
		user.Cert2LastRotated = parseTimePtr(getCol(row, colIndex, "cert_2_last_rotated"))

		user.AccessKey1LastUsedRegion = getCol(row, colIndex, "access_key_1_last_used_region")
		user.AccessKey1LastUsedService = getCol(row, colIndex, "access_key_1_last_used_service")
		user.AccessKey2LastUsedRegion = getCol(row, colIndex, "access_key_2_last_used_region")
		user.AccessKey2LastUsedService = getCol(row, colIndex, "access_key_2_last_used_service")

		report.Users = append(report.Users, user)
	}

	return report, nil
}

func getCol(row []string, colIndex map[string]int, name string) string {
	if idx, ok := colIndex[name]; ok && idx < len(row) {
		return row[idx]
	}
	return ""
}

func parseTime(s string) time.Time {
	if s == "" || s == "N/A" || s == "not_supported" || s == "no_information" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func parseTimePtr(s string) *time.Time {
	t := parseTime(s)
	if t.IsZero() {
		return nil
	}
	return &t
}

// GetPasswordPolicy returns the account password policy.
func (c *AWSClient) GetPasswordPolicy(ctx context.Context) (*PasswordPolicy, error) {
	iamClient := iam.NewFromConfig(c.cfg)
	output, err := iamClient.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		// NoSuchEntity means no policy is set
		if strings.Contains(err.Error(), "NoSuchEntity") {
			return nil, nil
		}
		return nil, fmt.Errorf("getting password policy: %w", err)
	}

	policy := output.PasswordPolicy
	pp := &PasswordPolicy{
		MinimumPasswordLength:      int(aws.ToInt32(policy.MinimumPasswordLength)),
		RequireSymbols:             policy.RequireSymbols,
		RequireNumbers:             policy.RequireNumbers,
		RequireUppercase:           policy.RequireUppercaseCharacters,
		RequireLowercase:           policy.RequireLowercaseCharacters,
		AllowUsersToChangePassword: policy.AllowUsersToChangePassword,
		ExpirePasswords:            policy.ExpirePasswords,
		HardExpiry:                 aws.ToBool(policy.HardExpiry),
	}

	if policy.MaxPasswordAge != nil && *policy.MaxPasswordAge > 0 {
		age := int(*policy.MaxPasswordAge)
		pp.MaxPasswordAge = &age
	}
	if policy.PasswordReusePrevention != nil && *policy.PasswordReusePrevention > 0 {
		reuse := int(*policy.PasswordReusePrevention)
		pp.PasswordReusePrevention = &reuse
	}

	return pp, nil
}

// ListRoles lists IAM roles and checks for external trust.
func (c *AWSClient) ListRoles(ctx context.Context, callback func([]Role) error) error {
	iamClient := iam.NewFromConfig(c.cfg)
	paginator := iam.NewListRolesPaginator(iamClient, &iam.ListRolesInput{})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("listing roles: %w", err)
		}

		roles := make([]Role, 0, len(output.Roles))
		for _, r := range output.Roles {
			role := Role{
				RoleName: aws.ToString(r.RoleName),
				ARN:      aws.ToString(r.Arn),
			}
			if r.AssumeRolePolicyDocument != nil {
				role.AssumeRolePolicyDocument = aws.ToString(r.AssumeRolePolicyDocument)
				// Check for external trust will be done by collector
			}
			roles = append(roles, role)
		}

		if err := callback(roles); err != nil {
			return err
		}
	}

	return nil
}

// ListBuckets lists all S3 buckets with their security settings.
func (c *AWSClient) ListBuckets(ctx context.Context) ([]Bucket, error) {
	s3Client := s3.NewFromConfig(c.cfg)
	output, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing buckets: %w", err)
	}

	buckets := make([]Bucket, 0, len(output.Buckets))
	for _, b := range output.Buckets {
		bucket := Bucket{
			Name: aws.ToString(b.Name),
		}

		// Get bucket location
		locOutput, err := s3Client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: b.Name,
		})
		if err == nil {
			bucket.Region = string(locOutput.LocationConstraint)
			if bucket.Region == "" {
				bucket.Region = "us-east-1"
			}
		}

		// Get public access block
		pabOutput, err := s3Client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: b.Name,
		})
		if err == nil && pabOutput.PublicAccessBlockConfiguration != nil {
			pab := pabOutput.PublicAccessBlockConfiguration
			bucket.PublicAccessBlocked = aws.ToBool(pab.BlockPublicAcls) &&
				aws.ToBool(pab.BlockPublicPolicy) &&
				aws.ToBool(pab.IgnorePublicAcls) &&
				aws.ToBool(pab.RestrictPublicBuckets)
		}

		// Get encryption
		encOutput, err := s3Client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: b.Name,
		})
		if err == nil && encOutput.ServerSideEncryptionConfiguration != nil {
			bucket.DefaultEncryptionEnabled = len(encOutput.ServerSideEncryptionConfiguration.Rules) > 0
		}

		// Get versioning
		verOutput, err := s3Client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: b.Name,
		})
		if err == nil {
			bucket.VersioningEnabled = verOutput.Status == "Enabled"
			bucket.MFADeleteEnabled = verOutput.MFADelete == "Enabled"
		}

		// Get logging
		logOutput, err := s3Client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{
			Bucket: b.Name,
		})
		if err == nil {
			bucket.LoggingEnabled = logOutput.LoggingEnabled != nil
		}

		// Get bucket policy and check for SSL requirement
		polOutput, err := s3Client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: b.Name,
		})
		if err == nil && polOutput.Policy != nil {
			// Simple check for SSL enforcement
			bucket.SSLOnlyPolicy = strings.Contains(*polOutput.Policy, "aws:SecureTransport") &&
				strings.Contains(*polOutput.Policy, "\"false\"")
		}

		buckets = append(buckets, bucket)
	}

	return buckets, nil
}

// GetAccountPublicAccessBlock checks if account-level public access block is enabled.
func (c *AWSClient) GetAccountPublicAccessBlock(ctx context.Context, accountID string) (bool, error) {
	s3ControlClient := s3control.NewFromConfig(c.cfg)
	output, err := s3ControlClient.GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{
		AccountId: aws.String(accountID),
	})
	if err != nil {
		// No configuration means not enabled
		return false, nil
	}

	if output.PublicAccessBlockConfiguration == nil {
		return false, nil
	}

	pab := output.PublicAccessBlockConfiguration
	return aws.ToBool(pab.BlockPublicAcls) &&
		aws.ToBool(pab.BlockPublicPolicy) &&
		aws.ToBool(pab.IgnorePublicAcls) &&
		aws.ToBool(pab.RestrictPublicBuckets), nil
}

// ListDBInstances lists RDS instances in the specified region.
func (c *AWSClient) ListDBInstances(ctx context.Context, region string) ([]DBInstance, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	rdsClient := rds.NewFromConfig(cfg)

	var instances []DBInstance
	paginator := rds.NewDescribeDBInstancesPaginator(rdsClient, &rds.DescribeDBInstancesInput{})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing DB instances: %w", err)
		}

		for _, db := range output.DBInstances {
			instances = append(instances, DBInstance{
				DBInstanceIdentifier:    aws.ToString(db.DBInstanceIdentifier),
				Engine:                  aws.ToString(db.Engine),
				EngineVersion:           aws.ToString(db.EngineVersion),
				PubliclyAccessible:      aws.ToBool(db.PubliclyAccessible),
				StorageEncrypted:        aws.ToBool(db.StorageEncrypted),
				DeletionProtection:      aws.ToBool(db.DeletionProtection),
				BackupRetentionPeriod:   int(aws.ToInt32(db.BackupRetentionPeriod)),
				MultiAZ:                 aws.ToBool(db.MultiAZ),
				AutoMinorVersionUpgrade: aws.ToBool(db.AutoMinorVersionUpgrade),
			})
		}
	}

	return instances, nil
}

// ListDBClusters lists RDS clusters in the specified region.
func (c *AWSClient) ListDBClusters(ctx context.Context, region string) ([]DBCluster, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	rdsClient := rds.NewFromConfig(cfg)

	var clusters []DBCluster
	paginator := rds.NewDescribeDBClustersPaginator(rdsClient, &rds.DescribeDBClustersInput{})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			// Some regions may not support clusters
			if strings.Contains(err.Error(), "not supported") {
				return clusters, nil
			}
			return nil, fmt.Errorf("describing DB clusters: %w", err)
		}

		for _, db := range output.DBClusters {
			clusters = append(clusters, DBCluster{
				DBClusterIdentifier:   aws.ToString(db.DBClusterIdentifier),
				Engine:                aws.ToString(db.Engine),
				EngineVersion:         aws.ToString(db.EngineVersion),
				StorageEncrypted:      aws.ToBool(db.StorageEncrypted),
				DeletionProtection:    aws.ToBool(db.DeletionProtection),
				BackupRetentionPeriod: int(aws.ToInt32(db.BackupRetentionPeriod)),
				MultiAZ:               aws.ToBool(db.MultiAZ),
			})
		}
	}

	return clusters, nil
}

// ListVPCs lists VPCs in the specified region with flow logs status.
func (c *AWSClient) ListVPCs(ctx context.Context, region string) ([]VPC, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	ec2Client := ec2.NewFromConfig(cfg)

	output, err := ec2Client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("describing VPCs: %w", err)
	}

	// Get flow logs for all VPCs
	flowLogsOutput, err := ec2Client.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{})
	flowLogVPCs := make(map[string]bool)
	if err == nil {
		for _, fl := range flowLogsOutput.FlowLogs {
			if fl.ResourceId != nil {
				flowLogVPCs[*fl.ResourceId] = true
			}
		}
	}

	vpcs := make([]VPC, 0, len(output.Vpcs))
	for _, v := range output.Vpcs {
		vpc := VPC{
			VPCID:           aws.ToString(v.VpcId),
			IsDefault:       aws.ToBool(v.IsDefault),
			FlowLogsEnabled: flowLogVPCs[aws.ToString(v.VpcId)],
		}
		vpcs = append(vpcs, vpc)
	}

	return vpcs, nil
}

// ListSecurityGroups lists security groups in the specified region.
func (c *AWSClient) ListSecurityGroups(ctx context.Context, region string) ([]SecurityGroup, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	ec2Client := ec2.NewFromConfig(cfg)

	var securityGroups []SecurityGroup
	paginator := ec2.NewDescribeSecurityGroupsPaginator(ec2Client, &ec2.DescribeSecurityGroupsInput{})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing security groups: %w", err)
		}

		for _, sg := range output.SecurityGroups {
			group := SecurityGroup{
				GroupID:   aws.ToString(sg.GroupId),
				GroupName: aws.ToString(sg.GroupName),
				VPCID:     aws.ToString(sg.VpcId),
				IsDefault: aws.ToString(sg.GroupName) == "default",
			}

			for _, perm := range sg.IpPermissions {
				rule := SecurityGroupRule{
					Protocol: aws.ToString(perm.IpProtocol),
					FromPort: int(aws.ToInt32(perm.FromPort)),
					ToPort:   int(aws.ToInt32(perm.ToPort)),
				}
				for _, ip := range perm.IpRanges {
					rule.CIDRBlocks = append(rule.CIDRBlocks, aws.ToString(ip.CidrIp))
				}
				for _, ip := range perm.Ipv6Ranges {
					rule.CIDRBlocks = append(rule.CIDRBlocks, aws.ToString(ip.CidrIpv6))
				}
				group.IngressRules = append(group.IngressRules, rule)
			}

			securityGroups = append(securityGroups, group)
		}
	}

	return securityGroups, nil
}

// DescribeTrails returns CloudTrail trails.
func (c *AWSClient) DescribeTrails(ctx context.Context) ([]Trail, error) {
	ctClient := cloudtrail.NewFromConfig(c.cfg)
	output, err := ctClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, fmt.Errorf("describing trails: %w", err)
	}

	trails := make([]Trail, 0, len(output.TrailList))
	for _, t := range output.TrailList {
		trail := Trail{
			Name:                      aws.ToString(t.Name),
			S3BucketName:              aws.ToString(t.S3BucketName),
			IsMultiRegionTrail:        aws.ToBool(t.IsMultiRegionTrail),
			LogFileValidationEnabled:  aws.ToBool(t.LogFileValidationEnabled),
			CloudWatchLogsLogGroupArn: t.CloudWatchLogsLogGroupArn,
			KMSKeyId:                  t.KmsKeyId,
		}

		// Get trail status
		status, err := ctClient.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: t.Name,
		})
		if err == nil {
			trail.IsLogging = aws.ToBool(status.IsLogging)
		}

		trails = append(trails, trail)
	}

	return trails, nil
}

// DescribeConfigRecorders returns AWS Config recorders in the specified region.
func (c *AWSClient) DescribeConfigRecorders(ctx context.Context, region string) ([]ConfigRecorder, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	configClient := configservice.NewFromConfig(cfg)

	output, err := configClient.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		return nil, fmt.Errorf("describing config recorders: %w", err)
	}

	// Get recorder status
	statusOutput, err := configClient.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{})
	statusMap := make(map[string]bool)
	if err == nil {
		for _, s := range statusOutput.ConfigurationRecordersStatus {
			statusMap[aws.ToString(s.Name)] = s.Recording
		}
	}

	recorders := make([]ConfigRecorder, 0, len(output.ConfigurationRecorders))
	for _, r := range output.ConfigurationRecorders {
		recorder := ConfigRecorder{
			Name:    aws.ToString(r.Name),
			RoleARN: aws.ToString(r.RoleARN),
		}
		if r.RecordingGroup != nil {
			recorder.AllSupported = r.RecordingGroup.AllSupported
			recorder.IncludeGlobal = r.RecordingGroup.IncludeGlobalResourceTypes
		}
		recorder.Recording = statusMap[recorder.Name]
		recorders = append(recorders, recorder)
	}

	return recorders, nil
}

// ListGuardDutyDetectors returns GuardDuty detectors in the specified region.
func (c *AWSClient) ListGuardDutyDetectors(ctx context.Context, region string) ([]GuardDutyDetector, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	gdClient := guardduty.NewFromConfig(cfg)

	listOutput, err := gdClient.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		// GuardDuty might not be enabled
		return nil, nil
	}

	detectors := make([]GuardDutyDetector, 0, len(listOutput.DetectorIds))
	for _, id := range listOutput.DetectorIds {
		getOutput, err := gdClient.GetDetector(ctx, &guardduty.GetDetectorInput{
			DetectorId: aws.String(id),
		})
		if err != nil {
			continue
		}

		detector := GuardDutyDetector{
			DetectorID:            id,
			Status:                string(getOutput.Status),
			FindingPublishingFreq: string(getOutput.FindingPublishingFrequency),
		}

		for _, feature := range getOutput.Features {
			switch feature.Name {
			case guarddutytypes.DetectorFeatureResultS3DataEvents:
				detector.S3LogsEnabled = feature.Status == guarddutytypes.FeatureStatusEnabled
			case guarddutytypes.DetectorFeatureResultEksAuditLogs:
				detector.EKSAuditLogsEnabled = feature.Status == guarddutytypes.FeatureStatusEnabled
			case guarddutytypes.DetectorFeatureResultEbsMalwareProtection:
				detector.MalwareScanEnabled = feature.Status == guarddutytypes.FeatureStatusEnabled
			}
		}

		unarchivedHighSeverityCriteria := map[string]guarddutytypes.Condition{
			"severity": {
				GreaterThanOrEqual: aws.Int64(7),
			},
			"service.archived": {
				Equals: []string{"false"},
			},
		}
		detector.HighOrCriticalFindings, _ = c.countGuardDutyFindings(ctx, gdClient, id, unarchivedHighSeverityCriteria)

		cutoffMillis := time.Now().Add(-48 * time.Hour).UnixMilli()
		staleHighSeverityCriteria := map[string]guarddutytypes.Condition{
			"severity": {
				GreaterThanOrEqual: aws.Int64(7),
			},
			"service.archived": {
				Equals: []string{"false"},
			},
			"updatedAt": {
				LessThanOrEqual: aws.Int64(cutoffMillis),
			},
		}
		detector.HighOrCriticalFindingsOlderThan48Hours, _ = c.countGuardDutyFindings(ctx, gdClient, id, staleHighSeverityCriteria)

		detectors = append(detectors, detector)
	}

	return detectors, nil
}

// countGuardDutyFindings counts findings matching the provided criteria.
func (c *AWSClient) countGuardDutyFindings(ctx context.Context, gdClient *guardduty.Client, detectorID string, criterion map[string]guarddutytypes.Condition) (int, error) {
	var count int
	var nextToken *string

	for {
		output, err := gdClient.ListFindings(ctx, &guardduty.ListFindingsInput{
			DetectorId: aws.String(detectorID),
			FindingCriteria: &guarddutytypes.FindingCriteria{
				Criterion: criterion,
			},
			MaxResults: aws.Int32(50),
			NextToken:  nextToken,
		})
		if err != nil {
			return count, err
		}

		count += len(output.FindingIds)
		if output.NextToken == nil || *output.NextToken == "" {
			break
		}
		nextToken = output.NextToken
	}

	return count, nil
}

// GetSecurityHubConfig returns Security Hub configuration in the specified region.
func (c *AWSClient) GetSecurityHubConfig(ctx context.Context, region string) (*SecurityHubConfig, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	shClient := securityhub.NewFromConfig(cfg)

	hubOutput, err := shClient.DescribeHub(ctx, &securityhub.DescribeHubInput{})
	if err != nil {
		// Security Hub not enabled
		return nil, nil
	}

	config := &SecurityHubConfig{
		Enabled:            true,
		AutoEnableControls: aws.ToBool(hubOutput.AutoEnableControls),
	}

	// Get enabled standards
	standardsOutput, err := shClient.GetEnabledStandards(ctx, &securityhub.GetEnabledStandardsInput{})
	if err == nil {
		for _, s := range standardsOutput.StandardsSubscriptions {
			config.StandardsARNs = append(config.StandardsARNs, aws.ToString(s.StandardsArn))
		}
	}

	// Get integrations
	integrationsOutput, err := shClient.ListEnabledProductsForImport(ctx, &securityhub.ListEnabledProductsForImportInput{})
	if err == nil {
		config.IntegrationCount = len(integrationsOutput.ProductSubscriptions)
		config.ProductSubscriptions = make([]string, 0, len(integrationsOutput.ProductSubscriptions))
		config.ProductSubscriptions = append(config.ProductSubscriptions, integrationsOutput.ProductSubscriptions...)
	}

	return config, nil
}

// GetSecurityHubCISComplianceByLevel returns control-level compliance counts for CIS levels 1, 2, and unknown.
func (c *AWSClient) GetSecurityHubCISComplianceByLevel(ctx context.Context, region, standardID string) (*SecurityHubCISComplianceByLevel, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	shClient := securityhub.NewFromConfig(cfg)

	filters := &securityhubtypes.AwsSecurityFindingFilters{
		ComplianceAssociatedStandardsId: []securityhubtypes.StringFilter{
			{
				Comparison: securityhubtypes.StringFilterComparisonEquals,
				Value:      aws.String(standardID),
			},
		},
	}

	paginator := securityhub.NewGetFindingsPaginator(shClient, &securityhub.GetFindingsInput{
		Filters:    filters,
		MaxResults: aws.Int32(100),
	})

	complianceByLevel := &SecurityHubCISComplianceByLevel{}
	levelStatuses := map[int]map[string]securityhubtypes.ComplianceStatus{
		0: {},
		1: {},
		2: {},
	}

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, nil
		}

		for _, finding := range output.Findings {
			if finding.Compliance == nil {
				continue
			}
			if finding.Compliance.Status == "" {
				continue
			}

			targetLevels := cisLevelsForFinding(finding.Compliance.RelatedRequirements)
			if len(targetLevels) == 0 {
				targetLevels = []int{0}
			}

			controlID := cisControlIDForFinding(finding)
			if controlID == "" {
				continue
			}

			for _, level := range targetLevels {
				current, exists := levelStatuses[level][controlID]
				if !exists || cisStatusSeverity(finding.Compliance.Status) > cisStatusSeverity(current) {
					levelStatuses[level][controlID] = finding.Compliance.Status
				}
			}
		}
	}

	for _, status := range levelStatuses[1] {
		switch status {
		case securityhubtypes.ComplianceStatusPassed:
			complianceByLevel.Level1.PassedControls++
		case securityhubtypes.ComplianceStatusFailed:
			complianceByLevel.Level1.FailedControls++
		case securityhubtypes.ComplianceStatusWarning:
			complianceByLevel.Level1.WarningControls++
		case securityhubtypes.ComplianceStatusNotAvailable:
			complianceByLevel.Level1.NotAvailableControls++
		}
	}

	for _, status := range levelStatuses[2] {
		switch status {
		case securityhubtypes.ComplianceStatusPassed:
			complianceByLevel.Level2.PassedControls++
		case securityhubtypes.ComplianceStatusFailed:
			complianceByLevel.Level2.FailedControls++
		case securityhubtypes.ComplianceStatusWarning:
			complianceByLevel.Level2.WarningControls++
		case securityhubtypes.ComplianceStatusNotAvailable:
			complianceByLevel.Level2.NotAvailableControls++
		}
	}
	for _, status := range levelStatuses[0] {
		switch status {
		case securityhubtypes.ComplianceStatusPassed:
			complianceByLevel.Unknown.PassedControls++
		case securityhubtypes.ComplianceStatusFailed:
			complianceByLevel.Unknown.FailedControls++
		case securityhubtypes.ComplianceStatusWarning:
			complianceByLevel.Unknown.WarningControls++
		case securityhubtypes.ComplianceStatusNotAvailable:
			complianceByLevel.Unknown.NotAvailableControls++
		}
	}

	return complianceByLevel, nil
}

func cisControlIDForFinding(finding securityhubtypes.AwsSecurityFinding) string {
	if finding.Compliance != nil && finding.Compliance.SecurityControlId != nil {
		id := strings.TrimSpace(aws.ToString(finding.Compliance.SecurityControlId))
		if id != "" {
			return id
		}
	}
	return strings.TrimSpace(aws.ToString(finding.GeneratorId))
}

func cisStatusSeverity(status securityhubtypes.ComplianceStatus) int {
	switch status {
	case securityhubtypes.ComplianceStatusFailed:
		return 4
	case securityhubtypes.ComplianceStatusWarning:
		return 3
	case securityhubtypes.ComplianceStatusPassed:
		return 2
	case securityhubtypes.ComplianceStatusNotAvailable:
		return 1
	default:
		return 0
	}
}

// cisLevelsForFinding infers benchmark levels from related requirements.
func cisLevelsForFinding(relatedRequirements []string) []int {
	var hasLevel1, hasLevel2 bool

	for _, requirement := range relatedRequirements {
		lower := strings.ToLower(requirement)
		if strings.Contains(lower, "level 2") || strings.Contains(lower, "level ii") {
			hasLevel2 = true
			continue
		}
		if strings.Contains(lower, "level 1") || strings.Contains(lower, "level i") {
			hasLevel1 = true
		}
	}

	if hasLevel1 {
		if hasLevel2 {
			return []int{1, 2}
		}
		return []int{1}
	}
	if hasLevel2 {
		return []int{2}
	}
	return nil
}

// GetInspectorSummaryFromSecurityHub returns Inspector patching metrics based on Security Hub findings.
func (c *AWSClient) GetInspectorSummaryFromSecurityHub(ctx context.Context, region string) (*InspectorSummary, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	shClient := securityhub.NewFromConfig(cfg)

	filters := &securityhubtypes.AwsSecurityFindingFilters{
		ProductName: []securityhubtypes.StringFilter{
			{
				Comparison: securityhubtypes.StringFilterComparisonPrefix,
				Value:      aws.String("Inspector"),
			},
		},
	}

	paginator := securityhub.NewGetFindingsPaginator(shClient, &securityhub.GetFindingsInput{
		Filters:    filters,
		MaxResults: aws.Int32(100),
	})

	summary := &InspectorSummary{}
	allResources := map[string]struct{}{}
	unpatchedResources := map[string]struct{}{}

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, nil
		}

		for _, finding := range output.Findings {
			summary.TotalFindings++
			summary.Enabled = true

			patched := isPatchedFinding(finding)
			if patched {
				summary.PatchedFindings++
			} else {
				summary.UnpatchedFindings++
			}

			for _, resource := range finding.Resources {
				resourceKey := inspectorServerResourceKey(resource)
				if resourceKey == "" {
					continue
				}
				allResources[resourceKey] = struct{}{}
				if !patched {
					unpatchedResources[resourceKey] = struct{}{}
				}
			}
		}
	}

	summary.TotalAffectedResources = len(allResources)
	summary.UnpatchedResources = len(unpatchedResources)

	return summary, nil
}

func isPatchedFinding(finding securityhubtypes.AwsSecurityFinding) bool {
	if finding.RecordState == securityhubtypes.RecordStateArchived {
		return true
	}
	if finding.Workflow == nil {
		return false
	}
	return finding.Workflow.Status == securityhubtypes.WorkflowStatusResolved ||
		finding.Workflow.Status == securityhubtypes.WorkflowStatusSuppressed
}

func inspectorServerResourceKey(resource securityhubtypes.Resource) string {
	if resource.Type == nil || resource.Id == nil {
		return ""
	}
	if *resource.Type != "AwsEc2Instance" {
		return ""
	}
	return *resource.Id
}

// ListAccessAnalyzers returns IAM Access Analyzer analyzers in the specified region.
func (c *AWSClient) ListAccessAnalyzers(ctx context.Context, region string) ([]AccessAnalyzer, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	aaClient := accessanalyzer.NewFromConfig(cfg)

	listOutput, err := aaClient.ListAnalyzers(ctx, &accessanalyzer.ListAnalyzersInput{})
	if err != nil {
		return nil, nil // Access Analyzer might not be available
	}

	analyzers := make([]AccessAnalyzer, 0, len(listOutput.Analyzers))
	for _, a := range listOutput.Analyzers {
		analyzer := AccessAnalyzer{
			Name:   aws.ToString(a.Name),
			ARN:    aws.ToString(a.Arn),
			Type:   string(a.Type),
			Status: string(a.Status),
		}

		// Get findings count
		findingsOutput, err := aaClient.ListFindings(ctx, &accessanalyzer.ListFindingsInput{
			AnalyzerArn: a.Arn,
		})
		if err == nil {
			analyzer.FindingsCount = len(findingsOutput.Findings)
		}

		analyzers = append(analyzers, analyzer)
	}

	return analyzers, nil
}
