package aws

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	configservice "github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	guarddutytypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	securityhubtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
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
	ListMFADevices(ctx context.Context, userName string) ([]MFADevice, error)
	GetPasswordPolicy(ctx context.Context) (*PasswordPolicy, error)
	ListRoles(ctx context.Context, callback func([]Role) error) error

	// S3
	ListBuckets(ctx context.Context) ([]Bucket, error)
	GetAccountPublicAccessBlock(ctx context.Context, accountID string) (bool, error)
	GetBucketPolicy(ctx context.Context, region, bucket string) (*BucketPolicy, error)
	GetBucketACL(ctx context.Context, region, bucket string) (*BucketACL, error)
	GetBucketLifecycle(ctx context.Context, region, bucket string) (*BucketLifecycle, error)

	// RDS (regional)
	ListDBInstances(ctx context.Context, region string) ([]DBInstance, error)
	ListDBClusters(ctx context.Context, region string) ([]DBCluster, error)

	// Network (regional)
	ListVPCs(ctx context.Context, region string) ([]VPC, error)
	ListSecurityGroups(ctx context.Context, region string) ([]SecurityGroup, error)

	// Account Security (regional for some)
	DescribeTrails(ctx context.Context) ([]Trail, error)
	DescribeConfigRecorders(ctx context.Context, region string) ([]ConfigRecorder, error)
	ListConfigRules(ctx context.Context, region string) ([]ConfigRule, error)
	ListGuardDutyDetectors(ctx context.Context, region string) ([]GuardDutyDetector, error)
	ListGuardDutyFindings(ctx context.Context, region, detectorID string, maxFindings int) ([]GuardDutyFinding, bool, error)
	GetSecurityHubConfig(ctx context.Context, region string) (*SecurityHubConfig, error)
	GetSecurityHubCISComplianceByLevel(ctx context.Context, region, standardID string) (*SecurityHubCISComplianceByLevel, error)
	GetInspectorSummaryFromSecurityHub(ctx context.Context, region string) (*InspectorSummary, error)
	ListAccessAnalyzers(ctx context.Context, region string) ([]AccessAnalyzer, error)

	// IAM Identity Center (one instance per account, regional). Caller is
	// expected to pass the home region; ListIdentityCenterInstances returns nil
	// for accounts where IdC is not enabled in that region.
	ListIdentityCenterInstances(ctx context.Context, region string) ([]IdentityCenterInstance, error)
	ListIdentityCenterPermissionSets(ctx context.Context, region, instanceARN string, withInternalEnrichment bool) ([]IdentityCenterPermissionSet, error)
	ListIdentityStoreUsers(ctx context.Context, region, identityStoreID string) ([]IdentityStoreUser, error)
	ListIdentityStoreGroups(ctx context.Context, region, identityStoreID string, withMemberCounts bool) ([]IdentityStoreGroup, error)

	// Lambda (regional). Base list returns posture metadata for every function;
	// per-function follow-up calls supply resource-policy presence and function-URL
	// auth-type, both of which require dedicated API calls.
	ListLambdaFunctions(ctx context.Context, region string) ([]LambdaFunction, error)
	LambdaFunctionHasResourcePolicy(ctx context.Context, region, functionName string) (bool, error)
	LambdaFunctionURLAuthType(ctx context.Context, region, functionName string) (hasURL bool, authType string, err error)

	// EC2 instances (regional). ListEC2Volumes returns a volumeID→encrypted
	// lookup so callers can enrich instances without holding the full Volume
	// objects (encryption is the only volume-level posture signal we use).
	ListEC2Instances(ctx context.Context, region string) ([]EC2Instance, error)
	ListEC2Volumes(ctx context.Context, region string) (map[string]bool, error)

	// CloudWatch Logs (regional). All posture-relevant metadata comes from the
	// single paginated DescribeLogGroups response; no per-group follow-up calls.
	ListCloudWatchLogGroups(ctx context.Context, region string) ([]CloudWatchLogGroup, error)

	// KMS (regional). Returns only CUSTOMER-managed keys; AWS-managed keys are
	// filtered out (no customer posture lever). Aliases come from a single
	// per-region ListAliases call, joined into the per-key metadata.
	ListKMSCustomerKeys(ctx context.Context, region string) ([]KMSKey, error)

	// Secrets Manager (regional). All posture-relevant metadata comes from
	// the single paginated ListSecrets call; secret VALUES are never read.
	ListSecretsManagerSecrets(ctx context.Context, region string) ([]SecretsManagerSecret, error)

	// SSM Parameter Store (regional). Paginated DescribeParameters returns all
	// metadata we need; parameter VALUES are never read (the value-reading APIs
	// GetParameter / GetParameters / GetParametersByPath are blocked by the
	// forbidden-API lint).
	ListSSMParameters(ctx context.Context, region string) ([]SSMParameter, error)
}

// AWSClient implements the Client interface using AWS SDK v2.
type AWSClient struct {
	cfg aws.Config
}

// Default regions per partition for STS and global services.
// STS requires a region to construct endpoints, even for global operations.
const (
	DefaultRegionAWS   = "us-east-1"
	DefaultRegionGov   = "us-gov-west-1"
	DefaultRegionChina = "cn-north-1"
)

// regionForRoleARN returns an appropriate default region based on the role ARN's partition.
// Falls back to us-east-1 for standard AWS or unrecognized ARNs.
func regionForRoleARN(roleARN string) string {
	if strings.HasPrefix(roleARN, "arn:aws-us-gov:") {
		return DefaultRegionGov
	}
	if strings.HasPrefix(roleARN, "arn:aws-cn:") {
		return DefaultRegionChina
	}
	return DefaultRegionAWS
}

// normalizeBucketRegion maps S3 location-constraint edge cases to SDK regions.
func normalizeBucketRegion(region string) string {
	switch region {
	case "":
		return DefaultRegionAWS
	case "EU":
		return "eu-west-1"
	default:
		return region
	}
}

// s3ConfigForRegion returns a copy of the client config pinned to the bucket region.
// Bucket-level S3 APIs must be called against the bucket's home region.
func (c *AWSClient) s3ConfigForRegion(region string) aws.Config {
	cfg := c.cfg.Copy()
	normalized := normalizeBucketRegion(region)
	if normalized != "" {
		cfg.Region = normalized
	}
	return cfg
}

// NewClient creates a new AWS client using the default credential chain.
// Falls back to us-east-1 if no region is configured. GovCloud/China users
// must configure AWS_REGION when using ambient credentials (no role ARN).
func NewClient(ctx context.Context) (*AWSClient, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	if cfg.Region == "" {
		cfg.Region = DefaultRegionAWS
	}
	return &AWSClient{cfg: cfg}, nil
}

// NewClientWithRole creates a new AWS client that assumes the specified role.
func NewClientWithRole(ctx context.Context, roleARN, externalID string) (*AWSClient, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	if cfg.Region == "" {
		cfg.Region = regionForRoleARN(roleARN)
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

// NewClientWithWebIdentity creates a new AWS client using web identity federation.
// The tokenSource must implement stscreds.IdentityTokenRetriever.
func NewClientWithWebIdentity(ctx context.Context, roleARN string, tokenSource stscreds.IdentityTokenRetriever) (*AWSClient, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	if cfg.Region == "" {
		cfg.Region = regionForRoleARN(roleARN)
	}

	stsClient := sts.NewFromConfig(cfg)
	creds := stscreds.NewWebIdentityRoleProvider(stsClient, roleARN, tokenSource, func(o *stscreds.WebIdentityRoleOptions) {
		o.Duration = 1 * time.Hour
	})

	cfg.Credentials = aws.NewCredentialsCache(creds)

	return &AWSClient{cfg: cfg}, nil
}

// tokenCacheTTL is how long to cache OIDC tokens before refetching.
// GitHub OIDC tokens typically expire in ~10-15 minutes.
// We use a shorter TTL to ensure tokens are fresh for multi-account runs.
const tokenCacheTTL = 5 * time.Minute

// GitHubOIDCTokenSource fetches OIDC tokens from GitHub Actions.
// It implements stscreds.IdentityTokenRetriever.
type GitHubOIDCTokenSource struct {
	// cachedToken holds a previously fetched token to avoid redundant requests.
	cachedToken string
	// cachedAt tracks when the token was cached for TTL-based refresh.
	cachedAt time.Time
}

// NewGitHubOIDCTokenSource creates a new token source for GitHub Actions OIDC.
func NewGitHubOIDCTokenSource() *GitHubOIDCTokenSource {
	return &GitHubOIDCTokenSource{}
}

// GetIdentityToken fetches an OIDC token from GitHub Actions with audience "sts.amazonaws.com".
// Returns the cached token if still valid, otherwise fetches a new one.
func (g *GitHubOIDCTokenSource) GetIdentityToken() ([]byte, error) {
	// Return cached token if still within TTL
	if g.cachedToken != "" && time.Since(g.cachedAt) < tokenCacheTTL {
		return []byte(g.cachedToken), nil
	}

	token, err := fetchGitHubOIDCToken()
	if err != nil {
		return nil, err
	}
	g.cachedToken = token
	g.cachedAt = time.Now()
	return []byte(token), nil
}

// fetchGitHubOIDCToken requests an OIDC token from GitHub Actions.
// Requires ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN env vars.
func fetchGitHubOIDCToken() (string, error) {
	requestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

	if requestURL == "" || requestToken == "" {
		return "", fmt.Errorf("GitHub Actions OIDC not available: ACTIONS_ID_TOKEN_REQUEST_URL or ACTIONS_ID_TOKEN_REQUEST_TOKEN not set")
	}

	// Add audience parameter for AWS STS using proper URL parsing
	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("parsing OIDC token request URL: %w", err)
	}
	query := parsedURL.Query()
	query.Set("audience", "sts.amazonaws.com")
	parsedURL.RawQuery = query.Encode()

	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		return "", fmt.Errorf("creating OIDC token request: %w", err)
	}
	req.Header.Set("Authorization", "bearer "+requestToken)
	req.Header.Set("Accept", "application/json; api-version=2.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting OIDC token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("OIDC token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("parsing OIDC token response: %w", err)
	}

	if result.Value == "" {
		return "", fmt.Errorf("OIDC token response missing 'value' field")
	}

	return result.Value, nil
}

// IsGitHubActionsOIDCAvailable returns true if running in GitHub Actions with OIDC enabled.
func IsGitHubActionsOIDCAvailable() bool {
	return os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" && os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != ""
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

// ListMFADevices returns MFA devices assigned to a specific IAM user.
func (c *AWSClient) ListMFADevices(ctx context.Context, userName string) ([]MFADevice, error) {
	iamClient := iam.NewFromConfig(c.cfg)
	paginator := iam.NewListMFADevicesPaginator(iamClient, &iam.ListMFADevicesInput{
		UserName: aws.String(userName),
	})

	var devices []MFADevice
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing MFA devices for %s: %w", userName, err)
		}

		for _, device := range output.MFADevices {
			devices = append(devices, MFADevice{
				UserName:     aws.ToString(device.UserName),
				SerialNumber: aws.ToString(device.SerialNumber),
				EnableDate:   aws.ToTime(device.EnableDate),
			})
		}
	}

	return devices, nil
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

		bucketClient := s3.NewFromConfig(c.s3ConfigForRegion(bucket.Region))

		// Get public access block
		pabOutput, err := bucketClient.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
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
		encOutput, err := bucketClient.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: b.Name,
		})
		if err == nil && encOutput.ServerSideEncryptionConfiguration != nil {
			bucket.DefaultEncryptionEnabled = len(encOutput.ServerSideEncryptionConfiguration.Rules) > 0
		}

		// Get versioning
		verOutput, err := bucketClient.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: b.Name,
		})
		if err == nil {
			bucket.VersioningEnabled = verOutput.Status == "Enabled"
			bucket.MFADeleteEnabled = verOutput.MFADelete == "Enabled"
		}

		// Get logging
		logOutput, err := bucketClient.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{
			Bucket: b.Name,
		})
		if err == nil {
			bucket.LoggingEnabled = logOutput.LoggingEnabled != nil
		}

		// Get bucket policy and check for SSL requirement
		polOutput, err := bucketClient.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
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

// GetBucketPolicy returns the bucket's policy document. Returns nil with no
// error when no policy is attached (NoSuchBucketPolicy).
func (c *AWSClient) GetBucketPolicy(ctx context.Context, region, bucket string) (*BucketPolicy, error) {
	s3Client := s3.NewFromConfig(c.s3ConfigForRegion(region))
	out, err := s3Client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(bucket)})
	if err != nil {
		if isAPIErrorCode(err, "NoSuchBucketPolicy") {
			return nil, nil
		}
		return nil, fmt.Errorf("getting bucket policy for %s: %w", bucket, err)
	}
	if out.Policy == nil {
		return nil, nil
	}
	return &BucketPolicy{Document: *out.Policy}, nil
}

// GetBucketACL returns the bucket's ACL. HasPublicGrant is computed from the
// grants list (any grant whose grantee URI is AllUsers or AuthenticatedUsers).
func (c *AWSClient) GetBucketACL(ctx context.Context, region, bucket string) (*BucketACL, error) {
	s3Client := s3.NewFromConfig(c.s3ConfigForRegion(region))
	out, err := s3Client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: aws.String(bucket)})
	if err != nil {
		return nil, fmt.Errorf("getting bucket ACL for %s: %w", bucket, err)
	}

	acl := &BucketACL{}
	if out.Owner != nil {
		acl.OwnerID = aws.ToString(out.Owner.ID)
	}
	for _, g := range out.Grants {
		grant := BucketACLGrant{Permission: string(g.Permission)}
		if g.Grantee != nil {
			grant.GranteeType = string(g.Grantee.Type)
			grant.GranteeURI = aws.ToString(g.Grantee.URI)
			grant.GranteeID = aws.ToString(g.Grantee.ID)
			if isPublicGranteeURI(grant.GranteeURI) {
				acl.HasPublicGrant = true
			}
		}
		acl.Grants = append(acl.Grants, grant)
	}
	return acl, nil
}

// GetBucketLifecycle returns the bucket's lifecycle configuration. Returns nil
// with no error when no lifecycle config is attached (NoSuchLifecycleConfiguration).
func (c *AWSClient) GetBucketLifecycle(ctx context.Context, region, bucket string) (*BucketLifecycle, error) {
	s3Client := s3.NewFromConfig(c.s3ConfigForRegion(region))
	out, err := s3Client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: aws.String(bucket)})
	if err != nil {
		if isAPIErrorCode(err, "NoSuchLifecycleConfiguration") {
			return nil, nil
		}
		return nil, fmt.Errorf("getting bucket lifecycle for %s: %w", bucket, err)
	}
	if len(out.Rules) == 0 {
		return &BucketLifecycle{}, nil
	}

	lc := &BucketLifecycle{Rules: make([]BucketLifecycleRule, 0, len(out.Rules))}
	for _, r := range out.Rules {
		lc.Rules = append(lc.Rules, toLifecycleRule(r))
	}
	return lc, nil
}

// toLifecycleRule projects an SDK lifecycle rule onto our normalized shape.
// Transitions and expirations are flattened to human-readable strings
// ("30d→STANDARD_IA", "365d", "2027-01-01") rather than the SDK's nested
// pointer types — consumers want forensic visibility, not editing primitives.
func toLifecycleRule(r s3types.LifecycleRule) BucketLifecycleRule {
	rule := BucketLifecycleRule{
		ID:     aws.ToString(r.ID),
		Status: string(r.Status),
	}
	if r.Filter != nil && r.Filter.Prefix != nil {
		rule.Prefix = aws.ToString(r.Filter.Prefix)
	}
	for _, tr := range r.Transitions {
		if s := formatLifecycleTransition(tr); s != "" {
			rule.Transitions = append(rule.Transitions, s)
		}
	}
	rule.Expiration = formatLifecycleExpiration(r.Expiration)
	return rule
}

func formatLifecycleTransition(tr s3types.Transition) string {
	if tr.Days != nil {
		return fmt.Sprintf("%dd→%s", *tr.Days, string(tr.StorageClass))
	}
	if tr.Date != nil {
		return fmt.Sprintf("%s→%s", tr.Date.Format("2006-01-02"), string(tr.StorageClass))
	}
	return ""
}

func formatLifecycleExpiration(exp *s3types.LifecycleExpiration) string {
	if exp == nil {
		return ""
	}
	if exp.Days != nil {
		return fmt.Sprintf("%dd", *exp.Days)
	}
	if exp.Date != nil {
		return exp.Date.Format("2006-01-02")
	}
	return ""
}

// isPublicGranteeURI returns true if the grantee URI targets one of S3's
// canonical "public" groups (AllUsers or AuthenticatedUsers).
func isPublicGranteeURI(uri string) bool {
	switch uri {
	case "http://acs.amazonaws.com/groups/global/AllUsers",
		"http://acs.amazonaws.com/groups/global/AuthenticatedUsers":
		return true
	}
	return false
}

// GetAccountPublicAccessBlock checks if account-level public access block is enabled.
func (c *AWSClient) GetAccountPublicAccessBlock(ctx context.Context, accountID string) (bool, error) {
	s3ControlClient := s3control.NewFromConfig(c.cfg)
	output, err := s3ControlClient.GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{
		AccountId: aws.String(accountID),
	})
	if err != nil {
		if isAPIErrorCode(err, "NoSuchPublicAccessBlockConfiguration") {
			return false, nil
		}
		return false, fmt.Errorf("getting account public access block: %w", err)
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
				LatestRestorableTime:    db.LatestRestorableTime,
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
				LatestRestorableTime:  db.LatestRestorableTime,
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
				for _, src := range perm.UserIdGroupPairs {
					if src.GroupId != nil {
						rule.SourceSGIDs = append(rule.SourceSGIDs, aws.ToString(src.GroupId))
					}
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
		if err != nil {
			return nil, fmt.Errorf("getting trail status for %s: %w", aws.ToString(t.Name), err)
		}
		trail.IsLogging = aws.ToBool(status.IsLogging)

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
	if len(output.ConfigurationRecorders) == 0 {
		return []ConfigRecorder{}, nil
	}

	// Get recorder status
	statusOutput, err := configClient.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{})
	if err != nil {
		return nil, fmt.Errorf("describing config recorder status: %w", err)
	}
	statusMap := make(map[string]bool)
	for _, s := range statusOutput.ConfigurationRecordersStatus {
		statusMap[aws.ToString(s.Name)] = s.Recording
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

// ListConfigRules returns AWS Config rules in the specified region paired with
// their most recent compliance state. Returns an empty slice if Config is not
// enabled in the region.
func (c *AWSClient) ListConfigRules(ctx context.Context, region string) ([]ConfigRule, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := configservice.NewFromConfig(cfg)

	rules, err := describeAllConfigRules(ctx, client)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return []ConfigRule{}, nil
	}

	complianceByRule, err := describeComplianceByConfigRule(ctx, client)
	if err != nil {
		return nil, err
	}
	lastEvalByRule, err := describeLastEvaluationByConfigRule(ctx, client)
	if err != nil {
		return nil, err
	}

	out := make([]ConfigRule, 0, len(rules))
	for _, r := range rules {
		name := aws.ToString(r.ConfigRuleName)
		row := ConfigRule{
			Name:            name,
			ARN:             aws.ToString(r.ConfigRuleArn),
			ComplianceState: complianceByRule[name],
			LastEvaluated:   lastEvalByRule[name],
		}
		if r.Source != nil {
			row.SourceOwner = string(r.Source.Owner)
			row.SourceIdentifier = aws.ToString(r.Source.SourceIdentifier)
		}
		out = append(out, row)
	}
	return out, nil
}

func describeAllConfigRules(ctx context.Context, client *configservice.Client) ([]configtypes.ConfigRule, error) {
	var rules []configtypes.ConfigRule
	var nextToken *string
	for {
		out, err := client.DescribeConfigRules(ctx, &configservice.DescribeConfigRulesInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("describing config rules: %w", err)
		}
		rules = append(rules, out.ConfigRules...)
		if out.NextToken == nil || *out.NextToken == "" {
			return rules, nil
		}
		nextToken = out.NextToken
	}
}

func describeComplianceByConfigRule(ctx context.Context, client *configservice.Client) (map[string]string, error) {
	out := map[string]string{}
	var nextToken *string
	for {
		resp, err := client.DescribeComplianceByConfigRule(ctx, &configservice.DescribeComplianceByConfigRuleInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("describing config rule compliance: %w", err)
		}
		for _, c := range resp.ComplianceByConfigRules {
			name := aws.ToString(c.ConfigRuleName)
			if c.Compliance != nil {
				out[name] = string(c.Compliance.ComplianceType)
			}
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return out, nil
		}
		nextToken = resp.NextToken
	}
}

// describeLastEvaluationByConfigRule returns the most recent evaluation
// timestamp per rule, preferring success over failure when both exist.
func describeLastEvaluationByConfigRule(ctx context.Context, client *configservice.Client) (map[string]*time.Time, error) {
	out := map[string]*time.Time{}
	var nextToken *string
	for {
		resp, err := client.DescribeConfigRuleEvaluationStatus(ctx, &configservice.DescribeConfigRuleEvaluationStatusInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("describing config rule evaluation status: %w", err)
		}
		for _, s := range resp.ConfigRulesEvaluationStatus {
			name := aws.ToString(s.ConfigRuleName)
			switch {
			case s.LastSuccessfulEvaluationTime != nil:
				out[name] = s.LastSuccessfulEvaluationTime
			case s.LastFailedEvaluationTime != nil:
				out[name] = s.LastFailedEvaluationTime
			}
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return out, nil
		}
		nextToken = resp.NextToken
	}
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

// ListGuardDutyFindings returns up to maxFindings unarchived high-or-critical
// (severity >= 7) findings for the given detector. The boolean return is true
// when more findings exist than maxFindings (the caller should record a
// truncation warning). Sorted by severity DESC then updatedAt DESC so a
// truncated result keeps the most actionable findings.
func (c *AWSClient) ListGuardDutyFindings(ctx context.Context, region, detectorID string, maxFindings int) ([]GuardDutyFinding, bool, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	gdClient := guardduty.NewFromConfig(cfg)

	criterion := map[string]guarddutytypes.Condition{
		"severity":         {GreaterThanOrEqual: aws.Int64(7)},
		"service.archived": {Equals: []string{"false"}},
	}

	ids, truncated, err := listGuardDutyFindingIDs(ctx, gdClient, detectorID, criterion, maxFindings)
	if err != nil {
		return nil, false, err
	}
	if len(ids) == 0 {
		return []GuardDutyFinding{}, false, nil
	}

	findings, err := getGuardDutyFindings(ctx, gdClient, detectorID, ids)
	if err != nil {
		return nil, false, err
	}
	return findings, truncated, nil
}

func listGuardDutyFindingIDs(ctx context.Context, gdClient *guardduty.Client, detectorID string, criterion map[string]guarddutytypes.Condition, max int) ([]string, bool, error) {
	var ids []string
	var nextToken *string
	for {
		output, err := gdClient.ListFindings(ctx, &guardduty.ListFindingsInput{
			DetectorId: aws.String(detectorID),
			FindingCriteria: &guarddutytypes.FindingCriteria{
				Criterion: criterion,
			},
			SortCriteria: &guarddutytypes.SortCriteria{
				AttributeName: aws.String("severity"),
				OrderBy:       guarddutytypes.OrderByDesc,
			},
			MaxResults: aws.Int32(50),
			NextToken:  nextToken,
		})
		if err != nil {
			return nil, false, err
		}
		ids = append(ids, output.FindingIds...)
		if len(ids) >= max {
			return ids[:max], output.NextToken != nil && *output.NextToken != "", nil
		}
		if output.NextToken == nil || *output.NextToken == "" {
			return ids, false, nil
		}
		nextToken = output.NextToken
	}
}

func getGuardDutyFindings(ctx context.Context, gdClient *guardduty.Client, detectorID string, ids []string) ([]GuardDutyFinding, error) {
	const batch = 50
	out := make([]GuardDutyFinding, 0, len(ids))
	for start := 0; start < len(ids); start += batch {
		end := start + batch
		if end > len(ids) {
			end = len(ids)
		}
		resp, err := gdClient.GetFindings(ctx, &guardduty.GetFindingsInput{
			DetectorId: aws.String(detectorID),
			FindingIds: ids[start:end],
		})
		if err != nil {
			return nil, fmt.Errorf("getting GuardDuty findings: %w", err)
		}
		for _, f := range resp.Findings {
			out = append(out, projectGuardDutyFinding(f, detectorID))
		}
	}
	return out, nil
}

func projectGuardDutyFinding(f guarddutytypes.Finding, detectorID string) GuardDutyFinding {
	row := GuardDutyFinding{
		ID:         aws.ToString(f.Id),
		DetectorID: detectorID,
		Severity:   aws.ToFloat64(f.Severity),
		Type:       aws.ToString(f.Type),
		Title:      aws.ToString(f.Title),
	}
	if f.Resource != nil {
		row.ResourceType = aws.ToString(f.Resource.ResourceType)
		if id := guardDutyResourceID(f.Resource); id != "" {
			row.ResourceID = id
		}
	}
	if ts := parseGuardDutyTime(aws.ToString(f.CreatedAt)); ts != nil {
		row.CreatedAt = ts
	}
	if ts := parseGuardDutyTime(aws.ToString(f.UpdatedAt)); ts != nil {
		row.UpdatedAt = ts
	}
	return row
}

// guardDutyResourceID extracts the most identifying ID from a finding's
// Resource block. GuardDuty's schema varies per resource type, so this picks
// the field most operators expect to see in a triage row.
func guardDutyResourceID(r *guarddutytypes.Resource) string {
	if r.InstanceDetails != nil && r.InstanceDetails.InstanceId != nil {
		return aws.ToString(r.InstanceDetails.InstanceId)
	}
	if r.AccessKeyDetails != nil && r.AccessKeyDetails.UserName != nil {
		return aws.ToString(r.AccessKeyDetails.UserName)
	}
	if len(r.S3BucketDetails) > 0 && r.S3BucketDetails[0].Name != nil {
		return aws.ToString(r.S3BucketDetails[0].Name)
	}
	if r.EksClusterDetails != nil && r.EksClusterDetails.Name != nil {
		return aws.ToString(r.EksClusterDetails.Name)
	}
	if r.KubernetesDetails != nil && r.KubernetesDetails.KubernetesWorkloadDetails != nil {
		return aws.ToString(r.KubernetesDetails.KubernetesWorkloadDetails.Name)
	}
	return ""
}

// parseGuardDutyTime parses the ISO8601 timestamps GuardDuty returns as
// strings (not native time.Time). Returns nil on unparseable input so callers
// can omit the field entirely rather than emit a zero-valued timestamp.
func parseGuardDutyTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t, err = time.Parse(time.RFC3339, s)
		if err != nil {
			return nil
		}
	}
	return &t
}

// GetSecurityHubConfig returns Security Hub configuration in the specified region.
func (c *AWSClient) GetSecurityHubConfig(ctx context.Context, region string) (*SecurityHubConfig, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	shClient := securityhub.NewFromConfig(cfg)

	hubOutput, err := shClient.DescribeHub(ctx, &securityhub.DescribeHubInput{})
	if err != nil {
		if isAPIErrorCode(err, "ResourceNotFoundException") {
			return nil, nil
		}
		return nil, fmt.Errorf("describing Security Hub: %w", err)
	}

	config := &SecurityHubConfig{
		Enabled:            true,
		AutoEnableControls: aws.ToBool(hubOutput.AutoEnableControls),
	}

	// Get enabled standards
	standardsOutput, err := shClient.GetEnabledStandards(ctx, &securityhub.GetEnabledStandardsInput{})
	if err != nil {
		return nil, fmt.Errorf("getting enabled Security Hub standards: %w", err)
	}
	for _, s := range standardsOutput.StandardsSubscriptions {
		config.StandardsARNs = append(config.StandardsARNs, aws.ToString(s.StandardsArn))
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
			return nil, fmt.Errorf("getting Security Hub findings for %s: %w", standardID, err)
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
			return nil, fmt.Errorf("getting Inspector findings from Security Hub: %w", err)
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
		return nil, fmt.Errorf("listing access analyzers: %w", err)
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

func isAPIErrorCode(err error, code string) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == code
}
