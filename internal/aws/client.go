package aws

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
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
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	configservice "github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	guarddutytypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	securityhubtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	"github.com/locktivity/epack/componentsdk"
)

// Client provides access to AWS APIs.
type Client interface {
	// GetCallerIdentity returns the account and principal of the current
	// credentials.
	GetCallerIdentity(ctx context.Context) (CallerIdentity, error)

	// GetAccountAlias returns the account alias if set.
	GetAccountAlias(ctx context.Context) (*string, error)

	// GetEnabledRegions returns the list of enabled regions.
	GetEnabledRegions(ctx context.Context) ([]string, error)

	// IAM
	GetCredentialReport(ctx context.Context) (*CredentialReport, error)
	GetAccountSummary(ctx context.Context) (*AccountSummary, error)
	ListOrganizationsFeatures(ctx context.Context) (*OrganizationFeatures, error)
	ListMFADevices(ctx context.Context, userName string) ([]MFADevice, error)
	GetPasswordPolicy(ctx context.Context) (*PasswordPolicy, error)
	ListRoles(ctx context.Context, callback func([]Role) error) error

	// S3
	ListBuckets(ctx context.Context) ([]Bucket, error)
	GetAccountPublicAccessBlock(ctx context.Context, accountID string) (PublicAccessBlockSettings, error)
	GetBucketPolicy(ctx context.Context, region, bucket string) (*BucketPolicy, error)
	GetBucketACL(ctx context.Context, region, bucket string) (*BucketACL, error)
	GetBucketLifecycle(ctx context.Context, region, bucket string) (*BucketLifecycle, error)

	// RDS (regional)
	ListDBInstances(ctx context.Context, region string) ([]DBInstance, error)
	ListDBClusters(ctx context.Context, region string) ([]DBCluster, error)

	// Network (regional)
	ListVPCs(ctx context.Context, region string, includeFlowLogs bool) ([]VPC, error)
	ListSecurityGroups(ctx context.Context, region string) ([]SecurityGroup, error)
	ListSecurityGroupsByID(ctx context.Context, region string, groupIDs []string) ([]SecurityGroup, error)

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
	ListIdentityStoreGroups(ctx context.Context, region, identityStoreID string) ([]IdentityStoreGroup, error)
	ListIdentityStoreGroupMembers(ctx context.Context, region, identityStoreID string, groups []IdentityStoreGroup) ([]IdentityStoreGroup, error)

	// Lambda (regional). Base list returns posture metadata for every function;
	// per-function follow-up calls supply resource-policy presence and function-URL
	// auth-type, both of which require dedicated API calls.
	ListLambdaFunctions(ctx context.Context, region string) ([]LambdaFunction, error)
	LambdaFunctionHasResourcePolicy(ctx context.Context, region, functionName string) (bool, error)
	LambdaFunctionURLAuthType(ctx context.Context, region, functionName string) (hasURL bool, authType string, err error)

	// EC2 instances (regional). ListEC2Volumes returns a volumeID→state
	// lookup so callers can enrich instances without holding the full Volume
	// objects (encryption is the only volume-level posture signal we use).
	ListEC2Instances(ctx context.Context, region string) ([]EC2Instance, error)
	ListEC2Volumes(ctx context.Context, region string) (map[string]EBSVolumeState, error)

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
	cfg        aws.Config
	authMethod string
	now        func() time.Time
	sleep      func(context.Context, time.Duration) error
}

// Options configures a client.
type Options struct {
	// HTTPClient sends every call the client makes. Nil keeps the SDK's own
	// HTTP client and retries.
	HTTPClient *http.Client

	// Now is the run's clock, which ages are measured against. It defaults
	// to time.Now.
	Now func() time.Time

	// Wait pauses between polls of a report AWS builds in the background. It
	// defaults to sleeping until d passes or ctx is done.
	Wait func(ctx context.Context, d time.Duration) error
}

func newAWSClient(cfg aws.Config, authMethod string, opts Options) *AWSClient {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	wait := opts.Wait
	if wait == nil {
		wait = sleepContext
	}
	return &AWSClient{cfg: cfg, authMethod: authMethod, now: now, sleep: wait}
}

// AuthMethod returns how the client's credentials prove who the collector
// is, as a componentsdk sign-in method: AuthWorkloadIdentity for a role
// assumed with a web identity token, AuthAccessKey for static access keys,
// or "" for any other source, such as IAM Identity Center or an instance
// role.
func (c *AWSClient) AuthMethod() string {
	return c.authMethod
}

// authMethodOf reads how credentials from the SDK's default chain sign in
// from the sources the SDK records for them, which needs no call to AWS. A
// role assumed with static keys signs in with the keys, and one assumed
// with a web identity token in the environment signs in with the token.
func authMethodOf(creds aws.CredentialsProvider) string {
	provider, ok := creds.(aws.CredentialProviderSource)
	if !ok {
		return ""
	}
	sources := provider.ProviderSources()
	for _, s := range sources {
		switch s {
		case aws.CredentialSourceSTSAssumeRoleWebID, aws.CredentialSourceEnvVarsSTSWebIDToken, aws.CredentialSourceProfileSTSWebIDToken:
			return componentsdk.AuthWorkloadIdentity
		}
	}
	for _, s := range sources {
		switch s {
		case aws.CredentialSourceEnvVars, aws.CredentialSourceProfile, aws.CredentialSourceCode:
			return componentsdk.AuthAccessKey
		}
	}
	return ""
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
func NewClient(ctx context.Context, opts Options) (*AWSClient, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	if cfg.Region == "" {
		cfg.Region = DefaultRegionAWS
	}
	useTransport(&cfg, opts.HTTPClient)
	return newAWSClient(cfg, authMethodOf(cfg.Credentials), opts), nil
}

// NewClientWithRole creates a new AWS client that assumes the specified role.
func NewClientWithRole(ctx context.Context, roleARN, externalID string, opts Options) (*AWSClient, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	if cfg.Region == "" {
		cfg.Region = regionForRoleARN(roleARN)
	}
	useTransport(&cfg, opts.HTTPClient)
	authMethod := authMethodOf(cfg.Credentials)

	stsClient := sts.NewFromConfig(cfg)
	creds := stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(o *stscreds.AssumeRoleOptions) {
		if externalID != "" {
			o.ExternalID = &externalID
		}
		o.Duration = 1 * time.Hour
	})

	cfg.Credentials = aws.NewCredentialsCache(creds)

	return newAWSClient(cfg, authMethod, opts), nil
}

// NewClientWithWebIdentity creates a new AWS client using web identity federation.
// The tokenSource must implement stscreds.IdentityTokenRetriever.
func NewClientWithWebIdentity(ctx context.Context, roleARN string, tokenSource stscreds.IdentityTokenRetriever, opts Options) (*AWSClient, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	if cfg.Region == "" {
		cfg.Region = regionForRoleARN(roleARN)
	}
	useTransport(&cfg, opts.HTTPClient)

	stsClient := sts.NewFromConfig(cfg)
	creds := stscreds.NewWebIdentityRoleProvider(stsClient, roleARN, tokenSource, func(o *stscreds.WebIdentityRoleOptions) {
		o.Duration = 1 * time.Hour
	})

	cfg.Credentials = aws.NewCredentialsCache(creds)

	return newAWSClient(cfg, componentsdk.AuthWorkloadIdentity, opts), nil
}

// tokenCacheTTL is how long to cache OIDC tokens before refetching.
// GitHub OIDC tokens typically expire in ~10-15 minutes.
// We use a shorter TTL to ensure tokens are fresh for multi-account runs.
const tokenCacheTTL = 5 * time.Minute

// Environment variables OIDC mode reads its identity token from.
const (
	GitHubTokenRequestURLEnv   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	GitHubTokenRequestTokenEnv = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"

	// WebIdentityTokenFileEnv names the file a CI job or a workload identity
	// writes the run's identity token to. It is the variable the SDK's own
	// default chain reads for the same purpose.
	WebIdentityTokenFileEnv = "AWS_WEB_IDENTITY_TOKEN_FILE"
)

// OIDCEnv holds the values of the variables OIDC mode reads.
type OIDCEnv struct {
	RequestURL   string
	RequestToken string
	TokenFile    string
}

// GitHubAvailable reports whether the run is a GitHub Actions job with
// identity tokens enabled.
func (e OIDCEnv) GitHubAvailable() bool {
	return e.RequestURL != "" && e.RequestToken != ""
}

// CredentialHost returns the host of GitHub's token endpoint, which receives
// the request token, or "" when the run does not use it.
func (e OIDCEnv) CredentialHost() string {
	if !e.GitHubAvailable() {
		return ""
	}
	u, err := url.Parse(e.RequestURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// TokenSource returns the identity token source for OIDC mode: GitHub
// Actions' token endpoint when the workflow exposes one, otherwise the token
// file. Nil when neither is available. GitHub's endpoint is called through
// client with ctx.
func (e OIDCEnv) TokenSource(ctx context.Context, client *http.Client) stscreds.IdentityTokenRetriever {
	if e.GitHubAvailable() {
		return NewGitHubOIDCTokenSource(ctx, client, e.RequestURL, e.RequestToken)
	}
	if e.TokenFile != "" {
		return NewFileTokenSource(e.TokenFile)
	}
	return nil
}

// GitHubOIDCTokenSource fetches OIDC tokens from GitHub Actions.
// It implements stscreds.IdentityTokenRetriever.
type GitHubOIDCTokenSource struct {
	ctx          context.Context
	client       *http.Client
	requestURL   string
	requestToken string

	// cachedToken holds a previously fetched token to avoid redundant requests.
	cachedToken string
	// cachedAt tracks when the token was cached for TTL-based refresh.
	cachedAt time.Time
}

// NewGitHubOIDCTokenSource creates a token source that asks GitHub's token
// endpoint through client. A nil client uses http.DefaultClient.
func NewGitHubOIDCTokenSource(ctx context.Context, client *http.Client, requestURL, requestToken string) *GitHubOIDCTokenSource {
	if client == nil {
		client = http.DefaultClient
	}
	return &GitHubOIDCTokenSource{ctx: ctx, client: client, requestURL: requestURL, requestToken: requestToken}
}

// GetIdentityToken fetches an OIDC token from GitHub Actions with audience "sts.amazonaws.com".
// Returns the cached token if still valid, otherwise fetches a new one.
func (g *GitHubOIDCTokenSource) GetIdentityToken() ([]byte, error) {
	// Return cached token if still within TTL
	if g.cachedToken != "" && time.Since(g.cachedAt) < tokenCacheTTL {
		return []byte(g.cachedToken), nil
	}

	token, err := g.fetch()
	if err != nil {
		return nil, err
	}
	g.cachedToken = token
	g.cachedAt = time.Now()
	return []byte(token), nil
}

// fetch requests an OIDC token from GitHub Actions.
func (g *GitHubOIDCTokenSource) fetch() (string, error) {
	if g.requestURL == "" || g.requestToken == "" {
		return "", componentsdk.CodeError(componentsdk.CodeConfigInvalid, fmt.Errorf("GitHub Actions OIDC not available: %s or %s not set", GitHubTokenRequestURLEnv, GitHubTokenRequestTokenEnv))
	}

	// Add audience parameter for AWS STS using proper URL parsing
	parsedURL, err := url.Parse(g.requestURL)
	if err != nil {
		return "", componentsdk.CodeError(componentsdk.CodeConfigInvalid, fmt.Errorf("parsing OIDC token request URL: %w", err))
	}
	query := parsedURL.Query()
	query.Set("audience", "sts.amazonaws.com")
	parsedURL.RawQuery = query.Encode()

	ctx := g.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = componentsdk.WithOperation(ctx, componentsdk.Operation{Name: GitHubTokenOperation})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return "", fmt.Errorf("creating OIDC token request: %w", err)
	}
	req.Header.Set("Authorization", "bearer "+g.requestToken)
	req.Header.Set("Accept", "application/json; api-version=2.0")

	resp, err := g.client.Do(req)
	if err != nil {
		// The request URL is a secret of the CI job, and url.Error prints it.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return "", fmt.Errorf("requesting OIDC token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", componentsdk.CodeError(componentsdk.ClassifyResponse(resp), fmt.Errorf("OIDC token request failed with status %d", resp.StatusCode))
	}

	var result struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("parsing OIDC token response: %w", err)
	}

	if result.Value == "" {
		return "", componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("OIDC token response missing 'value' field"))
	}

	return result.Value, nil
}

// GitHubTokenOperation names the call to GitHub's identity token endpoint.
const GitHubTokenOperation = "github.id_token.get"

// FileTokenSource reads an identity token from a file on every call, so a
// job that refreshes the file during a long run is picked up.
// It implements stscreds.IdentityTokenRetriever.
type FileTokenSource struct {
	path string
}

// NewFileTokenSource creates a token source that reads the given file.
func NewFileTokenSource(path string) *FileTokenSource {
	return &FileTokenSource{path: path}
}

// GetIdentityToken reads the token, trimmed of surrounding whitespace.
func (f *FileTokenSource) GetIdentityToken() ([]byte, error) {
	if f.path == "" {
		return nil, fmt.Errorf("web identity token file not set: %s is empty", WebIdentityTokenFileEnv)
	}
	token, err := os.ReadFile(f.path)
	if err != nil {
		return nil, fmt.Errorf("reading web identity token file %s (%s): %w", f.path, WebIdentityTokenFileEnv, err)
	}
	token = bytes.TrimSpace(token)
	if len(token) == 0 {
		return nil, fmt.Errorf("web identity token file %s (%s) is empty", f.path, WebIdentityTokenFileEnv)
	}
	return token, nil
}

// CallerIdentity is the account and principal a client's credentials belong
// to.
type CallerIdentity struct {
	Account string
	ARN     string
}

// GetCallerIdentity returns the account and principal of the current
// credentials.
func (c *AWSClient) GetCallerIdentity(ctx context.Context) (CallerIdentity, error) {
	stsClient := sts.NewFromConfig(c.cfg)
	output, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return CallerIdentity{}, fmt.Errorf("getting caller identity: %w", err)
	}
	if output.Account == nil || *output.Account == "" {
		return CallerIdentity{}, errMissing(output.ResultMetadata, "getting caller identity", "Account")
	}
	return CallerIdentity{Account: *output.Account, ARN: aws.ToString(output.Arn)}, nil
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

// GetAccountSummary returns IAM account-level summary flags.
func (c *AWSClient) GetAccountSummary(ctx context.Context) (*AccountSummary, error) {
	iamClient := iam.NewFromConfig(c.cfg)
	output, err := iamClient.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, fmt.Errorf("getting IAM account summary: %w", err)
	}
	if output.SummaryMap == nil {
		return nil, errMissing(output.ResultMetadata, "getting IAM account summary", "SummaryMap")
	}
	return accountSummaryFromMap(output.SummaryMap), nil
}

func accountSummaryFromMap(summary map[string]int32) *AccountSummary {
	return &AccountSummary{
		AccountMFAEnabled:                 summaryValueEnabled(summary, "AccountMFAEnabled"),
		AccountPasswordPresent:            summaryValueEnabled(summary, "AccountPasswordPresent"),
		AccountAccessKeysPresent:          summaryValueEnabled(summary, "AccountAccessKeysPresent"),
		AccountSigningCertificatesPresent: summaryValueEnabled(summary, "AccountSigningCertificatesPresent"),
	}
}

func summaryValueEnabled(summary map[string]int32, key string) bool {
	return summary[key] > 0
}

// ListOrganizationsFeatures returns IAM centralized root access features
// enabled for the current organization.
func (c *AWSClient) ListOrganizationsFeatures(ctx context.Context) (*OrganizationFeatures, error) {
	iamClient := iam.NewFromConfig(c.cfg)
	output, err := iamClient.ListOrganizationsFeatures(ctx, &iam.ListOrganizationsFeaturesInput{})
	if err != nil {
		return nil, fmt.Errorf("listing IAM organizations features: %w", err)
	}
	return organizationFeaturesFromList(aws.ToString(output.OrganizationId), output.EnabledFeatures), nil
}

func organizationFeaturesFromList(organizationID string, features []iamtypes.FeatureType) *OrganizationFeatures {
	out := &OrganizationFeatures{OrganizationID: organizationID}
	for _, feature := range features {
		switch feature {
		case iamtypes.FeatureTypeRootCredentialsManagement:
			out.RootCredentialsManagementFeatureEnabled = true
		case iamtypes.FeatureTypeRootSessions:
			out.RootSessionsFeatureEnabled = true
		}
	}
	return out
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
	// An account always has enabled regions, so an empty list is not an
	// answer. Read as one, it would leave every regional surface empty.
	if len(output.Regions) == 0 {
		return nil, errMissing(output.ResultMetadata, "describing regions", "Regions")
	}

	regions := make([]string, 0, len(output.Regions))
	for _, r := range output.Regions {
		if aws.ToString(r.RegionName) == "" {
			return nil, errMissing(output.ResultMetadata, "describing regions", "RegionName")
		}
		regions = append(regions, *r.RegionName)
	}
	return regions, nil
}

// ErrCredentialReportTimeout is returned when the IAM credential report is
// still not ready after the full polling budget. Callers use errors.Is to
// distinguish this transient condition from a real API failure.
var ErrCredentialReportTimeout = componentsdk.CodeError(componentsdk.CodeTimeout, errors.New("credential report generation timed out"))

// credentialReportBudget bounds the waiting per account. Accounts are
// collected sequentially under the SDK's global run timeout, so the budget
// must leave room for every configured account plus the rest of collection.
const (
	credentialReportBaseDelay = 2 * time.Second
	credentialReportMaxDelay  = 10 * time.Second
	credentialReportBudget    = 45 * time.Second
)

// credentialReportAPI is the slice of the IAM API used by the credential
// report polling loop, extracted so the loop can be tested without AWS.
type credentialReportAPI interface {
	GenerateCredentialReport(ctx context.Context, params *iam.GenerateCredentialReportInput, optFns ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error)
	GetCredentialReport(ctx context.Context, params *iam.GetCredentialReportInput, optFns ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error)
}

// GetCredentialReport generates and retrieves the IAM credential report.
func (c *AWSClient) GetCredentialReport(ctx context.Context) (*CredentialReport, error) {
	return getCredentialReport(ctx, iam.NewFromConfig(c.cfg), credentialReportWaits(credentialReportBaseDelay, credentialReportBudget), c.sleep)
}

// credentialReportWaits returns the waits between polls, doubling from base
// up to credentialReportMaxDelay until they add up to budget.
func credentialReportWaits(base, budget time.Duration) []time.Duration {
	var waits []time.Duration
	var total time.Duration
	for delay := base; total < budget; delay = min(delay*2, credentialReportMaxDelay) {
		wait := min(delay, budget-total)
		waits = append(waits, wait)
		total += wait
	}
	return waits
}

// getCredentialReport polls until the report is ready. Report generation is
// asynchronous on the AWS side; regenerating while a report is in progress is
// a no-op, and ReportNotPresent / ReportExpired require a fresh
// GenerateCredentialReport call, so the generate call stays inside the loop.
// The first read follows at once when AWS reports a recent report complete;
// every other read follows the next of waits, and polling stops when waits
// run out.
func getCredentialReport(ctx context.Context, api credentialReportAPI, waits []time.Duration, sleep func(context.Context, time.Duration) error) (*CredentialReport, error) {
	waited := 0
	for first := true; ; first = false {
		generated, err := api.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
		if err != nil {
			return nil, fmt.Errorf("generating credential report: %w", err)
		}

		if !first || generated == nil || generated.State != iamtypes.ReportStateTypeComplete {
			if waited == len(waits) {
				return nil, ErrCredentialReportTimeout
			}
			if err := sleep(ctx, waits[waited]); err != nil {
				return nil, fmt.Errorf("waiting for credential report: %w", err)
			}
			waited++
		}

		output, err := api.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
		if err != nil {
			if credentialReportPending(err) {
				continue
			}
			return nil, fmt.Errorf("getting credential report: %w", err)
		}
		if output == nil {
			return nil, errMissing(middleware.Metadata{}, "getting credential report", "Content")
		}
		if output.Content == nil {
			return nil, errMissing(output.ResultMetadata, "getting credential report", "Content")
		}

		report, err := parseCredentialReport(output.Content)
		if err != nil {
			return nil, inResponse(output.ResultMetadata, err)
		}
		return report, nil
	}
}

// credentialReportPending reports whether err means the report is still being
// generated, was never generated, or has expired; all three are resolved by
// regenerating and polling again. The string checks cover SDK paths where the
// typed exceptions don't surface.
func credentialReportPending(err error) bool {
	var notReady *iamtypes.CredentialReportNotReadyException
	var notPresent *iamtypes.CredentialReportNotPresentException
	var expired *iamtypes.CredentialReportExpiredException
	if errors.As(err, &notReady) || errors.As(err, &notPresent) || errors.As(err, &expired) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "ReportInProgress") ||
		strings.Contains(msg, "ReportNotPresent") ||
		strings.Contains(msg, "ReportExpired")
}

// sleepContext waits for d or until ctx is cancelled, whichever comes first.
func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
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
		if isAPIErrorCode(err, "NoSuchEntity") {
			return nil, nil
		}
		return nil, fmt.Errorf("getting password policy: %w", err)
	}
	if output.PasswordPolicy == nil {
		return nil, errMissing(output.ResultMetadata, "getting password policy", "PasswordPolicy")
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

// ListBuckets lists all S3 buckets with their security settings. Each
// per-bucket read keeps its error on the bucket, so a setting that could not
// be read leaves only that setting out.
func (c *AWSClient) ListBuckets(ctx context.Context) ([]Bucket, error) {
	s3Client := s3.NewFromConfig(c.cfg)
	output, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing buckets: %w", err)
	}

	buckets := make([]Bucket, 0, len(output.Buckets))
	for _, b := range output.Buckets {
		name := aws.ToString(b.Name)
		bucket := Bucket{Name: name}

		bucket.Region, bucket.RegionErr = bucketRegion(ctx, s3Client, name)

		bucketClient := s3.NewFromConfig(c.s3ConfigForRegion(bucket.Region))

		pabOutput, err := bucketClient.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: b.Name,
		})
		bucket.PublicAccessBlock = s3BucketPublicAccessBlockEvaluation(pabOutput, err)

		encOutput, err := bucketClient.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: b.Name,
		})
		encryption := s3DefaultEncryptionEvaluation(encOutput, err)
		bucket.DefaultEncryptionEnabled = encryption.Enabled
		bucket.DefaultEncryptionEvaluated = encryption.Evaluated
		bucket.DefaultEncryptionErrorCode = encryption.ErrorCode
		bucket.DefaultEncryptionErr = encryption.Err

		verOutput, err := bucketClient.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: b.Name,
		})
		if err != nil {
			bucket.VersioningErr = fmt.Errorf("getting versioning for %s: %w", name, err)
		} else {
			bucket.VersioningEnabled = verOutput.Status == "Enabled"
			bucket.MFADeleteEnabled = verOutput.MFADelete == "Enabled"
		}

		logOutput, err := bucketClient.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{
			Bucket: b.Name,
		})
		switch {
		case err != nil:
			bucket.LoggingErr = fmt.Errorf("getting logging for %s: %w", name, err)
		case logOutput.LoggingEnabled != nil:
			bucket.LoggingEnabled = true
			bucket.LoggingTargetBucket = aws.ToString(logOutput.LoggingEnabled.TargetBucket)
		}

		bucket.Policy, bucket.PolicyErr = getBucketPolicy(ctx, bucketClient, name)

		buckets = append(buckets, bucket)
	}

	return buckets, nil
}

// bucketRegion resolves a bucket's region from its location constraint,
// which is empty for us-east-1.
func bucketRegion(ctx context.Context, client *s3.Client, bucket string) (string, error) {
	out, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(bucket)})
	if err != nil {
		return "", fmt.Errorf("locating bucket %s: %w", bucket, err)
	}
	region := string(out.LocationConstraint)
	if region == "" {
		region = DefaultRegionAWS
	}
	return region, nil
}

type s3DefaultEncryptionResult struct {
	Enabled   bool
	Evaluated bool
	ErrorCode string
	Err       error
}

func s3DefaultEncryptionEvaluation(output *s3.GetBucketEncryptionOutput, err error) s3DefaultEncryptionResult {
	if err != nil {
		// Since January 5, 2023, S3 applies SSE-S3 to new objects for every
		// bucket. Keep legacy missing-config responses from lowering posture.
		if isAPIErrorCode(err, "ServerSideEncryptionConfigurationNotFoundError") {
			return s3DefaultEncryptionResult{
				Enabled:   true,
				Evaluated: true,
				ErrorCode: "ServerSideEncryptionConfigurationNotFoundError",
			}
		}
		return s3DefaultEncryptionResult{ErrorCode: apiErrorCode(err), Err: fmt.Errorf("getting default encryption: %w", err)}
	}
	if output == nil {
		return s3DefaultEncryptionResult{ErrorCode: "MissingGetBucketEncryptionOutput", Err: errMissing(middleware.Metadata{}, "getting default encryption", "output")}
	}
	if output.ServerSideEncryptionConfiguration == nil {
		return s3DefaultEncryptionResult{ErrorCode: "MissingServerSideEncryptionConfiguration", Err: errMissing(output.ResultMetadata, "getting default encryption", "ServerSideEncryptionConfiguration")}
	}
	if len(output.ServerSideEncryptionConfiguration.Rules) == 0 {
		return s3DefaultEncryptionResult{ErrorCode: "EmptyServerSideEncryptionRules", Err: errMissing(output.ResultMetadata, "getting default encryption", "Rules")}
	}
	return s3DefaultEncryptionResult{
		Enabled:   true,
		Evaluated: true,
	}
}

// getBucketPolicy returns the bucket's policy document, or nil with no error
// when no policy is attached (NoSuchBucketPolicy). A document that is not a
// policy is an invalid response, never an empty policy.
func getBucketPolicy(ctx context.Context, client *s3.Client, bucket string) (*BucketPolicy, error) {
	out, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(bucket)})
	if err != nil {
		if isAPIErrorCode(err, "NoSuchBucketPolicy") {
			return nil, nil
		}
		return nil, fmt.Errorf("getting bucket policy for %s: %w", bucket, err)
	}
	if out.Policy == nil {
		return nil, errMissing(out.ResultMetadata, "getting bucket policy for "+bucket, "Policy")
	}
	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(*out.Policy), &doc); err != nil {
		return nil, inResponse(out.ResultMetadata, componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("reading bucket policy for %s: %w", bucket, err)))
	}
	if len(doc.Statement) == 0 {
		return nil, errMissing(out.ResultMetadata, "getting bucket policy for "+bucket, "Statement")
	}
	return &BucketPolicy{Document: *out.Policy}, nil
}

// GetBucketPolicy returns the bucket's policy document. Returns nil with no
// error when no policy is attached (NoSuchBucketPolicy).
func (c *AWSClient) GetBucketPolicy(ctx context.Context, region, bucket string) (*BucketPolicy, error) {
	return getBucketPolicy(ctx, s3.NewFromConfig(c.s3ConfigForRegion(region)), bucket)
}

// GetBucketACL returns the bucket's ACL. HasPublicGrant is computed from the
// grants list (any grant whose grantee URI is AllUsers or AuthenticatedUsers).
func (c *AWSClient) GetBucketACL(ctx context.Context, region, bucket string) (*BucketACL, error) {
	s3Client := s3.NewFromConfig(c.s3ConfigForRegion(region))
	out, err := s3Client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: aws.String(bucket)})
	if err != nil {
		return nil, fmt.Errorf("getting bucket ACL for %s: %w", bucket, err)
	}
	if out.Owner == nil {
		return nil, errMissing(out.ResultMetadata, "getting bucket ACL for "+bucket, "Owner")
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
	} else if r.Prefix != nil { //nolint:staticcheck // legacy rules still return this field
		// Legacy rules carry the prefix at the top level, deprecated but still
		// served. Dropping it would make a scoped rule read as covering the
		// whole bucket.
		rule.Prefix = aws.ToString(r.Prefix) //nolint:staticcheck // see above
	}
	for _, tr := range r.Transitions {
		if s := formatLifecycleTransition(tr); s != "" {
			rule.Transitions = append(rule.Transitions, s)
		}
	}
	rule.Expiration = formatLifecycleExpiration(r.Expiration)
	if r.Expiration != nil {
		rule.ExpirationDays = aws.ToInt32(r.Expiration.Days)
		rule.ExpirationIsDate = r.Expiration.Date != nil
	}
	return rule
}

// GetBucketRegion resolves a bucket's region. Fails for buckets outside the
// account, which is how a cross-account trail delivery bucket announces
// itself.
func (c *AWSClient) GetBucketRegion(ctx context.Context, bucket string) (string, error) {
	return bucketRegion(ctx, s3.NewFromConfig(c.cfg), bucket)
}

// GetBucketObjectLock returns the bucket's object lock default retention, or
// nil when object lock is not configured.
func (c *AWSClient) GetBucketObjectLock(ctx context.Context, region, bucket string) (*ObjectLockConfig, error) {
	s3Client := s3.NewFromConfig(c.s3ConfigForRegion(region))
	out, err := s3Client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: aws.String(bucket)})
	if err != nil {
		if isAPIErrorCode(err, "ObjectLockConfigurationNotFoundError") {
			return nil, nil
		}
		return nil, fmt.Errorf("getting object lock for %s: %w", bucket, err)
	}
	if out.ObjectLockConfiguration == nil {
		return nil, errMissing(out.ResultMetadata, "getting object lock for "+bucket, "ObjectLockConfiguration")
	}
	if out.ObjectLockConfiguration.Rule == nil || out.ObjectLockConfiguration.Rule.DefaultRetention == nil {
		return nil, nil
	}
	retention := out.ObjectLockConfiguration.Rule.DefaultRetention
	return &ObjectLockConfig{
		Mode:  string(retention.Mode),
		Days:  aws.ToInt32(retention.Days),
		Years: aws.ToInt32(retention.Years),
	}, nil
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

// GetAccountPublicAccessBlock returns the account-level S3 Block Public Access settings.
func (c *AWSClient) GetAccountPublicAccessBlock(ctx context.Context, accountID string) (PublicAccessBlockSettings, error) {
	s3ControlClient := s3control.NewFromConfig(c.cfg)
	output, err := s3ControlClient.GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{
		AccountId: aws.String(accountID),
	})
	pab := s3AccountPublicAccessBlockEvaluation(output, err)
	return pab, pab.Err
}

// GetBucketPublicAccessBlock returns one bucket's public access block, for
// joins that need it outside the full bucket listing.
func (c *AWSClient) GetBucketPublicAccessBlock(ctx context.Context, region, bucket string) PublicAccessBlockSettings {
	s3Client := s3.NewFromConfig(c.s3ConfigForRegion(region))
	out, err := s3Client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String(bucket)})
	return s3BucketPublicAccessBlockEvaluation(out, err)
}

func s3BucketPublicAccessBlockEvaluation(output *s3.GetPublicAccessBlockOutput, err error) PublicAccessBlockSettings {
	if err != nil {
		if isAPIErrorCode(err, "NoSuchPublicAccessBlockConfiguration") {
			return PublicAccessBlockSettings{Evaluated: true}
		}
		return PublicAccessBlockSettings{ErrorCode: apiErrorCode(err), Err: fmt.Errorf("getting bucket public access block: %w", err)}
	}
	if output == nil {
		return PublicAccessBlockSettings{ErrorCode: "MissingGetPublicAccessBlockOutput", Err: errMissing(middleware.Metadata{}, "getting bucket public access block", "output")}
	}
	if output.PublicAccessBlockConfiguration == nil {
		return PublicAccessBlockSettings{ErrorCode: "MissingPublicAccessBlockConfiguration", Err: errMissing(output.ResultMetadata, "getting bucket public access block", "PublicAccessBlockConfiguration")}
	}

	return publicAccessBlockFromS3(output.PublicAccessBlockConfiguration)
}

func s3AccountPublicAccessBlockEvaluation(output *s3control.GetPublicAccessBlockOutput, err error) PublicAccessBlockSettings {
	if err != nil {
		if isAPIErrorCode(err, "NoSuchPublicAccessBlockConfiguration") {
			return PublicAccessBlockSettings{Evaluated: true}
		}
		return PublicAccessBlockSettings{ErrorCode: apiErrorCode(err), Err: fmt.Errorf("getting account public access block: %w", err)}
	}
	if output == nil {
		return PublicAccessBlockSettings{ErrorCode: "MissingGetPublicAccessBlockOutput", Err: errMissing(middleware.Metadata{}, "getting account public access block", "output")}
	}
	if output.PublicAccessBlockConfiguration == nil {
		return PublicAccessBlockSettings{ErrorCode: "MissingPublicAccessBlockConfiguration", Err: errMissing(output.ResultMetadata, "getting account public access block", "PublicAccessBlockConfiguration")}
	}

	return publicAccessBlockFromS3Control(output.PublicAccessBlockConfiguration)
}

func publicAccessBlockFromS3(pab *s3types.PublicAccessBlockConfiguration) PublicAccessBlockSettings {
	return PublicAccessBlockSettings{
		BlockPublicACLs:       aws.ToBool(pab.BlockPublicAcls),
		IgnorePublicACLs:      aws.ToBool(pab.IgnorePublicAcls),
		BlockPublicPolicy:     aws.ToBool(pab.BlockPublicPolicy),
		RestrictPublicBuckets: aws.ToBool(pab.RestrictPublicBuckets),
		Evaluated:             true,
	}
}

func publicAccessBlockFromS3Control(pab *s3controltypes.PublicAccessBlockConfiguration) PublicAccessBlockSettings {
	return PublicAccessBlockSettings{
		BlockPublicACLs:       aws.ToBool(pab.BlockPublicAcls),
		IgnorePublicACLs:      aws.ToBool(pab.IgnorePublicAcls),
		BlockPublicPolicy:     aws.ToBool(pab.BlockPublicPolicy),
		RestrictPublicBuckets: aws.ToBool(pab.RestrictPublicBuckets),
		Evaluated:             true,
	}
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
			instance := DBInstance{
				DBInstanceIdentifier:    aws.ToString(db.DBInstanceIdentifier),
				Engine:                  aws.ToString(db.Engine),
				EngineVersion:           aws.ToString(db.EngineVersion),
				PubliclyAccessible:      aws.ToBool(db.PubliclyAccessible),
				StorageEncrypted:        aws.ToBool(db.StorageEncrypted),
				DeletionProtection:      aws.ToBool(db.DeletionProtection),
				BackupRetentionPeriod:   int(aws.ToInt32(db.BackupRetentionPeriod)),
				MultiAZ:                 aws.ToBool(db.MultiAZ),
				AutoMinorVersionUpgrade: aws.ToBool(db.AutoMinorVersionUpgrade),
				PreferredBackupWindow:   aws.ToString(db.PreferredBackupWindow),
				LogExports:              db.EnabledCloudwatchLogsExports,
				LatestRestorableTime:    db.LatestRestorableTime,
			}
			if len(db.DBParameterGroups) > 0 {
				instance.ParameterGroupName = aws.ToString(db.DBParameterGroups[0].DBParameterGroupName)
				instance.ParameterApplyStatus = aws.ToString(db.DBParameterGroups[0].ParameterApplyStatus)
			}
			if endpoint := db.Endpoint; endpoint != nil { // LINT-ALLOW: the RDS listener port feeds ingress evaluation; the endpoint address is never read.
				instance.EndpointPort = int(aws.ToInt32(endpoint.Port))
			}
			for _, sg := range db.VpcSecurityGroups {
				if id := aws.ToString(sg.VpcSecurityGroupId); id != "" {
					instance.VpcSecurityGroupIDs = append(instance.VpcSecurityGroupIDs, id)
				}
			}
			instances = append(instances, instance)
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

// ListVPCs lists VPCs in the specified region.
func (c *AWSClient) ListVPCs(ctx context.Context, region string, includeFlowLogs bool) ([]VPC, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	ec2Client := ec2.NewFromConfig(cfg)

	output, err := ec2Client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("describing VPCs: %w", err)
	}

	flowLogVPCs := make(map[string]bool)
	flowLogsEvaluated := false
	var flowLogsErr error
	flowLogsErrorCode := ""
	if includeFlowLogs {
		flowLogsOutput, err := ec2Client.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{})
		if err != nil {
			flowLogsErr = &FlowLogsUnavailableError{
				Region: region,
				Code:   apiErrorCode(err),
				Err:    err,
			}
			flowLogsErrorCode = apiErrorCode(err)
		} else {
			flowLogsEvaluated = true
			for _, fl := range flowLogsOutput.FlowLogs {
				if fl.ResourceId != nil {
					flowLogVPCs[*fl.ResourceId] = true
				}
			}
		}
	}

	vpcs := make([]VPC, 0, len(output.Vpcs))
	for _, v := range output.Vpcs {
		vpc := VPC{
			VPCID:             aws.ToString(v.VpcId),
			IsDefault:         aws.ToBool(v.IsDefault),
			FlowLogsEnabled:   flowLogVPCs[aws.ToString(v.VpcId)],
			FlowLogsEvaluated: flowLogsEvaluated,
			FlowLogsErrorCode: flowLogsErrorCode,
		}
		vpcs = append(vpcs, vpc)
	}

	return vpcs, flowLogsErr
}

type FlowLogsUnavailableError struct {
	Region string
	Code   string
	Err    error
}

func (e *FlowLogsUnavailableError) Error() string {
	return fmt.Sprintf("describing VPC flow logs in %s: %v", e.Region, e.Err)
}

func (e *FlowLogsUnavailableError) Unwrap() error {
	return e.Err
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
			securityGroups = append(securityGroups, securityGroupFromSDK(sg))
		}
	}

	return securityGroups, nil
}

// ListSecurityGroupsByID describes only the named groups. Surfaces that join
// a resource's attached groups (RDS database-port ingress) use this instead
// of pulling the region's full inventory a second time.
func (c *AWSClient) ListSecurityGroupsByID(ctx context.Context, region string, groupIDs []string) ([]SecurityGroup, error) {
	if len(groupIDs) == 0 {
		return nil, nil
	}

	cfg := c.cfg.Copy()
	cfg.Region = region
	ec2Client := ec2.NewFromConfig(cfg)

	var securityGroups []SecurityGroup
	var last middleware.Metadata
	paginator := ec2.NewDescribeSecurityGroupsPaginator(ec2Client, &ec2.DescribeSecurityGroupsInput{GroupIds: groupIDs})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing security groups by id: %w", err)
		}

		for _, sg := range output.SecurityGroups {
			securityGroups = append(securityGroups, securityGroupFromSDK(sg))
		}
		last = output.ResultMetadata
	}

	// EC2 fails a request that names a group it does not have, so an answer
	// that leaves one out is incomplete, not a group without rules.
	answered := make(map[string]bool, len(securityGroups))
	for _, sg := range securityGroups {
		answered[sg.GroupID] = true
	}
	for _, id := range groupIDs {
		if !answered[id] {
			return nil, errIncomplete(last, "describing security groups by id", "security groups", len(answered), len(groupIDs))
		}
	}

	return securityGroups, nil
}

func securityGroupFromSDK(sg ec2types.SecurityGroup) SecurityGroup {
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

	return group
}

// DescribeTrails returns CloudTrail trails.
func (c *AWSClient) DescribeTrails(ctx context.Context) ([]Trail, error) {
	ctClient := cloudtrail.NewFromConfig(c.cfg)
	output, err := ctClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
		IncludeShadowTrails: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("describing trails: %w", err)
	}

	sdkTrails := dedupeCloudTrailSDKTrails(output.TrailList)
	trails := make([]Trail, 0, len(sdkTrails))
	var statusErr error
	for _, t := range sdkTrails {
		trail := Trail{
			Name:                      aws.ToString(t.Name),
			TrailARN:                  aws.ToString(t.TrailARN),
			HomeRegion:                aws.ToString(t.HomeRegion),
			S3BucketName:              aws.ToString(t.S3BucketName),
			S3KeyPrefix:               aws.ToString(t.S3KeyPrefix),
			IsMultiRegionTrail:        aws.ToBool(t.IsMultiRegionTrail),
			IsOrganizationTrail:       aws.ToBool(t.IsOrganizationTrail),
			LogFileValidationEnabled:  aws.ToBool(t.LogFileValidationEnabled),
			CloudWatchLogsLogGroupArn: t.CloudWatchLogsLogGroupArn,
			KMSKeyId:                  t.KmsKeyId,
		}

		// Get trail status
		status, err := ctClient.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: trailStatusIdentifier(t),
		})
		if err == nil && status.IsLogging == nil {
			err = errMissing(status.ResultMetadata, "getting trail status for "+trail.Name, "IsLogging")
		}
		if err != nil {
			trail.TrailStatusErrorCode = apiErrorCode(err)
			if shouldInferOrganizationTrailLogging(t, err) {
				trail.IsLogging = true
				trail.TrailStatusInferred = true
			} else {
				trail.StatusErr = &TrailStatusUnavailableError{
					TrailName: trail.Name,
					Code:      apiErrorCode(err),
					Err:       err,
				}
				if statusErr == nil {
					statusErr = trail.StatusErr
				}
			}
			trails = append(trails, trail)
			continue
		}
		trail.IsLogging = aws.ToBool(status.IsLogging)
		trail.TrailStatusEvaluated = true

		trails = append(trails, trail)
	}

	return trails, statusErr
}

type TrailStatusUnavailableError struct {
	TrailName string
	Code      string
	Err       error
}

func (e *TrailStatusUnavailableError) Error() string {
	return fmt.Sprintf("getting trail status for %s: %v", e.TrailName, e.Err)
}

func (e *TrailStatusUnavailableError) Unwrap() error {
	return e.Err
}

// shouldInferOrganizationTrailLogging reports whether a failed status read is
// a member account being blocked from its organization's shadow trail, which
// counts as coverage. Any other failure leaves the status unknown.
func shouldInferOrganizationTrailLogging(t cloudtrailtypes.Trail, err error) bool {
	if err == nil || !aws.ToBool(t.IsOrganizationTrail) {
		return false
	}
	return componentsdk.Classify(err) == componentsdk.CodePermissionDenied || isAPIErrorCode(err, "TrailNotFoundException")
}

func dedupeCloudTrailSDKTrails(trails []cloudtrailtypes.Trail) []cloudtrailtypes.Trail {
	out := make([]cloudtrailtypes.Trail, 0, len(trails))
	seen := make(map[string]struct{}, len(trails))
	for _, trail := range trails {
		key := cloudTrailSDKTrailIdentity(trail)
		if key == "" {
			out = append(out, trail)
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trail)
	}
	return out
}

func cloudTrailSDKTrailIdentity(t cloudtrailtypes.Trail) string {
	if arn := aws.ToString(t.TrailARN); arn != "" {
		return arn
	}
	if name := aws.ToString(t.Name); name != "" {
		return name
	}
	return ""
}

func trailStatusIdentifier(t cloudtrailtypes.Trail) *string {
	if t.TrailARN != nil && *t.TrailARN != "" {
		return t.TrailARN
	}
	return t.Name
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
// A region where GuardDuty is off answers with no detectors. A finding count
// that could not be read keeps its error on the detector.
func (c *AWSClient) ListGuardDutyDetectors(ctx context.Context, region string) ([]GuardDutyDetector, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	gdClient := guardduty.NewFromConfig(cfg)

	listOutput, err := gdClient.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing GuardDuty detectors in %s: %w", region, err)
	}

	detectors := make([]GuardDutyDetector, 0, len(listOutput.DetectorIds))
	for _, id := range listOutput.DetectorIds {
		getOutput, err := gdClient.GetDetector(ctx, &guardduty.GetDetectorInput{
			DetectorId: aws.String(id),
		})
		if err != nil {
			return nil, fmt.Errorf("getting GuardDuty detector %s in %s: %w", id, region, err)
		}
		if getOutput.Status == "" {
			return nil, errMissing(getOutput.ResultMetadata, "getting GuardDuty detector "+id, "Status")
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
		detector.HighOrCriticalFindings, detector.FindingsErr = c.countGuardDutyFindings(ctx, gdClient, id, unarchivedHighSeverityCriteria)

		cutoffMillis := c.now().Add(-48 * time.Hour).UnixMilli()
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
		detector.HighOrCriticalFindingsOlderThan48Hours, detector.StaleFindingsErr = c.countGuardDutyFindings(ctx, gdClient, id, staleHighSeverityCriteria)

		detectors = append(detectors, detector)
	}

	return detectors, nil
}

// GetGuardDutyAdministratorAccount returns the account ID administering this
// detector, or "" when the account is standalone. Membership is the
// interpretive key for finding-notification routing: member accounts commonly
// route findings centrally in the administrator account, so an absence of
// local rules is not an absence of coverage.
func (c *AWSClient) GetGuardDutyAdministratorAccount(ctx context.Context, region, detectorID string) (string, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	gdClient := guardduty.NewFromConfig(cfg)

	output, err := gdClient.GetAdministratorAccount(ctx, &guardduty.GetAdministratorAccountInput{
		DetectorId: aws.String(detectorID),
	})
	if err != nil {
		return "", fmt.Errorf("getting GuardDuty administrator account in %s: %w", region, err)
	}
	if output.Administrator == nil || !strings.EqualFold(aws.ToString(output.Administrator.RelationshipStatus), "enabled") {
		return "", nil
	}
	return aws.ToString(output.Administrator.AccountId), nil
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
			return 0, fmt.Errorf("counting GuardDuty findings for detector %s: %w", detectorID, err)
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
			return nil, false, fmt.Errorf("listing GuardDuty findings for detector %s: %w", detectorID, err)
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
		if len(resp.Findings) < end-start {
			return nil, errIncomplete(resp.ResultMetadata, "getting GuardDuty findings", "findings", len(resp.Findings), end-start)
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
		if isAPIErrorCode(err, "ResourceNotFoundException") || securityHubNotEnabled(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("describing Security Hub: %w", err)
	}
	if hubOutput.HubArn == nil {
		return nil, errMissing(hubOutput.ResultMetadata, "describing Security Hub", "HubArn")
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
	config.StandardsARNs = []string{}
	for _, s := range standardsOutput.StandardsSubscriptions {
		config.StandardsARNs = append(config.StandardsARNs, aws.ToString(s.StandardsArn))
	}

	// Get integrations
	integrationsOutput, err := shClient.ListEnabledProductsForImport(ctx, &securityhub.ListEnabledProductsForImportInput{})
	if err != nil {
		config.IntegrationsErr = fmt.Errorf("listing Security Hub integrations: %w", err)
		return config, nil
	}
	config.IntegrationCount = len(integrationsOutput.ProductSubscriptions)
	config.ProductSubscriptions = make([]string, 0, len(integrationsOutput.ProductSubscriptions))
	config.ProductSubscriptions = append(config.ProductSubscriptions, integrationsOutput.ProductSubscriptions...)

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
			if securityHubNotEnabled(err) {
				return nil, componentsdk.CodeError(componentsdk.CodeNotLicensed, fmt.Errorf("reading Inspector findings needs Security Hub, which is not enabled in %s: %w", region, err))
			}
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

// ListAccessAnalyzers returns IAM Access Analyzer analyzers in the specified
// region, with findings counted only for active analyzers: an analyzer that is
// creating, disabled, or failed evidences nothing.
func (c *AWSClient) ListAccessAnalyzers(ctx context.Context, region string) ([]AccessAnalyzer, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	aaClient := accessanalyzer.NewFromConfig(cfg)

	var analyzers []AccessAnalyzer
	paginator := accessanalyzer.NewListAnalyzersPaginator(aaClient, &accessanalyzer.ListAnalyzersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing access analyzers in %s: %w", region, err)
		}
		for _, a := range page.Analyzers {
			analyzer := AccessAnalyzer{
				Name:   aws.ToString(a.Name),
				ARN:    aws.ToString(a.Arn),
				Type:   string(a.Type),
				Status: string(a.Status),
			}
			if analyzer.Status == "ACTIVE" {
				c.countAnalyzerFindings(ctx, aaClient, &analyzer)
			}
			analyzers = append(analyzers, analyzer)
		}
	}
	return analyzers, nil
}

// countAnalyzerFindings buckets the analyzer's findings by triage state. A
// failed listing marks the analyzer unresolved rather than reporting zero: an
// AccessDenied here must never read as a clean analyzer.
func (c *AWSClient) countAnalyzerFindings(ctx context.Context, client *accessanalyzer.Client, analyzer *AccessAnalyzer) {
	paginator := accessanalyzer.NewListFindingsPaginator(client, &accessanalyzer.ListFindingsInput{
		AnalyzerArn: aws.String(analyzer.ARN),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			analyzer.FindingsUnresolved = true
			analyzer.FindingsErr = fmt.Errorf("listing findings for analyzer %s: %w", analyzer.Name, err)
			analyzer.ActiveFindingsCount = 0
			analyzer.ArchivedFindingsCount = 0
			return
		}
		for _, f := range page.Findings {
			switch string(f.Status) {
			case "ACTIVE":
				analyzer.ActiveFindingsCount++
			case "ARCHIVED":
				analyzer.ArchivedFindingsCount++
			}
		}
	}
}

// securityHubNotEnabled reports the error Security Hub answers with in a
// region where the account has not enabled it.
func securityHubNotEnabled(err error) bool {
	return isAPIErrorCode(err, "InvalidAccessException") && strings.Contains(err.Error(), "not subscribed")
}

func isAPIErrorCode(err error, code string) bool {
	return apiErrorCode(err) == code
}

func apiErrorCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		if code := strings.TrimSpace(apiErr.ErrorCode()); code != "" {
			return code
		}
	}
	if err != nil {
		return "NonAPIError"
	}
	return ""
}
