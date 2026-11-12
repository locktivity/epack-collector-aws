package aws

import (
	"bytes"
	"cmp"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	accessanalyzertypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
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
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
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
	ListRoles(ctx context.Context, pathPrefix string, callback func([]Role) error) error
	ListSAMLProviders(ctx context.Context) ([]SAMLProvider, error)

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
	DescribeTrails(ctx context.Context, regions []string, accountID string) ([]Trail, error)
	DescribeConfigRecorders(ctx context.Context, region string) ([]ConfigRecorder, error)
	ListConfigRules(ctx context.Context, region string) ([]ConfigRule, error)
	ListGuardDutyDetectors(ctx context.Context, region string) ([]GuardDutyDetector, error)
	ListGuardDutyFindings(ctx context.Context, region, detectorID string, maxFindings int) ([]GuardDutyFinding, bool, error)
	GetSecurityHubConfig(ctx context.Context, region string) (*SecurityHubConfig, error)
	GetSecurityHubCISComplianceByLevel(ctx context.Context, region, accountID, standardID string) (*SecurityHubCISComplianceByLevel, error)
	GetInspectorSummaryFromSecurityHub(ctx context.Context, region, accountID string) (*InspectorSummary, error)
	ListAccessAnalyzers(ctx context.Context, region string) ([]AccessAnalyzer, error)

	// IAM Identity Center (one instance per account, regional). The instance
	// listing answers for one region, so callers probe each region they
	// scan; it returns an empty slice where the caller sees no instance.
	ListIdentityCenterInstances(ctx context.Context, region string) ([]IdentityCenterInstance, error)
	ListIdentityCenterPermissionSetARNs(ctx context.Context, region, instanceARN string) ([]string, error)
	DescribeIdentityCenterPermissionSets(ctx context.Context, region, instanceARN string, arns []string, withInternalEnrichment bool) ([]IdentityCenterPermissionSet, error)
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
	// filtered out (no customer posture lever). With withAliases, aliases come
	// from a single per-region ListAliases call, joined into the per-key
	// metadata.
	ListKMSCustomerKeys(ctx context.Context, region string, withAliases bool) ([]KMSKey, error)

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
	ctx = componentsdk.WithOperation(ctx, componentsdk.Operation{Name: GitHubTokenOperation, Permission: GitHubTokenPermission})
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

// GitHubTokenPermission is the workflow permission the identity token
// endpoint needs.
const GitHubTokenPermission = "id-token:write"

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
	return orderRegions(regions, c.cfg.Region), nil
}

// orderRegions sorts regions with home, the client's own region, first when
// it is enabled. DescribeRegions promises no order, and the first region is
// the primary region the single-region services are read in.
func orderRegions(regions []string, home string) []string {
	slices.Sort(regions)
	if i := slices.Index(regions, home); i > 0 {
		regions = append([]string{home}, slices.Delete(regions, i, i+1)...)
	}
	return regions
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
		report.GeneratedTime = output.GeneratedTime
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

// ListRoles lists IAM roles whose path starts with pathPrefix, or every role
// when pathPrefix is empty, passing each page to callback.
func (c *AWSClient) ListRoles(ctx context.Context, pathPrefix string, callback func([]Role) error) error {
	iamClient := iam.NewFromConfig(c.cfg)
	input := &iam.ListRolesInput{}
	if pathPrefix != "" {
		input.PathPrefix = aws.String(pathPrefix)
	}
	paginator := iam.NewListRolesPaginator(iamClient, input)

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

// ListSAMLProviders lists the account's SAML identity providers. IAM answers
// with all of them at once.
func (c *AWSClient) ListSAMLProviders(ctx context.Context) ([]SAMLProvider, error) {
	output, err := iam.NewFromConfig(c.cfg).ListSAMLProviders(ctx, &iam.ListSAMLProvidersInput{})
	if err != nil {
		return nil, fmt.Errorf("listing SAML providers: %w", err)
	}
	providers := make([]SAMLProvider, 0, len(output.SAMLProviderList))
	for _, p := range output.SAMLProviderList {
		arn := aws.ToString(p.Arn)
		providers = append(providers, SAMLProvider{ARN: arn, Name: arn[strings.LastIndex(arn, "/")+1:]})
	}
	return providers, nil
}

// ListBuckets lists all S3 buckets with their security settings. Each
// per-bucket read keeps its error on the bucket, so a setting that could not
// be read leaves only that setting out.
func (c *AWSClient) ListBuckets(ctx context.Context) ([]Bucket, error) {
	s3Client := s3.NewFromConfig(c.cfg)
	// S3 rejects an unpaginated ListBuckets for an account whose bucket
	// quota is above 10,000, so the listing always asks for pages.
	var listed []s3types.Bucket
	paginator := s3.NewListBucketsPaginator(s3Client, &s3.ListBucketsInput{MaxBuckets: aws.Int32(listBucketsPageSize)})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing buckets: %w", err)
		}
		listed = append(listed, page.Buckets...)
	}

	buckets := make([]Bucket, 0, len(listed))
	for _, b := range listed {
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
// listBucketsPageSize is the most buckets ListBuckets returns in one page.
const listBucketsPageSize = 10000

func bucketRegion(ctx context.Context, client *s3.Client, bucket string) (string, error) {
	out, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(bucket)})
	if err != nil {
		return "", fmt.Errorf("locating bucket %s: %w", bucket, err)
	}
	// GetBucketLocation returns no constraint for a us-east-1 bucket and EU
	// for a legacy eu-west-1 bucket.
	return normalizeBucketRegion(string(out.LocationConstraint)), nil
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
	if f := r.Filter; f != nil {
		rule.Tags = addLifecycleTag(rule.Tags, f.Tag)
		rule.ObjectSizeGreaterThan = aws.ToInt64(f.ObjectSizeGreaterThan)
		rule.ObjectSizeLessThan = aws.ToInt64(f.ObjectSizeLessThan)
		if and := f.And; and != nil {
			for i := range and.Tags {
				rule.Tags = addLifecycleTag(rule.Tags, &and.Tags[i])
			}
			rule.ObjectSizeGreaterThan = aws.ToInt64(and.ObjectSizeGreaterThan)
			rule.ObjectSizeLessThan = aws.ToInt64(and.ObjectSizeLessThan)
		}
	}
	switch {
	case r.Filter != nil && r.Filter.Prefix != nil:
		rule.Prefix = aws.ToString(r.Filter.Prefix)
	case r.Filter != nil && r.Filter.And != nil && r.Filter.And.Prefix != nil:
		// A filter that combines a prefix with tags or object sizes holds
		// its prefix in And.
		rule.Prefix = aws.ToString(r.Filter.And.Prefix)
	case r.Prefix != nil: //nolint:staticcheck // legacy rules still return this field
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
	if r.NoncurrentVersionExpiration != nil {
		rule.NoncurrentExpirationDays = aws.ToInt32(r.NoncurrentVersionExpiration.NoncurrentDays)
		rule.NewerNoncurrentVersions = aws.ToInt32(r.NoncurrentVersionExpiration.NewerNoncurrentVersions)
	}
	return rule
}

// addLifecycleTag adds a lifecycle filter tag to tags.
func addLifecycleTag(tags map[string]string, tag *s3types.Tag) map[string]string {
	if tag == nil {
		return tags
	}
	if tags == nil {
		tags = map[string]string{}
	}
	tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	return tags
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

// GetBucketVersioning reports whether versioning is enabled on a bucket. A
// bucket whose versioning was never set, or is suspended, reads false.
func (c *AWSClient) GetBucketVersioning(ctx context.Context, region, bucket string) (bool, error) {
	s3Client := s3.NewFromConfig(c.s3ConfigForRegion(region))
	out, err := s3Client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(bucket)})
	if err != nil {
		return false, fmt.Errorf("getting versioning for %s: %w", bucket, err)
	}
	return out.Status == s3types.BucketVersioningStatusEnabled, nil
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
				DBClusterIdentifier:     aws.ToString(db.DBClusterIdentifier),
				Engine:                  aws.ToString(db.Engine),
				EngineVersion:           aws.ToString(db.EngineVersion),
				PubliclyAccessible:      aws.ToBool(db.PubliclyAccessible),
				StorageEncrypted:        storageEncrypted(db.StorageEncrypted, db.StorageEncryptionType),
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
				StorageEncrypted:      storageEncrypted(db.StorageEncrypted, db.StorageEncryptionType),
				DeletionProtection:    aws.ToBool(db.DeletionProtection),
				BackupRetentionPeriod: int(aws.ToInt32(db.BackupRetentionPeriod)),
				MultiAZ:               aws.ToBool(db.MultiAZ),
				LatestRestorableTime:  db.LatestRestorableTime,
			})
		}
	}

	return clusters, nil
}

// storageEncrypted reports whether a DB instance's or cluster's storage is
// encrypted at rest. Storage encrypted with an AWS owned key has
// StorageEncrypted false and StorageEncryptionType sse-rds.
func storageEncrypted(flag *bool, encryptionType rdstypes.StorageEncryptionType) bool {
	return aws.ToBool(flag) || encryptionType == rdstypes.StorageEncryptionTypeSse
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
				// A flow log whose delivery failed publishes nothing.
				if fl.ResourceId != nil && aws.ToString(fl.DeliverLogsStatus) != "FAILED" {
					flowLogVPCs[*fl.ResourceId] = true
				}
			}
		}
	}

	vpcs := make([]VPC, 0, len(output.Vpcs))
	for _, v := range output.Vpcs {
		vpc := VPC{
			VPCID:             aws.ToString(v.VpcId),
			OwnerID:           aws.ToString(v.OwnerId),
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

// GetManagedPrefixListCIDRs returns the CIDR blocks a managed prefix list
// holds. A security group rule whose source is the list allows each of them.
func (c *AWSClient) GetManagedPrefixListCIDRs(ctx context.Context, region, prefixListID string) ([]string, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	ec2Client := ec2.NewFromConfig(cfg)

	var cidrs []string
	paginator := ec2.NewGetManagedPrefixListEntriesPaginator(ec2Client, &ec2.GetManagedPrefixListEntriesInput{PrefixListId: aws.String(prefixListID)})
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting entries of prefix list %s: %w", prefixListID, err)
		}
		for _, entry := range output.Entries {
			cidrs = append(cidrs, aws.ToString(entry.Cidr))
		}
	}
	return cidrs, nil
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
		for _, pl := range perm.PrefixListIds {
			if pl.PrefixListId != nil {
				rule.PrefixListIDs = append(rule.PrefixListIDs, aws.ToString(pl.PrefixListId))
			}
		}
		group.IngressRules = append(group.IngressRules, rule)
	}

	return group
}

// DescribeTrails returns the trails DescribeTrails lists in each of regions,
// once per ARN. DescribeTrails lists the trails of the region it is called in
// and the shadows of multi-region and organization trails, so a single-region
// trail is found only in its own region. Each trail's status and event
// selectors are read in its home region when that region lists it, and
// otherwise in the first region that does. With no regions it reads the
// client's own region. A region whose listing fails is skipped. When another
// region's listing succeeded, the error is then a
// *TrailListingIncompleteError, joined with any *TrailStatusUnavailableError
// or *TrailSelectorsUnavailableError. accountID is the account being
// collected.
func (c *AWSClient) DescribeTrails(ctx context.Context, regions []string, accountID string) ([]Trail, error) {
	if len(regions) == 0 {
		regions = []string{c.cfg.Region}
	}
	var listed []listedTrail
	answered := map[string]bool{}
	var failed []string
	var firstListErr error
	for _, region := range regions {
		cfg := c.cfg.Copy()
		cfg.Region = region
		output, err := cloudtrail.NewFromConfig(cfg).DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
			IncludeShadowTrails: aws.Bool(true),
		})
		if err != nil {
			failed = append(failed, region)
			if firstListErr == nil {
				firstListErr = err
			}
			continue
		}
		answered[region] = true
		for _, t := range output.TrailList {
			listed = append(listed, listedTrail{trail: t, region: region})
		}
	}
	if len(failed) == len(regions) {
		return nil, fmt.Errorf("describing trails: %w", firstListErr)
	}

	unique := uniqueListedTrails(listed)
	trails := make([]Trail, 0, len(unique))
	var statusErr, selectorsErr error
	for _, l := range unique {
		cfg := c.cfg.Copy()
		cfg.Region = l.region
		trail, err := c.describeTrail(ctx, cloudtrail.NewFromConfig(cfg), l.trail, accountID)
		trails = append(trails, trail)
		var status *TrailStatusUnavailableError
		var selectors *TrailSelectorsUnavailableError
		switch {
		case errors.As(err, &status) && statusErr == nil:
			statusErr = status
		case errors.As(err, &selectors) && selectorsErr == nil:
			selectorsErr = selectors
		}
	}

	var listErr error
	if len(failed) > 0 {
		listErr = &TrailListingIncompleteError{Regions: failed, Err: firstListErr}
	}
	return trails, errors.Join(listErr, statusErr, selectorsErr)
}

// describeTrail reads one listed trail's status and the management events
// its event selectors record. It returns a *TrailStatusUnavailableError or a
// *TrailSelectorsUnavailableError for a read that failed.
func (c *AWSClient) describeTrail(ctx context.Context, ctClient *cloudtrail.Client, t cloudtrailtypes.Trail, accountID string) (Trail, error) {
	trail := Trail{
		Name:                      aws.ToString(t.Name),
		TrailARN:                  aws.ToString(t.TrailARN),
		HomeRegion:                aws.ToString(t.HomeRegion),
		S3BucketName:              aws.ToString(t.S3BucketName),
		S3KeyPrefix:               aws.ToString(t.S3KeyPrefix),
		IsMultiRegionTrail:        aws.ToBool(t.IsMultiRegionTrail),
		GlobalServiceEventsOff:    t.IncludeGlobalServiceEvents != nil && !*t.IncludeGlobalServiceEvents,
		IsOrganizationTrail:       aws.ToBool(t.IsOrganizationTrail),
		LogFileValidationEnabled:  aws.ToBool(t.LogFileValidationEnabled),
		CloudWatchLogsLogGroupArn: t.CloudWatchLogsLogGroupArn,
		KMSKeyId:                  t.KmsKeyId,
	}

	var err error
	status, statusErr := ctClient.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
		Name: trailStatusIdentifier(t),
	})
	if statusErr == nil && status.IsLogging == nil {
		statusErr = errMissing(status.ResultMetadata, "getting trail status for "+trail.Name, "IsLogging")
	}
	switch {
	case statusErr == nil:
		trail.IsLogging = aws.ToBool(status.IsLogging)
		trail.TrailStatusEvaluated = true
	case shouldInferOrganizationTrailLogging(t, accountID, statusErr):
		trail.TrailStatusErrorCode = apiErrorCode(statusErr)
		trail.IsLogging = true
		trail.TrailStatusInferred = true
	default:
		trail.TrailStatusErrorCode = apiErrorCode(statusErr)
		trail.StatusErr = &TrailStatusUnavailableError{
			TrailName: trail.Name,
			Code:      apiErrorCode(statusErr),
			Err:       statusErr,
		}
		err = trail.StatusErr
	}

	// A trail without custom event selectors records every management
	// event, reads and writes, and no data events.
	if !aws.ToBool(t.HasCustomEventSelectors) {
		trail.ManagementEvents = ManagementEventsReadWrite
		return trail, err
	}
	selectors, selectorsErr := ctClient.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{
		TrailName: trailStatusIdentifier(t),
	})
	if selectorsErr == nil && selectors.TrailARN == nil {
		selectorsErr = errMissing(selectors.ResultMetadata, "getting event selectors for "+trail.Name, "TrailARN")
	}
	switch {
	case selectorsErr == nil:
		trail.ManagementEvents, trail.ManagementEventSourcesExcluded = managementEvents(selectors.EventSelectors, selectors.AdvancedEventSelectors)
	case shouldInferOrganizationTrailLogging(t, accountID, selectorsErr):
		trail.ManagementEventsInferred = true
		trail.SelectorsErr = selectorsErr
	default:
		trail.SelectorsErr = &TrailSelectorsUnavailableError{
			TrailName: trail.Name,
			Err:       selectorsErr,
		}
		if err == nil {
			err = trail.SelectorsErr
		}
	}
	return trail, err
}

// Management events a trail's event selectors record.
const (
	ManagementEventsReadWrite = "read_write"
	ManagementEventsWriteOnly = "write_only"
	ManagementEventsReadOnly  = "read_only"
	ManagementEventsNone      = "none"
)

// managementEvents returns which management events the selectors record. A
// basic selector records them unless IncludeManagementEvents is false, and
// its ReadWriteType says which. An advanced selector records them when its
// eventCategory field equals Management, and its readOnly field says which.
//
// sourcesExcluded is true when every selector that records management writes
// leaves out an event source. A basic selector does that with
// ExcludeManagementEventSources, and an advanced one with an eventSource
// field. Either can leave out KMS or RDS Data API events.
func managementEvents(basic []cloudtrailtypes.EventSelector, advanced []cloudtrailtypes.AdvancedEventSelector) (events string, sourcesExcluded bool) {
	reads, writes, allSourceWrites := false, false, false
	for _, s := range basic {
		if s.IncludeManagementEvents != nil && !*s.IncludeManagementEvents {
			continue
		}
		w := true
		switch s.ReadWriteType {
		case cloudtrailtypes.ReadWriteTypeReadOnly:
			reads, w = true, false
		case cloudtrailtypes.ReadWriteTypeWriteOnly:
			writes = true
		default:
			reads, writes = true, true
		}
		if w && len(s.ExcludeManagementEventSources) == 0 {
			allSourceWrites = true
		}
	}
	for _, s := range advanced {
		r, w, excluded := advancedManagementEvents(s.FieldSelectors)
		reads, writes = reads || r, writes || w
		if w && !excluded {
			allSourceWrites = true
		}
	}
	sourcesExcluded = writes && !allSourceWrites
	switch {
	case reads && writes:
		return ManagementEventsReadWrite, sourcesExcluded
	case writes:
		return ManagementEventsWriteOnly, sourcesExcluded
	case reads:
		return ManagementEventsReadOnly, false
	}
	return ManagementEventsNone, false
}

// advancedManagementEvents reports whether an advanced selector records
// management reads and writes, and whether it leaves out an event source.
func advancedManagementEvents(fields []cloudtrailtypes.AdvancedFieldSelector) (reads, writes, sourcesExcluded bool) {
	management := false
	reads, writes = true, true
	for _, f := range fields {
		switch aws.ToString(f.Field) {
		case "eventCategory":
			management = slices.Contains(f.Equals, "Management")
		case "readOnly":
			switch {
			case slices.Contains(f.Equals, "true") || slices.Contains(f.NotEquals, "false"):
				writes = false
			case slices.Contains(f.Equals, "false") || slices.Contains(f.NotEquals, "true"):
				reads = false
			}
		case "eventSource":
			sourcesExcluded = true
		}
	}
	if !management {
		return false, false, false
	}
	return reads, writes, sourcesExcluded
}

// TrailListingIncompleteError is why the trails of some regions could not be
// listed, when another region's could.
type TrailListingIncompleteError struct {
	Regions []string
	Err     error
}

func (e *TrailListingIncompleteError) Error() string {
	return fmt.Sprintf("describing trails in %s: %v", strings.Join(e.Regions, ", "), e.Err)
}

func (e *TrailListingIncompleteError) Unwrap() error {
	return e.Err
}

// TrailSelectorsUnavailableError is why a trail's event selectors could not
// be read.
type TrailSelectorsUnavailableError struct {
	TrailName string
	Err       error
}

func (e *TrailSelectorsUnavailableError) Error() string {
	return fmt.Sprintf("getting event selectors for %s: %v", e.TrailName, e.Err)
}

func (e *TrailSelectorsUnavailableError) Unwrap() error {
	return e.Err
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
// counts as coverage. The trail's ARN holds the account that owns it, and a
// failed read of a trail accountID owns leaves the status unknown. Any other
// failure leaves the status unknown too.
func shouldInferOrganizationTrailLogging(t cloudtrailtypes.Trail, accountID string, err error) bool {
	if err == nil || !aws.ToBool(t.IsOrganizationTrail) {
		return false
	}
	if owner := trailOwnerAccountID(aws.ToString(t.TrailARN)); owner == "" || owner == accountID {
		return false
	}
	return componentsdk.Classify(err) == componentsdk.CodePermissionDenied || isAPIErrorCode(err, "TrailNotFoundException")
}

// trailOwnerAccountID is the account in a trail's ARN,
// arn:<partition>:cloudtrail:<region>:<account>:trail/<name>, or "" when the
// ARN has none.
func trailOwnerAccountID(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 || parts[0] != "arn" || parts[2] != "cloudtrail" {
		return ""
	}
	return parts[4]
}

// listedTrail is a trail as one region's DescribeTrails listed it.
type listedTrail struct {
	trail  cloudtrailtypes.Trail
	region string
}

// uniqueListedTrails keeps each trail once, in the order first listed. A
// trail several regions list is kept as its home region listed it, and
// otherwise as the first region did. A trail with neither ARN nor name is
// kept as it is.
func uniqueListedTrails(listed []listedTrail) []listedTrail {
	out := make([]listedTrail, 0, len(listed))
	seen := make(map[string]int, len(listed))
	for _, l := range listed {
		key := cloudTrailSDKTrailIdentity(l.trail)
		if key == "" {
			out = append(out, l)
			continue
		}
		i, ok := seen[key]
		switch {
		case !ok:
			seen[key] = len(out)
			out = append(out, l)
		case out[i].region != aws.ToString(out[i].trail.HomeRegion) && l.region == aws.ToString(l.trail.HomeRegion):
			out[i] = l
		}
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
			recorder.IncludeGlobal = recordsGlobalIAMTypes(r.RecordingGroup) && slices.Contains(regionsWithGlobalIAMRecording, region)
		}
		recorder.Recording = statusMap[recorder.Name]
		recorders = append(recorders, recorder)
	}

	return recorders, nil
}

// regionsWithGlobalIAMRecording are the regions where AWS Config was
// available before February 2022. Only these can record the global IAM
// resource types. A region Config reached later cannot, so no region is
// ever added to this list.
var regionsWithGlobalIAMRecording = []string{
	"af-south-1", "ap-east-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
	"ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ca-central-1",
	"cn-north-1", "cn-northwest-1", "eu-central-1", "eu-north-1", "eu-south-1",
	"eu-west-1", "eu-west-2", "eu-west-3", "me-south-1", "sa-east-1",
	"us-east-1", "us-east-2", "us-gov-east-1", "us-gov-west-1", "us-west-1", "us-west-2",
}

// globalIAMResourceTypes are the global resource types a Config recorder can
// record: IAM users, groups, roles, and customer managed policies.
var globalIAMResourceTypes = []configtypes.ResourceType{
	configtypes.ResourceTypeUser, configtypes.ResourceTypeGroup,
	configtypes.ResourceTypeRole, configtypes.ResourceTypePolicy,
}

// recordsGlobalIAMTypes reports whether a recording group records any of the
// global IAM resource types. includeGlobalResourceTypes adds them to an
// all-supported recorder only. An exclusion strategy records them unless it
// excludes them, and an inclusion strategy records the ones it lists.
func recordsGlobalIAMTypes(group *configtypes.RecordingGroup) bool {
	strategy := configtypes.RecordingStrategyType("")
	if group.RecordingStrategy != nil {
		strategy = group.RecordingStrategy.UseOnly
	}
	switch {
	case group.AllSupported || strategy == configtypes.RecordingStrategyTypeAllSupportedResourceTypes:
		return group.IncludeGlobalResourceTypes
	case strategy == configtypes.RecordingStrategyTypeExclusionByResourceTypes:
		var excluded []configtypes.ResourceType
		if group.ExclusionByResourceTypes != nil {
			excluded = group.ExclusionByResourceTypes.ResourceTypes
		}
		for _, t := range globalIAMResourceTypes {
			if !slices.Contains(excluded, t) {
				return true
			}
		}
		return false
	}
	for _, t := range globalIAMResourceTypes {
		if slices.Contains(group.ResourceTypes, t) {
			return true
		}
	}
	return false
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

// describeLastEvaluationByConfigRule returns the time each rule last
// evaluated successfully. A rule whose evaluations have only failed has
// none.
func describeLastEvaluationByConfigRule(ctx context.Context, client *configservice.Client) (map[string]*time.Time, error) {
	out := map[string]*time.Time{}
	var nextToken *string
	for {
		resp, err := client.DescribeConfigRuleEvaluationStatus(ctx, &configservice.DescribeConfigRuleEvaluationStatusInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("describing config rule evaluation status: %w", err)
		}
		for _, s := range resp.ConfigRulesEvaluationStatus {
			if s.LastSuccessfulEvaluationTime != nil {
				out[aws.ToString(s.ConfigRuleName)] = s.LastSuccessfulEvaluationTime
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
// that could not be read keeps its error on the detector. The counts cover
// accountID's own findings, as guardDutyFindingCriteria selects them.
func (c *AWSClient) ListGuardDutyDetectors(ctx context.Context, region, accountID string) ([]GuardDutyDetector, error) {
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

		detector.HighOrCriticalFindings, detector.FindingsErr = c.countGuardDutyFindings(ctx, gdClient, id, guardDutyFindingCriteria(accountID))

		staleHighSeverityCriteria := guardDutyFindingCriteria(accountID)
		staleHighSeverityCriteria["updatedAt"] = guarddutytypes.Condition{
			LessThanOrEqual: aws.Int64(c.now().Add(-48 * time.Hour).UnixMilli()),
		}
		detector.HighOrCriticalFindingsOlderThan48Hours, detector.StaleFindingsErr = c.countGuardDutyFindings(ctx, gdClient, id, staleHighSeverityCriteria)

		detectors = append(detectors, detector)
	}

	return detectors, nil
}

// guardDutyFindingCriteria selects accountID's unarchived findings of
// severity 7 or more. An administrator's detector also holds its members'
// findings, which carry their own accountId. ListFindings has no criterion
// for sample findings, so they match too.
func guardDutyFindingCriteria(accountID string) map[string]guarddutytypes.Condition {
	criteria := map[string]guarddutytypes.Condition{
		"severity":         {GreaterThanOrEqual: aws.Int64(7)},
		"service.archived": {Equals: []string{"false"}},
	}
	if accountID != "" {
		criteria["accountId"] = guarddutytypes.Condition{Equals: []string{accountID}}
	}
	return criteria
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

// ListGuardDutyFindings returns up to maxFindings of accountID's unarchived
// high-or-critical (severity >= 7) findings for the given detector, with
// sample findings marked. The boolean return is true when more findings exist
// than maxFindings (the caller should record a truncation warning). Sorted by
// severity DESC then updatedAt DESC so a truncated result keeps the most
// actionable findings.
func (c *AWSClient) ListGuardDutyFindings(ctx context.Context, region, detectorID, accountID string, maxFindings int) ([]GuardDutyFinding, bool, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	gdClient := guardduty.NewFromConfig(cfg)

	ids, truncated, err := listGuardDutyFindingIDs(ctx, gdClient, detectorID, guardDutyFindingCriteria(accountID), maxFindings)
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
	if f.Service != nil && f.Service.AdditionalInfo != nil {
		row.Sample = guardDutySampleInfo(aws.ToString(f.Service.AdditionalInfo.Value))
	}
	return row
}

// guardDutySampleInfo reports whether a finding's additionalInfo value holds
// "sample": true. The value is a JSON object, and sample findings have that
// key set.
func guardDutySampleInfo(value string) bool {
	var info struct {
		Sample bool `json:"sample"`
	}
	return json.Unmarshal([]byte(value), &info) == nil && info.Sample
}

// guardDutyResourceID extracts the most identifying ID from a finding's
// Resource block. A finding can carry the details of several resources, such
// as an S3 finding with the caller's access key, and its resourceType names
// the affected one. The ID of that resource comes first. Otherwise the ID is
// taken from the first details block present.
func guardDutyResourceID(r *guarddutytypes.Resource) string {
	var instance, accessKey, bucket, eks, workload, ecs, container, rdsInstance, rdsLimitless, lambda string
	if r.InstanceDetails != nil {
		instance = aws.ToString(r.InstanceDetails.InstanceId)
	}
	if r.AccessKeyDetails != nil {
		accessKey = aws.ToString(r.AccessKeyDetails.AccessKeyId)
	}
	if len(r.S3BucketDetails) > 0 {
		bucket = aws.ToString(r.S3BucketDetails[0].Name)
	}
	if r.EksClusterDetails != nil {
		eks = aws.ToString(r.EksClusterDetails.Name)
	}
	if r.KubernetesDetails != nil && r.KubernetesDetails.KubernetesWorkloadDetails != nil {
		workload = aws.ToString(r.KubernetesDetails.KubernetesWorkloadDetails.Name)
	}
	if r.EcsClusterDetails != nil {
		ecs = aws.ToString(r.EcsClusterDetails.Name)
	}
	if r.ContainerDetails != nil {
		container = cmp.Or(aws.ToString(r.ContainerDetails.Id), aws.ToString(r.ContainerDetails.Name))
	}
	if r.RdsDbInstanceDetails != nil {
		rdsInstance = aws.ToString(r.RdsDbInstanceDetails.DbInstanceIdentifier)
	}
	if r.RdsLimitlessDbDetails != nil {
		rdsLimitless = aws.ToString(r.RdsLimitlessDbDetails.DbShardGroupIdentifier)
	}
	if r.LambdaDetails != nil {
		lambda = aws.ToString(r.LambdaDetails.FunctionName)
	}
	var affected string
	switch aws.ToString(r.ResourceType) {
	case "Instance":
		affected = instance
	case "AccessKey":
		affected = accessKey
	case "S3Bucket", "S3Object":
		affected = bucket
	case "ECSCluster":
		affected = ecs
	case "Container":
		affected = container
	case "RDSDBInstance":
		affected = rdsInstance
	case "RDSLimitlessDB":
		affected = rdsLimitless
	case "Lambda":
		affected = lambda
	}
	return cmp.Or(affected, instance, accessKey, bucket, eks, workload, ecs, container, rdsInstance, rdsLimitless, lambda)
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
		AutoEnableControls: hubOutput.AutoEnableControls,
	}
	if hubOutput.AutoEnableControls == nil {
		config.AutoEnableControlsErr = errMissing(hubOutput.ResultMetadata, "describing Security Hub", "AutoEnableControls")
	}

	// Get enabled standards, every page.
	config.StandardsARNs = []string{}
	standards := securityhub.NewGetEnabledStandardsPaginator(shClient, &securityhub.GetEnabledStandardsInput{})
	for standards.HasMorePages() {
		page, err := standards.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting enabled Security Hub standards: %w", err)
		}
		for _, s := range page.StandardsSubscriptions {
			config.StandardsARNs = append(config.StandardsARNs, aws.ToString(s.StandardsArn))
		}
	}

	// Get integrations, every page.
	products := []string{}
	integrations := securityhub.NewListEnabledProductsForImportPaginator(shClient, &securityhub.ListEnabledProductsForImportInput{})
	for integrations.HasMorePages() {
		page, err := integrations.NextPage(ctx)
		if err != nil {
			config.IntegrationsErr = fmt.Errorf("listing Security Hub integrations: %w", err)
			return config, nil
		}
		products = append(products, page.ProductSubscriptions...)
	}
	config.IntegrationCount = len(products)
	config.ProductSubscriptions = products

	return config, nil
}

// GetSecurityHubCISComplianceByLevel returns control-level compliance counts
// for CIS levels 1, 2, and unknown from accountID's findings. GetFindings in
// an administrator account also returns its members' findings, which are not
// the account's. Security Hub derives a control's status from
// its active findings that are not suppressed, so archived and suppressed
// findings are left out too.
func (c *AWSClient) GetSecurityHubCISComplianceByLevel(ctx context.Context, region, accountID, standardID string) (*SecurityHubCISComplianceByLevel, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	shClient := securityhub.NewFromConfig(cfg)

	filters := &securityhubtypes.AwsSecurityFindingFilters{
		AwsAccountId: accountFilter(accountID),
		ComplianceAssociatedStandardsId: []securityhubtypes.StringFilter{
			{
				Comparison: securityhubtypes.StringFilterComparisonEquals,
				Value:      aws.String(standardID),
			},
		},
		RecordState: []securityhubtypes.StringFilter{
			{
				Comparison: securityhubtypes.StringFilterComparisonEquals,
				Value:      aws.String(string(securityhubtypes.RecordStateActive)),
			},
		},
		WorkflowStatus: []securityhubtypes.StringFilter{
			{
				Comparison: securityhubtypes.StringFilterComparisonNotEquals,
				Value:      aws.String(string(securityhubtypes.WorkflowStatusSuppressed)),
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
			if !findingOfAccount(finding, accountID) || !findingDrivesControlStatus(finding) {
				continue
			}
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

// accountFilter limits GetFindings to the findings of accountID.
func accountFilter(accountID string) []securityhubtypes.StringFilter {
	return []securityhubtypes.StringFilter{{
		Comparison: securityhubtypes.StringFilterComparisonEquals,
		Value:      aws.String(accountID),
	}}
}

// findingOfAccount reports whether a finding is accountID's own.
func findingOfAccount(finding securityhubtypes.AwsSecurityFinding, accountID string) bool {
	return aws.ToString(finding.AwsAccountId) == accountID
}

// findingDrivesControlStatus reports whether Security Hub counts a finding
// toward its control's status: an active finding that is not suppressed.
func findingDrivesControlStatus(finding securityhubtypes.AwsSecurityFinding) bool {
	if finding.RecordState == securityhubtypes.RecordStateArchived {
		return false
	}
	return finding.Workflow == nil || finding.Workflow.Status != securityhubtypes.WorkflowStatusSuppressed
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

// GetInspectorSummaryFromSecurityHub returns Inspector patching metrics based
// on accountID's Security Hub findings. GetFindings in an administrator
// account also returns its members' findings, which are left out.
func (c *AWSClient) GetInspectorSummaryFromSecurityHub(ctx context.Context, region, accountID string) (*InspectorSummary, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	shClient := securityhub.NewFromConfig(cfg)

	filters := &securityhubtypes.AwsSecurityFindingFilters{
		AwsAccountId: accountFilter(accountID),
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
			if !findingOfAccount(finding, accountID) {
				continue
			}
			summary.TotalFindings++

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
// countAnalyzerFindings counts an analyzer's active and archived findings.
// ListFindings supports only external access analyzers, so an unused access
// or internal access analyzer's findings are listed with ListFindingsV2.
func (c *AWSClient) countAnalyzerFindings(ctx context.Context, client *accessanalyzer.Client, analyzer *AccessAnalyzer) {
	count := func(status accessanalyzertypes.FindingStatus) {
		switch status {
		case accessanalyzertypes.FindingStatusActive:
			analyzer.ActiveFindingsCount++
		case accessanalyzertypes.FindingStatusArchived:
			analyzer.ArchivedFindingsCount++
		}
	}
	fail := func(err error) {
		analyzer.FindingsUnresolved = true
		analyzer.FindingsErr = fmt.Errorf("listing findings for analyzer %s: %w", analyzer.Name, err)
		analyzer.ActiveFindingsCount = 0
		analyzer.ArchivedFindingsCount = 0
		analyzer.RoleFindings = nil
		analyzer.UnusedFindings = nil
	}
	switch accessanalyzertypes.Type(analyzer.Type) {
	case accessanalyzertypes.TypeAccount, accessanalyzertypes.TypeOrganization:
		paginator := accessanalyzer.NewListFindingsPaginator(client, &accessanalyzer.ListFindingsInput{
			AnalyzerArn: aws.String(analyzer.ARN),
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				fail(err)
				return
			}
			for _, f := range page.Findings {
				count(f.Status)
				if f.ResourceType == accessanalyzertypes.ResourceTypeAwsIamRole {
					if analyzer.RoleFindings == nil {
						analyzer.RoleFindings = map[string]string{}
					}
					analyzer.RoleFindings[roleFindingKey(f)] = string(f.Status)
				}
			}
		}
	default:
		paginator := accessanalyzer.NewListFindingsV2Paginator(client, &accessanalyzer.ListFindingsV2Input{
			AnalyzerArn: aws.String(analyzer.ARN),
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				fail(err)
				return
			}
			for _, f := range page.Findings {
				count(f.Status)
				if isUnusedAccessAnalyzer(analyzer.Type) {
					if analyzer.UnusedFindings == nil {
						analyzer.UnusedFindings = map[string]UnusedFindingTally{}
					}
					key := unusedFindingKey(f)
					analyzer.UnusedFindings[key] = UnusedFindingTally{Status: string(f.Status), Count: analyzer.UnusedFindings[key].Count + 1}
				}
			}
		}
	}
}

// isUnusedAccessAnalyzer reports whether analyzerType is an unused access
// analyzer, for one account or for the organization.
func isUnusedAccessAnalyzer(analyzerType string) bool {
	switch accessanalyzertypes.Type(analyzerType) {
	case accessanalyzertypes.TypeAccountUnusedAccess, accessanalyzertypes.TypeOrganizationUnusedAccess:
		return true
	}
	return false
}

// unusedFindingKey identifies an unused access finding by the resource, its
// owner account, the finding type and the status. A finding's ID differs
// between analyzers, so the ID is left out.
func unusedFindingKey(f accessanalyzertypes.FindingSummaryV2) string {
	return strings.Join([]string{
		aws.ToString(f.Resource), aws.ToString(f.ResourceOwnerAccount), string(f.FindingType), string(f.Status),
	}, "|")
}

// roleFindingKey identifies an IAM role finding by the role, the access it
// grants and its status. The same finding has a different ID in each region,
// so the ID is left out.
func roleFindingKey(f accessanalyzertypes.FindingSummary) string {
	sortedPairs := func(m map[string]string) string {
		pairs := make([]string, 0, len(m))
		for k, v := range m {
			pairs = append(pairs, k+"="+v)
		}
		slices.Sort(pairs)
		return strings.Join(pairs, ",")
	}
	actions := slices.Clone(f.Action)
	slices.Sort(actions)
	return strings.Join([]string{
		aws.ToString(f.Resource), string(f.Status), sortedPairs(f.Principal), sortedPairs(f.Condition),
		strings.Join(actions, ","), strconv.FormatBool(aws.ToBool(f.IsPublic)),
	}, "|")
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
