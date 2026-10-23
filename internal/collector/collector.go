// Package collector provides AWS account posture collection functionality.
package collector

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// Collector collects AWS account security posture.
type Collector struct {
	config   Config
	warnings []string         // Service-level warnings accumulated during collection
	gaps     *gapLog          // Values left out of the artifacts, and why
	now      func() time.Time // The run's clock
}

// ErrNoUsableAccounts means no accounts were configured and the implicit
// default-credentials account could not be collected either. The remedy is
// configuration (add accounts or working AWS credentials), so callers map
// this to a config error rather than a network error.
var ErrNoUsableAccounts = errors.New("no accounts configured and default AWS credentials are unavailable")

// warn records a service-level warning for diagnostics.
func (c *Collector) warn(format string, args ...interface{}) {
	c.warnings = append(c.warnings, fmt.Sprintf(format, args...))
}

// status reports an indeterminate status update.
func (c *Collector) status(message string) {
	if c.config.OnStatus != nil {
		c.config.OnStatus(message)
	}
}

// progress reports a determinate progress update.
func (c *Collector) progress(current, total int64, message string) {
	if c.config.OnProgress != nil {
		c.config.OnProgress(current, total, message)
	}
}

// New creates a new Collector with the given configuration.
func New(config Config) (*Collector, error) {
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Collector{config: config, gaps: newGapLog(config.Recorder), now: now}, nil
}

// regionCopy returns a Collector for one concurrent region scan: it shares
// the configuration, clock, and gap log, and buffers its own warnings.
func (c *Collector) regionCopy() *Collector {
	return &Collector{config: c.config, gaps: c.gaps, now: c.now}
}

// Collect fetches and aggregates security posture metrics for all configured accounts.
// level controls the depth of collection (trust / audit / internal). Unknown or empty
// levels are treated as LevelTrust by the SDK reader; callers should not pre-validate.
// See the README for the per-surface field availability per level.
func (c *Collector) Collect(ctx context.Context, level componentsdk.Level) (*Output, error) {
	output := NewOutput(c.now())
	output.CollectedAtLevel = string(level)

	// Reset service-level warnings from any previous run
	c.warnings = nil

	// Determine which accounts to collect from
	accounts := c.config.Accounts
	if len(accounts) == 0 {
		// Use default credentials for current account
		accounts = []AccountConfig{{}}
	}

	total := int64(len(accounts))
	c.status("Starting AWS posture collection")

	// Track account errors and warnings for diagnostics
	var accountErrors []string
	var accountFailures []error
	var warnings []string

	// Determine effective auth mode and initialize
	authMode, oidcWarnings, err := c.initializeAuth(accounts)
	if err != nil {
		return nil, componentsdk.ConfigError{Err: err}
	}
	warnings = append(warnings, oidcWarnings...)

	// Collect from each account
	for i, acct := range accounts {
		c.progress(int64(i+1), total, fmt.Sprintf("Collecting account %d of %d", i+1, len(accounts)))

		posture, err := c.collectAccount(ctx, acct, authMode, level, len(output.Accounts))
		if err != nil {
			errMsg := formatAccountError(acct, err)
			accountErrors = append(accountErrors, errMsg)
			accountFailures = append(accountFailures, fmt.Errorf("%s: %w", accountRef(acct), err))
			output.FailedAccounts = append(output.FailedAccounts, FailedAccountRecord{
				AccountID: accountIDFromRoleARN(acct.RoleARN),
				RoleARN:   acct.RoleARN,
				Label:     acct.Label,
				ErrorCode: apiErrorCode(err),
				err:       err,
			})
			c.status(errMsg)
			continue
		}
		posture.AccountLabel = acct.Label
		output.Accounts = append(output.Accounts, *posture)
	}

	// Combine all warnings (auth warnings + service-level warnings)
	allWarnings := append(warnings, c.warnings...)

	// Add diagnostics if there were any errors or warnings
	if len(accountErrors) > 0 || len(allWarnings) > 0 {
		output.Diagnostics = &Diagnostics{
			AccountErrors: accountErrors,
			Warnings:      allWarnings,
		}
	}

	// Partial failure emits stubs and succeeds; total failure fails the run
	// with the first account's code, since every account failed to sign in.
	// With no accounts configured, the implicit default-credentials account
	// failing is a configuration problem unless AWS rejected the credentials
	// it found: report it as such so an unconfigured run exits with the
	// config error code.
	if len(output.Accounts) == 0 && len(accountErrors) > 0 {
		if len(c.config.Accounts) == 0 {
			switch componentsdk.Classify(accountFailures[0]) {
			case componentsdk.CodeAuthFailed, componentsdk.CodePermissionDenied:
				return nil, accountFailures[0]
			}
			return nil, componentsdk.ConfigError{Err: fmt.Errorf("%w: %s", ErrNoUsableAccounts, strings.Join(accountErrors, "; "))}
		}
		return nil, fmt.Errorf("all %d configured accounts failed: %w", len(accounts), errors.Join(accountFailures...))
	}

	c.status("Collection complete")
	return output, nil
}

// collectAccount collects posture for a single AWS account, which will be
// entry index of the artifact's accounts. Only the sign-in fails it; every
// later read that fails leaves its values out with a gap.
func (c *Collector) collectAccount(ctx context.Context, acctConfig AccountConfig, authMode string, level componentsdk.Level, index int) (*AccountPosture, error) {
	steps := &stepper{ctx: ctx}
	defer steps.end()

	signIn := steps.next("sign_in", "Sign in")
	client, err := c.createClient(signIn, acctConfig, authMode)
	if err != nil {
		return nil, err
	}

	// Get account ID
	identity, err := client.GetCallerIdentity(signIn)
	if err != nil {
		return nil, fmt.Errorf("getting account ID: %w", err)
	}
	accountID := identity.Account
	c.status(fmt.Sprintf("Connected to account %s", accountID))
	if index == 0 {
		c.signedInAs(identity, client.AuthMethod())
	}
	at := accountAt(index)

	// Determine regions to scan. Without the region list, nothing regional
	// can be measured, so every regional surface is left out.
	accountCtx := steps.next("account", "Account alias and regions")
	regions, err := c.getRegions(accountCtx, client)
	if err != nil {
		c.warn("account %s: failed to list enabled regions: %v", accountID, err)
		posture := NewAccountPosture(accountID, nil)
		c.collectAccountAlias(accountCtx, client, accountID, at, posture)
		c.collectGlobalMetrics(steps, client, accountID, at, posture, level)
		posture.AccountSecurity = *c.collectCloudTrailOnly(steps.next("cloudtrail", "CloudTrail trails"), client, accountID, at, &posture.S3, level)
		c.gaps.leaveOut(err, at.p("regions"))
		c.leaveOutRegional(err, at)
		normalizeForLevel(posture, level)
		return posture, nil
	}

	posture := NewAccountPosture(accountID, regions)
	c.collectAccountAlias(accountCtx, client, accountID, at, posture)

	// Collect global metrics (IAM, S3, CloudFront)
	c.collectGlobalMetrics(steps, client, accountID, at, posture, level)

	// Collect regional metrics (RDS, Network, Lambda, EC2, CloudWatch Logs, KMS, Secrets Manager, SSM, WAF)
	steps.end()
	c.status(fmt.Sprintf("Scanning %d regions", len(regions)))
	c.collectRegionalMetrics(ctx, client, regions, accountID, at, posture, level)

	// Collect account security services
	c.collectSecurityServices(steps, client, regions, at, posture, level)

	// Strict-superset normalization: at audit+, every level-gated array is
	// non-nil so consumers can rely on []  vs `null` to distinguish "fleet
	// empty" from "field not collected at this level" without consulting
	// collected_at_level.
	normalizeForLevel(posture, level)

	return posture, nil
}

// collectAccountAlias reads the account alias, leaving it out with a gap
// when the read fails.
func (c *Collector) collectAccountAlias(ctx context.Context, client *aws.AWSClient, accountID string, at at, posture *AccountPosture) {
	alias, err := client.GetAccountAlias(ctx)
	if err != nil {
		c.warn("account %s: failed to read the account alias: %v", accountID, err)
		c.gaps.leaveOut(err, at.p("account_alias"))
		return
	}
	posture.AccountAlias = alias
}

// regionalSurfaces are the parts of an account's posture measured per region,
// or in the primary region the region list names.
var regionalSurfaces = [][]any{
	{"rds"}, {"network"}, {"lambda"}, {"ec2"}, {"cloudwatch_logs"}, {"monitoring"},
	{"stored_images"}, {"load_balancers"}, {"ses"}, {"ecs"}, {"auto_scaling"}, {"waf"},
	{"kms"}, {"secrets_manager"}, {"ssm_parameters"}, {"identity_center"},
	{"account_security", "config"}, {"account_security", "guardduty"},
	{"account_security", "access_analyzer"}, {"account_security", "security_hub"},
	{"account_security", "inspector"},
}

// leaveOutRegional records every regional surface as left out because the
// region list could not be read.
func (c *Collector) leaveOutRegional(err error, at at) {
	c.gaps.rec.Helper()
	for _, surface := range regionalSurfaces {
		c.gaps.leaveOut(err, at.p(surface...))
	}
}

// collectCloudTrailOnly collects the account security surfaces that need no
// region list: CloudTrail and its delivery buckets.
func (c *Collector) collectCloudTrailOnly(ctx context.Context, client *aws.AWSClient, accountID string, at at, s3 *S3Metrics, level componentsdk.Level) *AccountSecurity {
	security := &AccountSecurity{}
	trailsAt := at.sub("account_security", "cloudtrail")
	trails := c.collectCloudTrailStatus(ctx, client, accountID, trailsAt, &security.CloudTrail, level)
	c.resolveTrailBucketRetention(ctx, client, accountID, trailsAt, trails, s3, &security.CloudTrail)
	c.recordCloudTrailUnread(trailsAt, &security.CloudTrail)
	return security
}

// signedInAs records the principal the run signed in as, the first
// account's role session or user, and how its credentials prove it.
func (c *Collector) signedInAs(identity aws.CallerIdentity, authMethod string) {
	if c.config.Recorder == nil {
		return
	}
	kind := "user"
	if strings.Contains(identity.ARN, ":assumed-role/") {
		kind = "role"
	}
	c.config.Recorder.SignedInAs(componentsdk.Principal{
		Provider:   "aws",
		Kind:       kind,
		TenantID:   identity.Account,
		AuthMethod: authMethod,
		ID:         identity.ARN,
	})
}

// clientOptions configures every AWS client the collector builds.
func (c *Collector) clientOptions() aws.Options {
	return aws.Options{HTTPClient: c.config.HTTPClient, Now: c.now, Wait: c.config.Wait}
}

// createClient creates an AWS client for the given account configuration.
func (c *Collector) createClient(ctx context.Context, acctConfig AccountConfig, authMode string) (*aws.AWSClient, error) {
	// No role ARN means use default credentials
	if acctConfig.RoleARN == "" {
		client, err := aws.NewClient(ctx, c.clientOptions())
		if err != nil {
			return nil, fmt.Errorf("creating AWS client: %w", err)
		}
		return client, nil
	}

	// Route based on auth mode
	switch authMode {
	case AuthModeOIDC:
		tokens := c.config.OIDC.TokenSource(ctx, c.config.HTTPClient)
		client, err := aws.NewClientWithWebIdentity(ctx, acctConfig.RoleARN, tokens, c.clientOptions())
		if err != nil {
			return nil, fmt.Errorf("creating AWS client with web identity: %w", err)
		}
		return client, nil

	case AuthModeAssumeRole:
		client, err := aws.NewClientWithRole(ctx, acctConfig.RoleARN, acctConfig.ExternalID, c.clientOptions())
		if err != nil {
			return nil, fmt.Errorf("creating AWS client with role: %w", err)
		}
		return client, nil

	default:
		return nil, fmt.Errorf("unknown auth_mode: %s", authMode)
	}
}

// getRegions returns the regions to scan, either from config or from AWS.
func (c *Collector) getRegions(ctx context.Context, client *aws.AWSClient) ([]string, error) {
	if len(c.config.Regions) > 0 {
		return c.config.Regions, nil
	}

	regions, err := client.GetEnabledRegions(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting enabled regions: %w", err)
	}
	return regions, nil
}

// collectGlobalMetrics collects the global services' metrics, IAM, S3, and
// CloudFront, each as a step. level is passed through to per-surface
// collectors that gate audit / internal fields.
func (c *Collector) collectGlobalMetrics(steps *stepper, client *aws.AWSClient, accountID string, at at, posture *AccountPosture, level componentsdk.Level) {
	posture.IAM = *c.collectIAMMetrics(steps.next("iam", "IAM users, roles, and password policy"), client, accountID, at, level)
	posture.S3 = *c.collectS3Metrics(steps.next("s3", "S3 buckets"), client, accountID, at, level)
	posture.CloudFront = *c.collectCloudFrontMetrics(steps.next("cloudfront", "CloudFront distributions"), client, accountID, level)
	c.recordUnread(at.sub("cloudfront"), posture.CloudFront.missing)
}

// regionScan holds one region's raw surface results and the warnings emitted
// while collecting them. Regions are scanned concurrently, so per-region
// results are assembled into the account aggregates afterward, in region
// order, keeping the output identical to a serial scan.
type regionScan struct {
	rds              *rdsMetricsWithCounts
	rdsErr           error
	network          *networkMetricsWithCounts
	networkErr       error
	lambda           *LambdaMetrics
	lambdaErr        error
	ec2              *EC2Metrics
	ec2Err           error
	cwLogs           *CloudWatchLogsMetrics
	cwLogsErr        error
	monitoring       *MonitoringMetrics
	monitoringErr    error
	storedImages     *StoredImageMetrics
	storedImagesErr  error
	loadBalancers    *LoadBalancerMetrics
	loadBalancersErr error
	ses              *SESMetrics
	sesErr           error
	ecs              *ECSMetrics
	ecsErr           error
	autoScaling      *AutoScalingMetrics
	autoScalingErr   error
	kms              *KMSMetrics
	kmsErr           error
	secrets          *SecretsManagerMetrics
	secretsErr       error
	ssm              *SSMParametersMetrics
	ssmErr           error
	waf              *wafRegionScan
	wafErr           error
	warnings         []string
}

// scanRegion collects every regional surface for one region, each in its
// step. It runs on its own Collector copy so concurrent regions buffer
// warnings independently; the caller replays them in region order.
func (c *Collector) scanRegion(steps *regionalSteps, client *aws.AWSClient, region, accountID string, level componentsdk.Level) regionScan {
	rc := c.regionCopy()
	var s regionScan
	step := func(name, title string, collect func(ctx context.Context)) {
		collect(steps.enter(name, title))
		steps.leave(name)
	}

	step("rds", "RDS databases", func(ctx context.Context) {
		if s.rds, s.rdsErr = rc.collectRDSMetrics(ctx, client, region, level); s.rdsErr != nil {
			rc.warn("account %s region %s: failed to collect RDS metrics: %v", accountID, region, s.rdsErr)
		}
	})
	step("network", "VPCs and security groups", func(ctx context.Context) {
		if s.network, s.networkErr = rc.collectNetworkMetrics(ctx, client, region, accountID, level); s.networkErr != nil {
			rc.warn("account %s region %s: failed to collect network metrics: %v", accountID, region, s.networkErr)
		}
	})
	step("lambda", "Lambda functions", func(ctx context.Context) {
		if s.lambda, s.lambdaErr = rc.collectLambdaMetrics(ctx, client, region, accountID, level); s.lambdaErr != nil {
			rc.warn("account %s region %s: failed to collect Lambda metrics: %v", accountID, region, s.lambdaErr)
		}
	})
	step("ec2", "EC2 instances and volumes", func(ctx context.Context) {
		if s.ec2, s.ec2Err = rc.collectEC2Metrics(ctx, client, region, accountID, level); s.ec2Err != nil {
			rc.warn("account %s region %s: failed to collect EC2 metrics: %v", accountID, region, s.ec2Err)
		}
	})
	step("cloudwatch_logs", "CloudWatch log groups", func(ctx context.Context) {
		if s.cwLogs, s.cwLogsErr = rc.collectCloudWatchLogsMetrics(ctx, client, region, accountID, level); s.cwLogsErr != nil {
			rc.warn("account %s region %s: failed to collect CloudWatch Logs metrics: %v", accountID, region, s.cwLogsErr)
		}
	})
	step("monitoring", "CloudWatch alarms", func(ctx context.Context) {
		if s.monitoring, s.monitoringErr = rc.collectMonitoringMetrics(ctx, client, region, accountID, level); s.monitoringErr != nil {
			rc.warn("account %s region %s: failed to collect monitoring metrics: %v", accountID, region, s.monitoringErr)
		}
	})
	step("stored_images", "EBS snapshots and AMIs", func(ctx context.Context) {
		if s.storedImages, s.storedImagesErr = rc.collectStoredImageMetrics(ctx, client, region, accountID, level); s.storedImagesErr != nil {
			rc.warn("account %s region %s: failed to collect snapshot and AMI metrics: %v", accountID, region, s.storedImagesErr)
		}
	})
	step("load_balancers", "Load balancers", func(ctx context.Context) {
		if s.loadBalancers, s.loadBalancersErr = rc.collectLoadBalancerMetrics(ctx, client, region, accountID, level); s.loadBalancersErr != nil {
			rc.warn("account %s region %s: failed to collect load balancer metrics: %v", accountID, region, s.loadBalancersErr)
		}
	})
	step("ses", "SES configuration sets and identities", func(ctx context.Context) {
		if s.ses, s.sesErr = rc.collectSESMetrics(ctx, client, region, accountID, level); s.sesErr != nil {
			rc.warn("account %s region %s: failed to collect SES metrics: %v", accountID, region, s.sesErr)
		}
	})
	step("ecs", "ECS services", func(ctx context.Context) {
		if s.ecs, s.ecsErr = rc.collectECSMetrics(ctx, client, region, accountID, level); s.ecsErr != nil {
			rc.warn("account %s region %s: failed to collect ECS metrics: %v", accountID, region, s.ecsErr)
		}
	})
	step("auto_scaling", "Auto Scaling groups", func(ctx context.Context) {
		if s.autoScaling, s.autoScalingErr = rc.collectAutoScalingMetrics(ctx, client, region, accountID, level); s.autoScalingErr != nil {
			rc.warn("account %s region %s: failed to collect auto scaling metrics: %v", accountID, region, s.autoScalingErr)
		}
	})
	step("kms", "KMS keys", func(ctx context.Context) {
		if s.kms, s.kmsErr = rc.collectKMSMetrics(ctx, client, region, accountID, level); s.kmsErr != nil {
			rc.warn("account %s region %s: failed to collect KMS metrics: %v", accountID, region, s.kmsErr)
		}
	})
	step("secrets_manager", "Secrets Manager secrets", func(ctx context.Context) {
		if s.secrets, s.secretsErr = rc.collectSecretsManagerMetrics(ctx, client, region, accountID, level); s.secretsErr != nil {
			rc.warn("account %s region %s: failed to collect Secrets Manager metrics: %v", accountID, region, s.secretsErr)
		}
	})
	step("ssm_parameters", "SSM parameters", func(ctx context.Context) {
		if s.ssm, s.ssmErr = rc.collectSSMParameters(ctx, client, region, accountID, level); s.ssmErr != nil {
			rc.warn("account %s region %s: failed to collect SSM parameters: %v", accountID, region, s.ssmErr)
		}
	})
	step("waf", wafStepTitle, func(ctx context.Context) {
		if s.waf, s.wafErr = rc.collectWAFRegion(ctx, client, region); s.wafErr != nil {
			rc.warn("account %s region %s: failed to collect WAF metrics: %v", accountID, region, s.wafErr)
		}
	})

	s.warnings = rc.warnings
	return s
}

// wafStepTitle is the WAF step's title, which the regions and the
// account-wide pass over the CloudFront scope share.
const wafStepTitle = "WAF web ACLs"

// collectRegionalMetrics scans every region concurrently and populates the
// posture's regional surfaces, including the WAF posture, which joins the
// regional scans with the global CLOUDFRONT scope. level is passed through
// to per-surface collectors that gate audit / internal fields. A surface that
// failed in any region is left out whole; a value a narrower read left
// unknown is left out on its own.
func (c *Collector) collectRegionalMetrics(ctx context.Context, client *aws.AWSClient, regions []string, accountID string, at at, posture *AccountPosture, level componentsdk.Level) {
	rdsMetrics := rdsMetricsWithCounts{minRetention: -1}
	var networkMetrics networkMetricsWithCounts
	var wafScan wafScanWithCounts
	var wafErr error

	var rdsRegionsFailed, networkRegionsFailed []string

	total := int64(len(regions))
	var scanned int64
	var progressMu sync.Mutex
	steps := newRegionalSteps(ctx, len(regions), "waf")
	scans := mapConcurrent(regions, regionConcurrency, func(region string) regionScan {
		progressMu.Lock()
		scanned++
		c.progress(scanned, total, fmt.Sprintf("Scanning region %s", region))
		progressMu.Unlock()
		return c.scanRegion(steps, client, region, accountID, level)
	})

	// failed records a surface as left out because of the first region it
	// failed in.
	failed := func(surface string, err error) bool {
		c.gaps.rec.Helper()
		if err == nil {
			return false
		}
		c.gaps.leaveOut(err, at.p(surface))
		return true
	}

	for i, region := range regions {
		s := scans[i]
		c.warnings = append(c.warnings, s.warnings...)

		if !failed("rds", s.rdsErr) {
			rdsMetrics = mergeRDSMetrics(rdsMetrics, *s.rds)
			rdsMetrics.RegionsEvaluatedCount++
		} else {
			rdsRegionsFailed = append(rdsRegionsFailed, region)
		}

		if !failed("network", s.networkErr) {
			networkMetrics = mergeNetworkMetrics(networkMetrics, *s.network)
			networkMetrics.RegionsEvaluatedCount++
		} else {
			networkRegionsFailed = append(networkRegionsFailed, region)
		}

		if !failed("lambda", s.lambdaErr) {
			posture.Lambda = mergeLambdaMetrics(posture.Lambda, *s.lambda)
		}
		if !failed("ec2", s.ec2Err) {
			posture.EC2 = mergeEC2Metrics(posture.EC2, *s.ec2)
		}
		if !failed("cloudwatch_logs", s.cwLogsErr) {
			posture.CloudWatchLogs = mergeCloudWatchLogsMetrics(posture.CloudWatchLogs, *s.cwLogs)
		}
		if !failed("monitoring", s.monitoringErr) {
			posture.Monitoring = mergeMonitoringMetrics(posture.Monitoring, *s.monitoring)
		}
		if !failed("stored_images", s.storedImagesErr) {
			posture.StoredImages = mergeStoredImageMetrics(posture.StoredImages, *s.storedImages)
		}
		if !failed("load_balancers", s.loadBalancersErr) {
			posture.LoadBalancers = mergeLoadBalancerMetrics(posture.LoadBalancers, *s.loadBalancers)
		}
		if !failed("ses", s.sesErr) {
			posture.SES = mergeSESMetrics(posture.SES, *s.ses)
		}
		if !failed("ecs", s.ecsErr) {
			posture.ECS = mergeECSMetrics(posture.ECS, *s.ecs)
		}
		if !failed("auto_scaling", s.autoScalingErr) {
			posture.AutoScaling = mergeAutoScalingMetrics(posture.AutoScaling, *s.autoScaling)
		}
		if !failed("kms", s.kmsErr) {
			posture.KMS = mergeKMSMetrics(posture.KMS, *s.kms)
		}
		if !failed("secrets_manager", s.secretsErr) {
			posture.SecretsManager = mergeSecretsManagerMetrics(posture.SecretsManager, *s.secrets)
		}
		if !failed("ssm_parameters", s.ssmErr) {
			posture.SSMParameters = mergeSSMParametersMetrics(posture.SSMParameters, *s.ssm)
		}
		if s.wafErr == nil {
			wafScan.wafRegionScan = mergeWAFScans(wafScan.wafRegionScan, *s.waf)
			wafScan.RegionsEvaluatedCount++
		} else if wafErr == nil {
			wafErr = s.wafErr
		}
	}

	rdsMetrics.RegionsFailed = rdsRegionsFailed
	rdsMetrics.finalize()
	networkMetrics.RegionsFailed = networkRegionsFailed
	networkMetrics.finalize()
	posture.RDS = rdsMetrics.RDSMetrics
	posture.Network = networkMetrics.NetworkMetrics

	if len(posture.Lambda.Functions) > 0 {
		kept, dropped, truncated := Truncate(posture.Lambda.Functions, LambdaFunctionsCap, func(a, b LambdaFunctionRow) bool {
			return a.LastModified > b.LastModified
		})
		posture.Lambda.Functions = kept
		posture.Lambda.FunctionsTruncated = truncated
		posture.Lambda.FunctionsDroppedCount = dropped
		if truncated {
			c.warn("account %s: Lambda function inventory truncated to %d (dropped %d)", accountID, LambdaFunctionsCap, dropped)
		}
	}

	if len(posture.EC2.Instances) > 0 {
		kept, dropped, truncated := Truncate(posture.EC2.Instances, EC2InstancesCap, func(a, b EC2InstanceRow) bool {
			return a.LaunchTime > b.LaunchTime
		})
		posture.EC2.Instances = kept
		posture.EC2.InstancesTruncated = truncated
		posture.EC2.InstancesDroppedCount = dropped
		if truncated {
			c.warn("account %s: EC2 instance inventory truncated to %d (dropped %d)", accountID, EC2InstancesCap, dropped)
		}
	}

	if len(posture.CloudWatchLogs.LogGroups) > 0 {
		kept, dropped, truncated := Truncate(posture.CloudWatchLogs.LogGroups, CloudWatchLogGroupsCap, func(a, b CloudWatchLogGroupRow) bool {
			return a.StoredBytes > b.StoredBytes
		})
		posture.CloudWatchLogs.LogGroups = kept
		posture.CloudWatchLogs.LogGroupsTruncated = truncated
		posture.CloudWatchLogs.LogGroupsDroppedCount = dropped
		if truncated {
			c.warn("account %s: CloudWatch log groups inventory truncated to %d (dropped %d)", accountID, CloudWatchLogGroupsCap, dropped)
		}
	}

	if len(posture.KMS.Keys) > 0 {
		kept, dropped, truncated := Truncate(posture.KMS.Keys, KMSKeysCap, func(a, b KMSKeyRow) bool {
			return a.CreationDate > b.CreationDate
		})
		posture.KMS.Keys = kept
		posture.KMS.KeysTruncated = truncated
		posture.KMS.KeysDroppedCount = dropped
		if truncated {
			c.warn("account %s: KMS key inventory truncated to %d (dropped %d)", accountID, KMSKeysCap, dropped)
		}
	}

	if len(posture.SecretsManager.Secrets) > 0 {
		kept, dropped, truncated := Truncate(posture.SecretsManager.Secrets, SecretsManagerSecretsCap, func(a, b SecretsManagerSecretRow) bool {
			return a.LastChangedDate > b.LastChangedDate
		})
		posture.SecretsManager.Secrets = kept
		posture.SecretsManager.SecretsTruncated = truncated
		posture.SecretsManager.SecretsDroppedCount = dropped
		if truncated {
			c.warn("account %s: Secrets Manager inventory truncated to %d (dropped %d)", accountID, SecretsManagerSecretsCap, dropped)
		}
	}

	if len(posture.SSMParameters.Parameters) > 0 {
		kept, dropped, truncated := Truncate(posture.SSMParameters.Parameters, SSMParametersCap, func(a, b SSMParameterRow) bool {
			return a.LastModifiedDate > b.LastModifiedDate
		})
		posture.SSMParameters.Parameters = kept
		posture.SSMParameters.ParametersTruncated = truncated
		posture.SSMParameters.ParametersDroppedCount = dropped
		if truncated {
			c.warn("account %s: SSM parameter inventory truncated to %d (dropped %d)", accountID, SSMParametersCap, dropped)
		}
	}

	posture.WAF = *c.collectWAFMetrics(steps.enter("waf", wafStepTitle), client, accountID, wafScan, level)
	steps.leave("waf")
	if wafErr != nil {
		posture.WAF.missing.add(wafErr, "internet_facing_alb_count", "covered_internet_facing_alb_count", "internet_facing_alb_coverage_pct", "web_acl_count", "rate_limiting_enforced")
		if level.AtLeast(componentsdk.LevelAudit) {
			posture.WAF.missing.add(wafErr, "web_acls")
		}
	}

	c.recordRegionalUnread(at, posture)
}

// recordRegionalUnread writes the values narrower reads left unknown, in the
// regional surfaces and their rows, as gaps.
func (c *Collector) recordRegionalUnread(at at, p *AccountPosture) {
	c.recordUnread(at.sub("rds"), p.RDS.missing)
	recordRowsUnread(c, at.sub("rds", "instances"), p.RDS.Instances, func(r *RDSInstance) unread { return r.missing })
	c.recordUnread(at.sub("network"), p.Network.missing)
	recordRowsUnread(c, at.sub("network", "vpcs"), p.Network.VPCs, func(r *VPCSummary) unread { return r.missing })
	c.recordUnread(at.sub("lambda"), p.Lambda.missing)
	recordRowsUnread(c, at.sub("lambda", "functions"), p.Lambda.Functions, func(r *LambdaFunctionRow) unread { return r.missing })
	c.recordUnread(at.sub("ec2"), p.EC2.missing)
	recordRowsUnread(c, at.sub("ec2", "instances"), p.EC2.Instances, func(r *EC2InstanceRow) unread { return r.missing })
	c.recordUnread(at.sub("monitoring"), p.Monitoring.missing)
	recordRowsUnread(c, at.sub("monitoring", "alarms"), p.Monitoring.Alarms, func(r *CloudWatchAlarmRow) unread { return r.missing })
	c.recordUnread(at.sub("stored_images"), p.StoredImages.missing)
	c.recordUnread(at.sub("load_balancers"), p.LoadBalancers.missing)
	recordRowsUnread(c, at.sub("load_balancers", "load_balancers"), p.LoadBalancers.LoadBalancers, func(r *LoadBalancerRow) unread { return r.missing })
	c.recordUnread(at.sub("ses"), p.SES.missing)
	recordRowsUnread(c, at.sub("ses", "configuration_sets"), p.SES.ConfigurationSets, func(r *SESConfigurationSetRow) unread { return r.missing })
	recordRowsUnread(c, at.sub("ses", "identities"), p.SES.Identities, func(r *SESIdentityRow) unread { return r.missing })
	c.recordUnread(at.sub("ecs"), p.ECS.missing)
	recordRowsUnread(c, at.sub("ecs", "services"), p.ECS.Services, func(r *ECSServiceRow) unread { return r.missing })
	c.recordUnread(at.sub("kms"), p.KMS.missing)
	recordRowsUnread(c, at.sub("kms", "keys"), p.KMS.Keys, func(r *KMSKeyRow) unread { return r.missing })
	c.recordUnread(at.sub("waf"), p.WAF.missing)
	recordRowsUnread(c, at.sub("waf", "web_acls"), p.WAF.WebACLs, func(r *WebACLRow) unread { return r.missing })
}

// collectSecurityServices collects account-level security service status,
// each service as a step. level is passed through to per-surface collectors
// that gate audit / internal fields.
func (c *Collector) collectSecurityServices(steps *stepper, client *aws.AWSClient, regions []string, at at, posture *AccountPosture, level componentsdk.Level) {
	primaryRegion := DefaultPrimaryRegion
	if len(regions) > 0 {
		primaryRegion = regions[0]
	}

	// collectAccountSecurity handles per-service warnings internally
	posture.AccountSecurity = *c.collectAccountSecurity(steps, client, primaryRegion, regions, posture.AccountID, at, &posture.S3, level)

	posture.IdentityCenter = c.collectIdentityCenter(steps.next("identity_center", "IAM Identity Center"), client, regions, posture.AccountID, at, level)
}

// resolveAuthMode determines the effective authentication mode based on config.
// If auth_mode is omitted, defaults to assume_role for backward compatibility.
// Returns empty string if no role ARNs are specified (will use default credentials).
func (c *Collector) resolveAuthMode(accounts []AccountConfig) (string, error) {
	// Check if any accounts have role ARNs (need auth mode selection)
	hasRoleARNs := false
	for _, acct := range accounts {
		if acct.RoleARN != "" {
			hasRoleARNs = true
			break
		}
	}

	// If no role ARNs, no auth mode needed (default credentials)
	if !hasRoleARNs {
		return "", nil
	}

	// Determine effective auth mode (default to assume_role for backward compatibility)
	authMode := c.config.AuthMode
	if authMode == "" {
		authMode = AuthModeAssumeRole
	}

	// Validate auth mode
	switch authMode {
	case AuthModeOIDC:
		if !c.config.OIDC.GitHubAvailable() && c.config.OIDC.TokenFile == "" {
			return "", fmt.Errorf("auth_mode is 'oidc' but no identity token is available: GitHub Actions did not set %s and %s, and %s does not name a token file", aws.GitHubTokenRequestURLEnv, aws.GitHubTokenRequestTokenEnv, aws.WebIdentityTokenFileEnv)
		}
	case AuthModeAssumeRole:
		// Valid, no additional checks needed
	default:
		return "", fmt.Errorf("invalid auth_mode %q: must be %q or %q", authMode, AuthModeOIDC, AuthModeAssumeRole)
	}

	return authMode, nil
}

// initializeAuth sets up authentication mode and returns any warnings. For
// OIDC mode, it checks for incompatible settings; each account's sign-in
// reads its own identity token.
func (c *Collector) initializeAuth(accounts []AccountConfig) (authMode string, warnings []string, err error) {
	authMode, err = c.resolveAuthMode(accounts)
	if err != nil {
		return "", nil, err
	}

	if authMode != AuthModeOIDC {
		return authMode, nil, nil
	}

	// Check for incompatible settings
	for _, acct := range accounts {
		if acct.ExternalID != "" {
			warnings = append(warnings, fmt.Sprintf("external_id is ignored in OIDC mode for role %s", acct.RoleARN))
		}
	}

	return authMode, warnings, nil
}

// accountIDFromRoleARN extracts the 12-digit account ID from a configured
// role ARN (arn:aws:iam::123456789012:role/name). Returns "" when the ARN is
// absent or malformed, e.g. an account collected with default credentials.
func accountIDFromRoleARN(roleARN string) string {
	parts := strings.Split(roleARN, ":")
	if len(parts) < 5 {
		return ""
	}
	id := parts[4]
	if len(id) != 12 {
		return ""
	}
	for _, r := range id {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return id
}

// formatAccountError creates a diagnostic error message for a failed account collection.
func formatAccountError(acct AccountConfig, err error) string {
	return fmt.Sprintf("failed to collect account (%s): %v", accountRef(acct), err)
}

// accountRef names an account by its label and role, or as the default
// credentials' account.
func accountRef(acct AccountConfig) string {
	roleInfo := "default credentials"
	if acct.RoleARN != "" {
		roleInfo = acct.RoleARN
	}
	if acct.Label != "" {
		roleInfo = acct.Label + ": " + roleInfo
	}
	return roleInfo
}
