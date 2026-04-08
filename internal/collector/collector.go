// Package collector provides AWS account posture collection functionality.
package collector

import (
	"context"
	"fmt"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

// Collector collects AWS account security posture.
type Collector struct {
	config      Config
	tokenSource *aws.GitHubOIDCTokenSource // Cached token source for OIDC mode
	warnings    []string                   // Service-level warnings accumulated during collection
}

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
	return &Collector{config: config}, nil
}

// Collect fetches and aggregates security posture metrics for all configured accounts.
func (c *Collector) Collect(ctx context.Context) (*Output, error) {
	output := NewOutput()

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
	var warnings []string

	// Determine effective auth mode and initialize
	authMode, oidcWarnings, err := c.initializeAuth(accounts)
	if err != nil {
		return nil, err
	}
	warnings = append(warnings, oidcWarnings...)

	// Collect from each account
	for i, acct := range accounts {
		c.progress(int64(i+1), total, fmt.Sprintf("Collecting account %d of %d", i+1, len(accounts)))

		posture, err := c.collectAccount(ctx, acct, authMode)
		if err != nil {
			errMsg := formatAccountError(acct, err)
			accountErrors = append(accountErrors, errMsg)
			c.status(errMsg)
			continue
		}
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

	c.status("Collection complete")
	return output, nil
}

// collectAccount collects posture for a single AWS account.
func (c *Collector) collectAccount(ctx context.Context, acctConfig AccountConfig, authMode string) (*AccountPosture, error) {
	// Create client for this account
	c.status("Connecting to AWS...")
	client, err := c.createClient(ctx, acctConfig, authMode)
	if err != nil {
		return nil, err
	}

	// Get account ID
	accountID, err := client.GetCallerIdentity(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting account ID: %w", err)
	}
	c.status(fmt.Sprintf("Connected to account %s", accountID))

	// Determine regions to scan
	regions, err := c.getRegions(ctx, client)
	if err != nil {
		return nil, err
	}
	c.status(fmt.Sprintf("Scanning %d regions", len(regions)))

	posture := NewAccountPosture(accountID, regions)

	// Get account alias
	alias, _ := client.GetAccountAlias(ctx)
	posture.AccountAlias = alias

	// Collect global metrics (IAM, S3)
	c.collectGlobalMetrics(ctx, client, accountID, posture)

	// Collect regional metrics (RDS, Network)
	rdsMetrics, networkMetrics := c.collectRegionalMetrics(ctx, client, regions, accountID)
	posture.RDS = rdsMetrics.RDSMetrics
	posture.Network = networkMetrics.NetworkMetrics

	// Collect account security services
	c.collectSecurityServices(ctx, client, regions, posture)

	return posture, nil
}

// createClient creates an AWS client for the given account configuration.
func (c *Collector) createClient(ctx context.Context, acctConfig AccountConfig, authMode string) (*aws.AWSClient, error) {
	// No role ARN means use default credentials
	if acctConfig.RoleARN == "" {
		client, err := aws.NewClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("creating AWS client: %w", err)
		}
		return client, nil
	}

	// Route based on auth mode
	switch authMode {
	case AuthModeOIDC:
		client, err := aws.NewClientWithWebIdentity(ctx, acctConfig.RoleARN, c.tokenSource)
		if err != nil {
			return nil, fmt.Errorf("creating AWS client with web identity: %w", err)
		}
		return client, nil

	case AuthModeAssumeRole:
		client, err := aws.NewClientWithRole(ctx, acctConfig.RoleARN, acctConfig.ExternalID)
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

// collectGlobalMetrics collects IAM and S3 metrics (global services).
func (c *Collector) collectGlobalMetrics(ctx context.Context, client *aws.AWSClient, accountID string, posture *AccountPosture) {
	// IAM metrics (global)
	c.status("Collecting IAM metrics...")
	if iamMetrics, err := c.collectIAMMetrics(ctx, client, accountID); err == nil {
		posture.IAM = *iamMetrics
	} else {
		c.warn("account %s: failed to collect IAM metrics: %v", accountID, err)
	}

	// S3 metrics (global bucket list)
	c.status("Collecting S3 metrics...")
	if s3Metrics, err := c.collectS3Metrics(ctx, client, accountID); err == nil {
		posture.S3 = *s3Metrics
	} else {
		c.warn("account %s: failed to collect S3 metrics: %v", accountID, err)
	}
}

// collectRegionalMetrics collects RDS and network metrics across all regions.
func (c *Collector) collectRegionalMetrics(ctx context.Context, client *aws.AWSClient, regions []string, accountID string) (rdsMetricsWithCounts, networkMetricsWithCounts) {
	var rdsMetrics rdsMetricsWithCounts
	var networkMetrics networkMetricsWithCounts

	total := int64(len(regions))
	for i, region := range regions {
		c.progress(int64(i+1), total, fmt.Sprintf("Scanning region %s", region))

		if rds, err := c.collectRDSMetrics(ctx, client, region); err == nil {
			rdsMetrics = mergeRDSMetrics(rdsMetrics, *rds)
		} else {
			c.warn("account %s region %s: failed to collect RDS metrics: %v", accountID, region, err)
		}

		if network, err := c.collectNetworkMetrics(ctx, client, region); err == nil {
			networkMetrics = mergeNetworkMetrics(networkMetrics, *network)
		} else {
			c.warn("account %s region %s: failed to collect network metrics: %v", accountID, region, err)
		}
	}

	return rdsMetrics, networkMetrics
}

// collectSecurityServices collects account-level security service status.
func (c *Collector) collectSecurityServices(ctx context.Context, client *aws.AWSClient, regions []string, posture *AccountPosture) {
	primaryRegion := DefaultPrimaryRegion
	if len(regions) > 0 {
		primaryRegion = regions[0]
	}

	// collectAccountSecurity handles per-service warnings internally
	acctSec, _ := c.collectAccountSecurity(ctx, client, primaryRegion, regions, posture.AccountID)
	if acctSec != nil {
		posture.AccountSecurity = *acctSec
	}
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
		if !aws.IsGitHubActionsOIDCAvailable() {
			return "", fmt.Errorf("auth_mode is 'oidc' but GitHub Actions OIDC is not available (missing ACTIONS_ID_TOKEN_REQUEST_URL or ACTIONS_ID_TOKEN_REQUEST_TOKEN)")
		}
	case AuthModeAssumeRole:
		// Valid, no additional checks needed
	default:
		return "", fmt.Errorf("invalid auth_mode %q: must be %q or %q", authMode, AuthModeOIDC, AuthModeAssumeRole)
	}

	return authMode, nil
}

// initializeAuth sets up authentication mode and returns any warnings.
// For OIDC mode, initializes the token source and checks for incompatible settings.
func (c *Collector) initializeAuth(accounts []AccountConfig) (authMode string, warnings []string, err error) {
	authMode, err = c.resolveAuthMode(accounts)
	if err != nil {
		return "", nil, err
	}

	if authMode != AuthModeOIDC {
		return authMode, nil, nil
	}

	// Initialize OIDC token source
	c.tokenSource = aws.NewGitHubOIDCTokenSource()

	// Check for incompatible settings
	for _, acct := range accounts {
		if acct.ExternalID != "" {
			warnings = append(warnings, fmt.Sprintf("external_id is ignored in OIDC mode for role %s", acct.RoleARN))
		}
	}

	return authMode, warnings, nil
}

// formatAccountError creates a diagnostic error message for a failed account collection.
func formatAccountError(acct AccountConfig, err error) string {
	roleInfo := "default credentials"
	if acct.RoleARN != "" {
		roleInfo = acct.RoleARN
	}
	return fmt.Sprintf("failed to collect account (%s): %v", roleInfo, err)
}
