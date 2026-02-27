// Package collector provides AWS account posture collection functionality.
package collector

import (
	"context"
	"fmt"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

// Collector collects AWS account security posture.
type Collector struct {
	config Config
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

	// Determine which accounts to collect from
	accounts := c.config.Accounts
	if len(accounts) == 0 {
		// Use default credentials for current account
		accounts = []AccountConfig{{}}
	}

	total := int64(len(accounts))
	c.status("Starting AWS posture collection")

	// Collect from each account
	for i, acct := range accounts {
		c.progress(int64(i+1), total, fmt.Sprintf("Collecting account %d of %d", i+1, len(accounts)))

		posture, err := c.collectAccount(ctx, acct)
		if err != nil {
			// Log error but continue with other accounts
			continue
		}
		output.Accounts = append(output.Accounts, *posture)
	}

	c.status("Collection complete")
	return output, nil
}

// collectAccount collects posture for a single AWS account.
func (c *Collector) collectAccount(ctx context.Context, acctConfig AccountConfig) (*AccountPosture, error) {
	// Create client for this account
	c.status("Connecting to AWS...")
	client, err := c.createClient(ctx, acctConfig)
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
	rdsMetrics, networkMetrics := c.collectRegionalMetrics(ctx, client, regions)
	posture.RDS = rdsMetrics.RDSMetrics
	posture.Network = networkMetrics.NetworkMetrics

	// Collect account security services
	c.collectSecurityServices(ctx, client, regions, posture)

	return posture, nil
}

// createClient creates an AWS client for the given account configuration.
func (c *Collector) createClient(ctx context.Context, acctConfig AccountConfig) (*aws.AWSClient, error) {
	if acctConfig.RoleARN != "" {
		client, err := aws.NewClientWithRole(ctx, acctConfig.RoleARN, acctConfig.ExternalID)
		if err != nil {
			return nil, fmt.Errorf("creating AWS client with role: %w", err)
		}
		return client, nil
	}

	client, err := aws.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating AWS client: %w", err)
	}
	return client, nil
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
	}

	// S3 metrics (global bucket list)
	c.status("Collecting S3 metrics...")
	if s3Metrics, err := c.collectS3Metrics(ctx, client, accountID); err == nil {
		posture.S3 = *s3Metrics
	}
}

// collectRegionalMetrics collects RDS and network metrics across all regions.
func (c *Collector) collectRegionalMetrics(ctx context.Context, client *aws.AWSClient, regions []string) (rdsMetricsWithCounts, networkMetricsWithCounts) {
	var rdsMetrics rdsMetricsWithCounts
	var networkMetrics networkMetricsWithCounts

	total := int64(len(regions))
	for i, region := range regions {
		c.progress(int64(i+1), total, fmt.Sprintf("Scanning region %s", region))

		if rds, err := c.collectRDSMetrics(ctx, client, region); err == nil {
			rdsMetrics = mergeRDSMetrics(rdsMetrics, *rds)
		}

		if network, err := c.collectNetworkMetrics(ctx, client, region); err == nil {
			networkMetrics = mergeNetworkMetrics(networkMetrics, *network)
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

	if acctSec, err := c.collectAccountSecurity(ctx, client, primaryRegion, regions); err == nil {
		posture.AccountSecurity = *acctSec
	}
}
