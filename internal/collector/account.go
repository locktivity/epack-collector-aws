package collector

import (
	"context"
	"strings"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

// collectAccountSecurity collects account-level security service status.
func (c *Collector) collectAccountSecurity(ctx context.Context, client *aws.AWSClient, primaryRegion string, regions []string, accountID string) (*AccountSecurity, error) {
	security := &AccountSecurity{}

	c.status("Checking CloudTrail...")
	c.collectCloudTrailStatus(ctx, client, accountID, &security.CloudTrail)

	c.status("Checking AWS Config...")
	c.collectConfigStatus(ctx, client, primaryRegion, accountID, &security.Config)

	c.status("Checking GuardDuty...")
	c.collectGuardDutyStatus(ctx, client, regions, accountID, &security.GuardDuty)

	c.status("Checking Security Hub...")
	c.collectSecurityHubStatus(ctx, client, primaryRegion, accountID, &security.SecurityHub)

	c.status("Checking Inspector...")
	c.collectInspectorStatus(ctx, client, primaryRegion, accountID, &security.Inspector)

	return security, nil
}

// collectCloudTrailStatus collects CloudTrail configuration status.
func (c *Collector) collectCloudTrailStatus(ctx context.Context, client *aws.AWSClient, accountID string, status *CloudTrailStatus) {
	trails, err := client.DescribeTrails(ctx)
	if err != nil {
		c.warn("account %s: failed to collect CloudTrail status: %v", accountID, err)
		return
	}

	for _, trail := range trails {
		if trail.IsLogging {
			status.Enabled = true
		}
		if trail.IsMultiRegionTrail {
			status.MultiRegionEnabled = true
		}
	}
}

// collectConfigStatus collects AWS Config status.
func (c *Collector) collectConfigStatus(ctx context.Context, client *aws.AWSClient, region string, accountID string, status *ConfigStatus) {
	recorders, err := client.DescribeConfigRecorders(ctx, region)
	if err != nil {
		c.warn("account %s: failed to collect AWS Config status: %v", accountID, err)
		return
	}
	if len(recorders) == 0 {
		return
	}

	status.Enabled = true
	for _, r := range recorders {
		if r.Recording {
			status.RecorderRunning = true
		}
	}
}

// collectGuardDutyStatus collects GuardDuty status across all regions.
func (c *Collector) collectGuardDutyStatus(ctx context.Context, client *aws.AWSClient, regions []string, accountID string, status *GuardDutyStatus) {
	for _, region := range regions {
		detectors, err := client.ListGuardDutyDetectors(ctx, region)
		if err != nil {
			c.warn("account %s region %s: failed to collect GuardDuty status: %v", accountID, region, err)
			continue
		}
		if len(detectors) == 0 {
			continue
		}

		status.Enabled = true
		for _, d := range detectors {
			status.UnremediatedFindingsOver48Hours += d.HighOrCriticalFindingsOlderThan48Hours
		}
	}
}

// collectSecurityHubStatus collects Security Hub status.
func (c *Collector) collectSecurityHubStatus(ctx context.Context, client *aws.AWSClient, region string, accountID string, status *SecurityHubStatus) {
	hubConfig, err := client.GetSecurityHubConfig(ctx, region)
	if err != nil {
		c.warn("account %s: failed to collect Security Hub status: %v", accountID, err)
		return
	}
	if hubConfig == nil {
		return
	}

	status.Enabled = hubConfig.Enabled

	for _, standardARN := range hubConfig.StandardsARNs {
		if !isCISStandard(standardARN) {
			continue
		}

		standardID := standardIDFromARN(standardARN)
		if standardID == "" {
			continue
		}

		complianceByLevel, err := client.GetSecurityHubCISComplianceByLevel(ctx, region, standardID)
		if err != nil {
			c.warn("account %s: failed to collect CIS compliance for %s: %v", accountID, standardID, err)
			continue
		}
		if complianceByLevel == nil {
			continue
		}

		mergeCISLevelCompliance(&status.CISAWSFoundationsBenchmarkLevel1, complianceByLevel.Level1)
		mergeCISLevelCompliance(&status.CISAWSFoundationsBenchmarkLevel2, complianceByLevel.Level2)
		mergeCISLevelCompliance(&status.CISAWSFoundationsBenchmarkUnknownLevel, complianceByLevel.Unknown)
	}
	finalizeCISLevelCompliance(&status.CISAWSFoundationsBenchmarkLevel1)
	finalizeCISLevelCompliance(&status.CISAWSFoundationsBenchmarkLevel2)
	finalizeCISLevelCompliance(&status.CISAWSFoundationsBenchmarkUnknownLevel)
}

// collectInspectorStatus collects Inspector vulnerability posture from Security Hub findings.
func (c *Collector) collectInspectorStatus(ctx context.Context, client *aws.AWSClient, region string, accountID string, status *InspectorStatus) {
	summary, err := client.GetInspectorSummaryFromSecurityHub(ctx, region)
	if err != nil {
		c.warn("account %s: failed to collect Inspector status: %v", accountID, err)
		return
	}
	if summary == nil {
		return
	}

	status.Enabled = summary.Enabled
	status.UnpatchedServerPercent = percent(summary.UnpatchedResources, summary.TotalAffectedResources)
}

func isCISStandard(standardARN string) bool {
	return strings.Contains(strings.ToLower(standardARN), CISStandardsARNMarker)
}

func standardIDFromARN(standardARN string) string {
	const marker = ":standards/"
	idx := strings.Index(standardARN, marker)
	if idx == -1 {
		return ""
	}
	return "standards/" + standardARN[idx+len(marker):]
}

func mergeCISLevelCompliance(target *CISComplianceByLevel, source aws.SecurityHubCISCompliance) {
	target.PassedControls += source.PassedControls
	target.FailedControls += source.FailedControls
	target.WarningControls += source.WarningControls
	target.NotAvailableControls += source.NotAvailableControls
}

func finalizeCISLevelCompliance(level *CISComplianceByLevel) {
	scoredControls := level.PassedControls + level.FailedControls + level.WarningControls
	level.Enabled = scoredControls > 0 || level.NotAvailableControls > 0
	level.CompliancePercent = percent(level.PassedControls, scoredControls)
	level.ComplianceState = cisComplianceState(level.PassedControls, level.FailedControls, level.WarningControls, level.NotAvailableControls)
}

func cisComplianceState(passed, failed, warning, notAvailable int) string {
	switch {
	case failed > 0:
		return "FAILED"
	case warning > 0:
		return "WARNING"
	case passed > 0:
		return "PASSED"
	case notAvailable > 0:
		return "NOT_AVAILABLE"
	default:
		return "UNKNOWN"
	}
}
