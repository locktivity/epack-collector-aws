package collector

import (
	"context"
	"strings"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

// collectAccountSecurity collects account-level security service status.
func (c *Collector) collectAccountSecurity(ctx context.Context, client *aws.AWSClient, primaryRegion string, regions []string) (*AccountSecurity, error) {
	security := &AccountSecurity{}

	c.collectCloudTrailStatus(ctx, client, &security.CloudTrail)
	c.collectConfigStatus(ctx, client, primaryRegion, &security.Config)
	c.collectGuardDutyStatus(ctx, client, regions, &security.GuardDuty)
	c.collectSecurityHubStatus(ctx, client, primaryRegion, &security.SecurityHub)
	c.collectInspectorStatus(ctx, client, primaryRegion, &security.Inspector)

	return security, nil
}

// collectCloudTrailStatus collects CloudTrail configuration status.
func (c *Collector) collectCloudTrailStatus(ctx context.Context, client *aws.AWSClient, status *CloudTrailStatus) {
	trails, err := client.DescribeTrails(ctx)
	if err != nil {
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
func (c *Collector) collectConfigStatus(ctx context.Context, client *aws.AWSClient, region string, status *ConfigStatus) {
	recorders, err := client.DescribeConfigRecorders(ctx, region)
	if err != nil || len(recorders) == 0 {
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
func (c *Collector) collectGuardDutyStatus(ctx context.Context, client *aws.AWSClient, regions []string, status *GuardDutyStatus) {
	for _, region := range regions {
		detectors, err := client.ListGuardDutyDetectors(ctx, region)
		if err != nil || len(detectors) == 0 {
			continue
		}

		status.Enabled = true
		for _, d := range detectors {
			status.UnremediatedFindingsOver48Hours += d.HighOrCriticalFindingsOlderThan48Hours
		}
	}
}

// collectSecurityHubStatus collects Security Hub status.
func (c *Collector) collectSecurityHubStatus(ctx context.Context, client *aws.AWSClient, region string, status *SecurityHubStatus) {
	hubConfig, err := client.GetSecurityHubConfig(ctx, region)
	if err != nil || hubConfig == nil {
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
		if err != nil || complianceByLevel == nil {
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
func (c *Collector) collectInspectorStatus(ctx context.Context, client *aws.AWSClient, region string, status *InspectorStatus) {
	summary, err := client.GetInspectorSummaryFromSecurityHub(ctx, region)
	if err != nil || summary == nil {
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
