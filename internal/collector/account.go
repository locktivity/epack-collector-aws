package collector

import (
	"context"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// collectAccountSecurity collects account-level security service status.
// level is passed through to per-service collectors that gate audit / internal fields.
func (c *Collector) collectAccountSecurity(ctx context.Context, client *aws.AWSClient, primaryRegion string, regions []string, accountID string, level componentsdk.Level) (*AccountSecurity, error) {
	security := &AccountSecurity{}

	c.status("Checking CloudTrail...")
	c.collectCloudTrailStatus(ctx, client, accountID, &security.CloudTrail, level)

	c.status("Checking AWS Config...")
	c.collectConfigStatus(ctx, client, primaryRegion, accountID, &security.Config, level)

	c.status("Checking GuardDuty...")
	c.collectGuardDutyStatus(ctx, client, regions, accountID, &security.GuardDuty, level)

	c.status("Checking Security Hub...")
	c.collectSecurityHubStatus(ctx, client, primaryRegion, accountID, &security.SecurityHub, level)

	c.status("Checking Inspector...")
	c.collectInspectorStatus(ctx, client, primaryRegion, accountID, &security.Inspector, level)

	return security, nil
}

// collectCloudTrailStatus collects CloudTrail configuration status.
func (c *Collector) collectCloudTrailStatus(ctx context.Context, client *aws.AWSClient, accountID string, status *CloudTrailStatus, level componentsdk.Level) {
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

	if level.AtLeast(componentsdk.LevelAudit) {
		status.Trails = trailsToInventory(trails, level)
	}
}

// trailsToInventory projects the trail list onto per-trail rows. Audit emits
// the boolean encryption / log-forwarding flags; internal additionally exposes
// the KMS key ARN and CloudWatch Logs ARN so consumers can correlate the trail
// to its key and destination log group.
func trailsToInventory(trails []aws.Trail, level componentsdk.Level) []CloudTrailTrail {
	out := make([]CloudTrailTrail, 0, len(trails))
	for _, t := range trails {
		row := CloudTrailTrail{
			Name:                     t.Name,
			S3BucketName:             t.S3BucketName,
			IsMultiRegionTrail:       t.IsMultiRegionTrail,
			LogFileValidationEnabled: t.LogFileValidationEnabled,
			KMSEncrypted:             t.KMSKeyId != nil && *t.KMSKeyId != "",
			CloudWatchLogsEnabled:    t.CloudWatchLogsLogGroupArn != nil && *t.CloudWatchLogsLogGroupArn != "",
			IsLogging:                t.IsLogging,
		}
		if level.AtLeast(componentsdk.LevelInternal) {
			if t.KMSKeyId != nil {
				row.KMSKeyARN = *t.KMSKeyId
			}
			if t.CloudWatchLogsLogGroupArn != nil {
				row.CloudWatchLogsARN = *t.CloudWatchLogsLogGroupArn
			}
		}
		out = append(out, row)
	}
	return out
}

// collectConfigStatus collects AWS Config status.
func (c *Collector) collectConfigStatus(ctx context.Context, client *aws.AWSClient, region string, accountID string, status *ConfigStatus, level componentsdk.Level) {
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

	if level.AtLeast(componentsdk.LevelAudit) {
		status.Recorders = configRecordersToInventory(recorders, region)
	}

	if level.AtLeast(componentsdk.LevelInternal) {
		rules, err := client.ListConfigRules(ctx, region)
		if err != nil {
			c.warn("account %s: failed to collect AWS Config rules: %v", accountID, err)
			return
		}
		rows := configRulesToInventory(rules, region)
		kept, dropped, truncated := Truncate(rows, ConfigRulesCap, func(a, b ConfigRuleRow) bool {
			return a.Name < b.Name
		})
		status.Rules = kept
		status.RulesTruncated = truncated
		status.RulesDroppedCount = dropped
		if truncated {
			c.warn("account %s region %s: Config rule inventory truncated to %d (dropped %d)", accountID, region, ConfigRulesCap, dropped)
		}
	}
}

// configRulesToInventory projects the rule list onto per-rule internal-level
// rows. All rules carry the same region (the region this call was made for).
func configRulesToInventory(rules []aws.ConfigRule, region string) []ConfigRuleRow {
	out := make([]ConfigRuleRow, 0, len(rules))
	for _, r := range rules {
		row := ConfigRuleRow{
			Name:             r.Name,
			Region:           region,
			ARN:              r.ARN,
			SourceOwner:      r.SourceOwner,
			SourceIdentifier: r.SourceIdentifier,
			ComplianceState:  r.ComplianceState,
		}
		if r.LastEvaluated != nil {
			row.LastEvaluated = r.LastEvaluated.UTC().Format(time.RFC3339)
		}
		out = append(out, row)
	}
	return out
}

// configRecordersToInventory projects the recorder list onto per-recorder rows.
// All recorders carry the same region (the region this call was made for).
func configRecordersToInventory(recorders []aws.ConfigRecorder, region string) []ConfigRecorderRow {
	out := make([]ConfigRecorderRow, 0, len(recorders))
	for _, r := range recorders {
		out = append(out, ConfigRecorderRow{
			Name:          r.Name,
			Region:        region,
			RoleARN:       r.RoleARN,
			AllSupported:  r.AllSupported,
			IncludeGlobal: r.IncludeGlobal,
			Recording:     r.Recording,
		})
	}
	return out
}

// collectGuardDutyStatus collects GuardDuty status across all regions.
func (c *Collector) collectGuardDutyStatus(ctx context.Context, client *aws.AWSClient, regions []string, accountID string, status *GuardDutyStatus, level componentsdk.Level) {
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

		if level.AtLeast(componentsdk.LevelAudit) {
			for _, d := range detectors {
				status.Detectors = append(status.Detectors, guardDutyDetectorToRow(d, region))
			}
		}

		if level.AtLeast(componentsdk.LevelInternal) {
			for _, d := range detectors {
				findings, truncated, err := client.ListGuardDutyFindings(ctx, region, d.DetectorID, GuardDutyFindingsCap)
				if err != nil {
					c.warn("account %s region %s detector %s: failed to collect GuardDuty findings: %v", accountID, region, d.DetectorID, err)
					continue
				}
				for _, f := range findings {
					status.Findings = append(status.Findings, guardDutyFindingToRow(f, region))
				}
				if truncated {
					status.FindingsTruncated = true
					status.FindingsDroppedCount += d.HighOrCriticalFindings - len(findings)
					c.warn("account %s region %s detector %s: GuardDuty findings truncated at %d (detector reports %d total)",
						accountID, region, d.DetectorID, GuardDutyFindingsCap, d.HighOrCriticalFindings)
				}
			}
		}
	}
}

// guardDutyFindingToRow projects a single finding onto its internal-level row.
// Region is stamped from the caller (findings are detector-scoped, detectors
// are regional).
func guardDutyFindingToRow(f aws.GuardDutyFinding, region string) GuardDutyFindingRow {
	row := GuardDutyFindingRow{
		ID:           f.ID,
		DetectorID:   f.DetectorID,
		Region:       region,
		Severity:     f.Severity,
		Type:         f.Type,
		Title:        f.Title,
		ResourceType: f.ResourceType,
		ResourceID:   f.ResourceID,
	}
	if f.CreatedAt != nil {
		row.CreatedAt = f.CreatedAt.UTC().Format(time.RFC3339)
	}
	if f.UpdatedAt != nil {
		row.UpdatedAt = f.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return row
}

// guardDutyDetectorToRow projects a single detector onto its audit-level row.
func guardDutyDetectorToRow(d aws.GuardDutyDetector, region string) GuardDutyDetectorRow {
	return GuardDutyDetectorRow{
		DetectorID:                             d.DetectorID,
		Region:                                 region,
		Status:                                 d.Status,
		FindingPublishingFreq:                  d.FindingPublishingFreq,
		S3LogsEnabled:                          d.S3LogsEnabled,
		EKSAuditLogsEnabled:                    d.EKSAuditLogsEnabled,
		MalwareScanEnabled:                     d.MalwareScanEnabled,
		HighOrCriticalFindings:                 d.HighOrCriticalFindings,
		HighOrCriticalFindingsOlderThan48Hours: d.HighOrCriticalFindingsOlderThan48Hours,
	}
}

// collectSecurityHubStatus collects Security Hub status.
func (c *Collector) collectSecurityHubStatus(ctx context.Context, client *aws.AWSClient, region string, accountID string, status *SecurityHubStatus, level componentsdk.Level) {
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

	if level.AtLeast(componentsdk.LevelAudit) {
		status.AutoEnableControls = hubConfig.AutoEnableControls
		status.StandardsARNs = append([]string(nil), hubConfig.StandardsARNs...)
		status.IntegrationCount = hubConfig.IntegrationCount
		status.ProductSubscriptions = append([]string(nil), hubConfig.ProductSubscriptions...)
	}
}

// collectInspectorStatus collects Inspector vulnerability posture from Security Hub findings.
func (c *Collector) collectInspectorStatus(ctx context.Context, client *aws.AWSClient, region string, accountID string, status *InspectorStatus, level componentsdk.Level) {
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

	if level.AtLeast(componentsdk.LevelAudit) {
		status.TotalFindings = summary.TotalFindings
		status.PatchedFindings = summary.PatchedFindings
		status.UnpatchedFindings = summary.UnpatchedFindings
		status.TotalAffectedResources = summary.TotalAffectedResources
		status.UnpatchedResources = summary.UnpatchedResources
	}
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
