package collector

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// collectAccountSecurity collects account-level security service status,
// each service as a step. level is passed through to per-service collectors
// that gate audit / internal fields.
func (c *Collector) collectAccountSecurity(steps *stepper, client *aws.AWSClient, primaryRegion string, regions []string, accountID string, at at, s3 *S3Metrics, level componentsdk.Level) *AccountSecurity {
	security := &AccountSecurity{}

	ctx := steps.next("cloudtrail", "CloudTrail trails")
	trailsAt := at.sub("account_security", "cloudtrail")
	trails := c.collectCloudTrailStatus(ctx, client, accountID, trailsAt, &security.CloudTrail, level)
	c.resolveTrailBucketRetention(ctx, client, accountID, trailsAt, trails, s3, &security.CloudTrail)
	c.recordCloudTrailUnread(trailsAt, &security.CloudTrail)

	c.collectConfigStatus(steps.next("config", "AWS Config"), client, primaryRegion, accountID, &security.Config, level)
	c.collectGuardDutyStatus(steps.next("guardduty", "GuardDuty"), client, regions, accountID, &security.GuardDuty, level)
	c.collectAccessAnalyzerStatus(steps.next("access_analyzer", "IAM Access Analyzer"), client, regions, accountID, &security.AccessAnalyzer, level)
	c.collectSecurityHubStatus(steps.next("security_hub", "Security Hub"), client, primaryRegion, accountID, &security.SecurityHub, level)
	c.collectInspectorStatus(steps.next("inspector", "Inspector"), client, primaryRegion, accountID, &security.Inspector, level)

	secAt := at.sub("account_security")
	c.recordUnread(secAt.sub("config"), security.Config.missing)
	c.recordUnread(secAt.sub("guardduty"), security.GuardDuty.missing)
	recordRowsUnread(c, secAt.sub("guardduty", "detectors"), security.GuardDuty.Detectors, func(r *GuardDutyDetectorRow) unread { return r.missing })
	recordRowsUnread(c, secAt.sub("guardduty", "finding_notification", "rules"), security.GuardDuty.FindingNotification.Rules, func(r *GuardDutyNotificationRuleRow) unread { return r.missing })
	c.recordUnread(secAt.sub("access_analyzer"), security.AccessAnalyzer.missing)
	recordRowsUnread(c, secAt.sub("access_analyzer", "analyzers"), security.AccessAnalyzer.Analyzers, func(r *AccessAnalyzerRow) unread { return r.missing })
	c.recordUnread(secAt.sub("security_hub"), security.SecurityHub.missing)
	c.recordUnread(secAt.sub("inspector"), security.Inspector.missing)

	return security
}

// trailDescriber is the slice of the AWS client used by collectCloudTrailStatus,
// extracted so the failure paths can be tested without AWS.
type trailDescriber interface {
	DescribeTrails(ctx context.Context) ([]aws.Trail, error)
}

// collectCloudTrailStatus collects CloudTrail configuration status. When the
// trails cannot be listed, every value that depends on them is left out.
func (c *Collector) collectCloudTrailStatus(ctx context.Context, client trailDescriber, accountID string, at at, status *CloudTrailStatus, level componentsdk.Level) []aws.Trail {
	trails, err := client.DescribeTrails(ctx)
	if err != nil {
		var statusErr *aws.TrailStatusUnavailableError
		if !errors.As(err, &statusErr) || len(trails) == 0 {
			status.TrailListingErrorCode = apiErrorCode(err)
			c.warn("account %s: failed to collect CloudTrail status: %v", accountID, err)
			status.missing.add(err, "enabled", "multi_region_enabled", "organization_trail_enabled")
			status.missing.add(err, trailRetentionCounts...)
			status.missing.add(err, trailObjectLockCounts...)
			status.missing.add(err, trailPublicAccessCounts...)
			if level.AtLeast(componentsdk.LevelAudit) {
				status.missing.add(err, "trails")
			}
			return nil
		}
		c.warn("account %s: failed to collect one or more CloudTrail trail statuses: %v", accountID, err)
	}
	status.TrailListingEvaluated = true

	summarizeCloudTrailStatus(status, trails)

	if level.AtLeast(componentsdk.LevelAudit) {
		status.Trails = trailsToInventory(trails, level)
	}
	return trails
}

// summarizeCloudTrailStatus sets whether a trail is logging, a multi-region
// one, and an organization one. A trail whose status is unknown leaves a flag
// unknown unless another trail already settles it.
func summarizeCloudTrailStatus(status *CloudTrailStatus, trails []aws.Trail) {
	trails = dedupeTrails(trails)
	for _, trail := range trails {
		switch {
		case trail.TrailStatusEvaluated:
			status.TrailStatusEvaluatedCount++
		case trail.TrailStatusInferred:
			status.TrailStatusInferredCount++
		case trail.TrailStatusErrorCode != "":
			status.TrailStatusUnknownCount++
		}
		if trail.IsLogging {
			status.Enabled = true
		}
		if trail.IsLogging && trail.IsMultiRegionTrail {
			status.MultiRegionEnabled = true
		}
		if trail.IsLogging && trail.IsOrganizationTrail {
			status.OrganizationTrailEnabled = true
		}
	}
	for _, trail := range trails {
		if trail.StatusErr == nil {
			continue
		}
		if !status.Enabled {
			status.missing.addPartial(trail.StatusErr, 1, "enabled")
		}
		if trail.IsMultiRegionTrail && !status.MultiRegionEnabled {
			status.missing.addPartial(trail.StatusErr, 1, "multi_region_enabled")
		}
		if trail.IsOrganizationTrail && !status.OrganizationTrailEnabled {
			status.missing.addPartial(trail.StatusErr, 1, "organization_trail_enabled")
		}
	}
}

// recordCloudTrailUnread writes the CloudTrail values a failed read left
// unknown as gaps.
func (c *Collector) recordCloudTrailUnread(at at, status *CloudTrailStatus) {
	c.recordUnread(at, status.missing)
	recordRowsUnread(c, at.sub("trails"), status.Trails, func(r *CloudTrailTrail) unread { return r.missing })
}

// trailsToInventory projects the trail list onto per-trail rows. Audit emits
// the boolean encryption / log-forwarding flags; internal additionally exposes
// the KMS key ARN and CloudWatch Logs ARN so consumers can correlate the trail
// to its key and destination log group.
func trailsToInventory(trails []aws.Trail, level componentsdk.Level) []CloudTrailTrail {
	trails = dedupeTrails(trails)
	out := make([]CloudTrailTrail, 0, len(trails))
	for _, t := range trails {
		row := CloudTrailTrail{
			Name:                     t.Name,
			TrailARN:                 t.TrailARN,
			HomeRegion:               t.HomeRegion,
			S3BucketName:             t.S3BucketName,
			S3KeyPrefix:              t.S3KeyPrefix,
			IsMultiRegionTrail:       t.IsMultiRegionTrail,
			IsOrganizationTrail:      t.IsOrganizationTrail,
			LogFileValidationEnabled: t.LogFileValidationEnabled,
			KMSEncrypted:             t.KMSKeyId != nil && *t.KMSKeyId != "",
			CloudWatchLogsEnabled:    t.CloudWatchLogsLogGroupArn != nil && *t.CloudWatchLogsLogGroupArn != "",
			IsLogging:                t.IsLogging,
			TrailStatusEvaluated:     t.TrailStatusEvaluated,
			TrailStatusInferred:      t.TrailStatusInferred,
			TrailStatusErrorCode:     t.TrailStatusErrorCode,
		}
		row.missing.add(t.StatusErr, "is_logging")
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

func dedupeTrails(trails []aws.Trail) []aws.Trail {
	out := make([]aws.Trail, 0, len(trails))
	seen := make(map[string]int, len(trails))
	for _, trail := range trails {
		key := trailIdentity(trail)
		if key == "" {
			out = append(out, trail)
			continue
		}
		if idx, ok := seen[key]; ok {
			if shouldReplaceDuplicateTrail(out[idx], trail) {
				out[idx] = trail
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, trail)
	}
	return out
}

func trailIdentity(trail aws.Trail) string {
	if trail.TrailARN != "" {
		return trail.TrailARN
	}
	return trail.Name
}

func shouldReplaceDuplicateTrail(existing, candidate aws.Trail) bool {
	if !existing.TrailStatusEvaluated && candidate.TrailStatusEvaluated {
		return true
	}
	if !existing.IsLogging && candidate.IsLogging {
		return true
	}
	return false
}

// collectConfigStatus collects AWS Config status. A failed read leaves the
// values that depend on it out.
func (c *Collector) collectConfigStatus(ctx context.Context, client *aws.AWSClient, region string, accountID string, status *ConfigStatus, level componentsdk.Level) {
	recorders, err := client.DescribeConfigRecorders(ctx, region)
	if err != nil {
		c.warn("account %s: failed to collect AWS Config status: %v", accountID, err)
		status.missing.add(err, "enabled", "recorder_running")
		if level.AtLeast(componentsdk.LevelAudit) {
			status.missing.add(err, "recorders")
		}
		if level.AtLeast(componentsdk.LevelInternal) {
			status.missing.add(err, "rules")
		}
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
			status.missing.add(err, "rules")
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

// guardDutyRegionScan holds one region's GuardDuty results and the warnings
// emitted while collecting them, so regions can be scanned concurrently and
// assembled in region order.
type guardDutyRegionScan struct {
	detectors    []aws.GuardDutyDetector
	listErr      error
	notification guardDutyNotificationScan
	findings     []GuardDutyFindingRow
	findingsErr  error
	truncated    bool
	dropped      int
	warnings     []string
}

// scanGuardDutyRegion collects one region's detectors and, at internal level,
// their findings. It runs on its own Collector copy so concurrent regions
// buffer warnings independently; the caller replays them in region order.
func (c *Collector) scanGuardDutyRegion(ctx context.Context, client *aws.AWSClient, region, accountID string, level componentsdk.Level) guardDutyRegionScan {
	rc := c.regionCopy()
	var s guardDutyRegionScan

	s.detectors, s.listErr = client.ListGuardDutyDetectors(ctx, region)
	if s.listErr != nil {
		rc.warn("account %s region %s: failed to collect GuardDuty status: %v", accountID, region, s.listErr)
		s.warnings = rc.warnings
		return s
	}

	// GuardDuty allows one detector per region, so [0] is the detector.
	if len(s.detectors) > 0 {
		s.notification = rc.scanGuardDutyNotificationRegion(ctx, client, region, accountID, s.detectors[0].DetectorID)
	}

	if level.AtLeast(componentsdk.LevelInternal) {
		for _, d := range s.detectors {
			findings, truncated, err := client.ListGuardDutyFindings(ctx, region, d.DetectorID, GuardDutyFindingsCap)
			if err != nil {
				rc.warn("account %s region %s detector %s: failed to collect GuardDuty findings: %v", accountID, region, d.DetectorID, err)
				if s.findingsErr == nil {
					s.findingsErr = err
				}
				continue
			}
			for _, f := range findings {
				s.findings = append(s.findings, guardDutyFindingToRow(f, region))
			}
			if truncated {
				s.truncated = true
				s.dropped += d.HighOrCriticalFindings - len(findings)
				rc.warn("account %s region %s detector %s: GuardDuty findings truncated at %d (detector reports %d total)",
					accountID, region, d.DetectorID, GuardDutyFindingsCap, d.HighOrCriticalFindings)
			}
		}
	}

	s.warnings = rc.warnings
	return s
}

// collectGuardDutyStatus collects GuardDuty status across all regions. A
// region whose detectors could not be read leaves every value that sums over
// regions unknown.
func (c *Collector) collectGuardDutyStatus(ctx context.Context, client *aws.AWSClient, regions []string, accountID string, status *GuardDutyStatus, level componentsdk.Level) {
	scans := mapConcurrent(regions, regionConcurrency, func(region string) guardDutyRegionScan {
		return c.scanGuardDutyRegion(ctx, client, region, accountID, level)
	})

	audit := level.AtLeast(componentsdk.LevelAudit)
	internal := level.AtLeast(componentsdk.LevelInternal)
	failedRegions := 0
	var firstErr error
	for i, region := range regions {
		s := scans[i]
		c.warnings = append(c.warnings, s.warnings...)
		if s.listErr != nil {
			failedRegions++
			if firstErr == nil {
				firstErr = s.listErr
			}
			continue
		}
		if len(s.detectors) == 0 {
			continue
		}

		status.Enabled = true
		for _, d := range s.detectors {
			status.UnremediatedFindingsOver48Hours += d.HighOrCriticalFindingsOlderThan48Hours
			status.missing.addPartial(d.StaleFindingsErr, 1, "unremediated_findings_over_48h")
		}
		applyGuardDutyNotificationScan(&status.FindingNotification, &status.missing, s.notification, region, audit)

		if audit {
			for _, d := range s.detectors {
				row := guardDutyDetectorToRow(d, region)
				row.missing.add(d.FindingsErr, "high_or_critical_findings")
				row.missing.add(d.StaleFindingsErr, "high_or_critical_findings_older_than_48h")
				status.Detectors = append(status.Detectors, row)
			}
		}

		if internal {
			status.Findings = append(status.Findings, s.findings...)
			status.missing.add(s.findingsErr, "findings")
			if s.truncated {
				status.FindingsTruncated = true
			}
			status.FindingsDroppedCount += s.dropped
		}
	}

	if failedRegions > 0 {
		if !status.Enabled {
			status.missing.addPartial(firstErr, failedRegions, "enabled")
		}
		status.missing.addPartial(firstErr, failedRegions, "unremediated_findings_over_48h", "finding_notification")
		if audit {
			status.missing.add(firstErr, "detectors")
		}
		if internal {
			status.missing.add(firstErr, "findings")
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

// collectSecurityHubStatus collects Security Hub status. A failed read leaves
// the values that depend on it out.
func (c *Collector) collectSecurityHubStatus(ctx context.Context, client *aws.AWSClient, region string, accountID string, status *SecurityHubStatus, level componentsdk.Level) {
	cisLevels := []string{"cis_aws_foundations_benchmark_level_1", "cis_aws_foundations_benchmark_level_2", "cis_aws_foundations_benchmark_unknown_level"}
	audit := level.AtLeast(componentsdk.LevelAudit)
	hubConfig, err := client.GetSecurityHubConfig(ctx, region)
	if err != nil {
		c.warn("account %s: failed to collect Security Hub status: %v", accountID, err)
		status.missing.add(err, "enabled")
		status.missing.add(err, cisLevels...)
		if audit {
			status.missing.add(err, "auto_enable_controls", "standards_arns", "integration_count", "product_subscriptions")
		}
		return
	}
	if hubConfig == nil {
		finalizeCISLevelCompliance(&status.CISAWSFoundationsBenchmarkLevel1)
		finalizeCISLevelCompliance(&status.CISAWSFoundationsBenchmarkLevel2)
		finalizeCISLevelCompliance(&status.CISAWSFoundationsBenchmarkUnknownLevel)
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
			status.missing.addPartial(err, 1, cisLevels...)
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

	if audit {
		status.AutoEnableControls = hubConfig.AutoEnableControls
		status.StandardsARNs = append([]string{}, hubConfig.StandardsARNs...)
		if hubConfig.IntegrationsErr == nil {
			status.IntegrationCount = intPtr(hubConfig.IntegrationCount)
		}
		status.ProductSubscriptions = append([]string{}, hubConfig.ProductSubscriptions...)
		status.missing.add(hubConfig.IntegrationsErr, "integration_count", "product_subscriptions")
	}
}

// inspectorSummarizer is the slice of the AWS client used by
// collectInspectorStatus, extracted so the failure paths can be tested
// without AWS.
type inspectorSummarizer interface {
	GetInspectorSummaryFromSecurityHub(ctx context.Context, region string) (*aws.InspectorSummary, error)
}

// collectInspectorStatus collects Inspector vulnerability posture from Security Hub findings.
func (c *Collector) collectInspectorStatus(ctx context.Context, client inspectorSummarizer, region string, accountID string, status *InspectorStatus, level componentsdk.Level) {
	summary, err := client.GetInspectorSummaryFromSecurityHub(ctx, region)
	if err != nil {
		status.StatusErrorCode = apiErrorCode(err)
		c.warn("account %s: failed to collect Inspector status: %v", accountID, err)
		status.missing.add(err, "enabled", "unpatched_server_percent", "total_affected_resources", "unpatched_resources")
		if level.AtLeast(componentsdk.LevelAudit) {
			status.missing.add(err, "total_findings", "patched_findings", "unpatched_findings")
		}
		return
	}
	status.StatusEvaluated = true
	if summary == nil {
		summary = &aws.InspectorSummary{}
	}

	status.Enabled = summary.Enabled
	status.TotalAffectedResources = summary.TotalAffectedResources
	status.UnpatchedResources = summary.UnpatchedResources
	status.UnpatchedServerPercent = pctOf(summary.UnpatchedResources, summary.TotalAffectedResources)

	if level.AtLeast(componentsdk.LevelAudit) {
		status.TotalFindings = intPtr(summary.TotalFindings)
		status.PatchedFindings = intPtr(summary.PatchedFindings)
		status.UnpatchedFindings = intPtr(summary.UnpatchedFindings)
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
	level.ScoredControls = scoredControls
	level.CompliancePercent = pctOf(level.PassedControls, scoredControls)
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
