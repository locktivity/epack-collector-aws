package collector

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// collectAccountSecurity collects account-level security service status,
// each service as a step. level is passed through to per-service collectors
// that gate audit / internal fields. The Inspector step also reads
// Inspector's own status, coverage, and findings in every region into scan,
// unless the run leaves out the vuln-scanning artifact.
func (c *Collector) collectAccountSecurity(steps *stepper, client *aws.AWSClient, primaryRegion string, regions []string, accountID string, at at, s3 *S3Metrics, scan *inspectorScan, level componentsdk.Level) *AccountSecurity {
	security := &AccountSecurity{}

	ctx := steps.next("cloudtrail", "CloudTrail trails")
	trailsAt := at.sub("account_security", "cloudtrail")
	trails := c.collectCloudTrailStatus(ctx, client, regions, nil, accountID, trailsAt, &security.CloudTrail, level)
	c.resolveTrailBucketRetention(ctx, client, accountID, trailsAt, trails, s3, &security.CloudTrail)
	c.recordCloudTrailUnread(trailsAt, &security.CloudTrail)

	c.collectConfigStatus(steps.next("config", "AWS Config"), client, primaryRegion, accountID, &security.Config, level)
	c.collectGuardDutyStatus(steps.next("guardduty", "GuardDuty"), client, regions, accountID, &security.GuardDuty, level)
	c.collectAccessAnalyzerStatus(steps.next("access_analyzer", "IAM Access Analyzer"), client, regions, accountID, &security.AccessAnalyzer, level)
	c.collectSecurityHubStatus(steps.next("security_hub", "Security Hub"), client, primaryRegion, accountID, &security.SecurityHub, level)
	inspectorCtx := steps.next("inspector", "Inspector")
	c.collectInspectorStatus(inspectorCtx, client, primaryRegion, accountID, &security.Inspector, level)
	if !c.config.SkipVulnScanning {
		*scan = c.collectInspectorScan(inspectorCtx, client, regions, accountID)
	}

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
	DescribeTrails(ctx context.Context, regions []string, accountID string) ([]aws.Trail, error)
}

// collectCloudTrailStatus collects CloudTrail configuration status from the
// trails each region lists. When the trails cannot be listed, every value
// that depends on them is left out. When some regions' trails could not be
// listed, or regionsErr says the region list itself could not be read, the
// trails found still count, and a value they leave false is left out.
func (c *Collector) collectCloudTrailStatus(ctx context.Context, client trailDescriber, regions []string, regionsErr error, accountID string, at at, status *CloudTrailStatus, level componentsdk.Level) []aws.Trail {
	trails, err := client.DescribeTrails(ctx, regions, accountID)
	var incomplete *aws.TrailListingIncompleteError
	if err != nil {
		var statusErr *aws.TrailStatusUnavailableError
		var selectorsErr *aws.TrailSelectorsUnavailableError
		partial := errors.As(err, &statusErr) || errors.As(err, &selectorsErr) || errors.As(err, &incomplete)
		if !partial || len(trails) == 0 {
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
	unlisted, unlistedErr := 0, error(nil)
	switch {
	case incomplete != nil:
		unlisted, unlistedErr = len(incomplete.Regions), incomplete
	case regionsErr != nil:
		unlisted, unlistedErr = 1, regionsErr
	}
	if unlistedErr != nil {
		leaveOutUnlistedTrails(status, unlisted, unlistedErr, level)
	}

	if level.AtLeast(componentsdk.LevelAudit) {
		status.Trails = trailsToInventory(trails, level)
	}
	return trails
}

// summarizeCloudTrailStatus sets whether a trail logs management activity, a
// multi-region one, and an organization one. A trail counts when it is
// logging and its event selectors record management events that change the
// account, reads and writes or writes only. A trail that records only data
// events or only reads does not count, and neither does one that leaves out
// an event source such as KMS. A multi-region trail with global service
// events off does not count as multi-region. A trail whose status or
// selectors are unknown leaves a flag unknown unless another trail already
// settles it.
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
		if !trail.IsLogging || !recordsManagementWrites(trail) {
			continue
		}
		status.Enabled = true
		if trail.IsMultiRegionTrail && !trail.GlobalServiceEventsOff {
			status.MultiRegionEnabled = true
		}
		if trail.IsOrganizationTrail {
			status.OrganizationTrailEnabled = true
		}
	}
	for _, trail := range trails {
		err := trailCoverageUnknown(trail)
		if err == nil {
			continue
		}
		if !status.Enabled {
			status.missing.addPartial(err, 1, "enabled")
		}
		if trail.IsMultiRegionTrail && !trail.GlobalServiceEventsOff && !status.MultiRegionEnabled {
			status.missing.addPartial(err, 1, "multi_region_enabled")
		}
		if trail.IsOrganizationTrail && !status.OrganizationTrailEnabled {
			status.missing.addPartial(err, 1, "organization_trail_enabled")
		}
	}
}

// recordsManagementWrites reports whether a trail's event selectors record
// the management events that change the account, from every event source.
// An organization trail whose
// selectors a member account is denied counts, as its status does.
func recordsManagementWrites(trail aws.Trail) bool {
	switch {
	case trail.ManagementEventsInferred:
		return true
	case trail.ManagementEventSourcesExcluded:
		return false
	case trail.ManagementEvents == aws.ManagementEventsReadWrite, trail.ManagementEvents == aws.ManagementEventsWriteOnly:
		return true
	}
	return false
}

// trailCoverageUnknown returns why a trail may count as logging management
// activity without the collector knowing, or nil when it is known to count or
// known not to.
func trailCoverageUnknown(trail aws.Trail) error {
	statusUnknown := trail.StatusErr != nil
	selectorsUnknown := trail.SelectorsErr != nil && !trail.ManagementEventsInferred
	switch {
	case statusUnknown && (selectorsUnknown || recordsManagementWrites(trail)):
		return trail.StatusErr
	case selectorsUnknown && trail.IsLogging:
		return trail.SelectorsErr
	}
	return nil
}

// leaveOutUnlistedTrails leaves out each value a region whose trails could
// not be listed could change. A flag that the listed trails already set
// stays, since an unlisted trail cannot unset it.
func leaveOutUnlistedTrails(status *CloudTrailStatus, regions int, err error, level componentsdk.Level) {
	if !status.Enabled {
		status.missing.addPartial(err, regions, "enabled")
	}
	if !status.MultiRegionEnabled {
		status.missing.addPartial(err, regions, "multi_region_enabled")
	}
	if !status.OrganizationTrailEnabled {
		status.missing.addPartial(err, regions, "organization_trail_enabled")
	}
	status.missing.addPartial(err, regions, "trail_status_evaluated_count", "trail_status_inferred_count", "trail_status_unknown_count")
	status.missing.addPartial(err, regions, trailRetentionCounts...)
	status.missing.addPartial(err, regions, trailObjectLockCounts...)
	status.missing.addPartial(err, regions, trailPublicAccessCounts...)
	if level.AtLeast(componentsdk.LevelAudit) {
		status.missing.addPartial(err, regions, "trails")
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
			ManagementEvents:         t.ManagementEvents,
		}
		row.missing.add(t.StatusErr, "is_logging")
		row.missing.add(t.SelectorsErr, "management_events")
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
// values that depend on it out. Rules can exist without a customer managed
// recorder, so they are listed either way.
func (c *Collector) collectConfigStatus(ctx context.Context, client *aws.AWSClient, region string, accountID string, status *ConfigStatus, level componentsdk.Level) {
	recorders, err := client.DescribeConfigRecorders(ctx, region)
	if err != nil {
		c.warn("account %s: failed to collect AWS Config status: %v", accountID, err)
		status.missing.add(err, "enabled", "recorder_running")
		if level.AtLeast(componentsdk.LevelAudit) {
			status.missing.add(err, "recorders")
		}
		if level.AtLeast(componentsdk.LevelInternal) {
			status.missing.add(err, "rules", "rules_truncated", "rules_dropped_count")
		}
		return
	}

	if len(recorders) > 0 {
		status.Enabled = true
		for _, r := range recorders {
			if r.Recording {
				status.RecorderRunning = true
			}
		}
		if level.AtLeast(componentsdk.LevelAudit) {
			status.Recorders = configRecordersToInventory(recorders, region)
		}
	}

	if level.AtLeast(componentsdk.LevelInternal) {
		rules, err := client.ListConfigRules(ctx, region)
		if err != nil {
			c.warn("account %s: failed to collect AWS Config rules: %v", accountID, err)
			status.missing.add(err, "rules", "rules_truncated", "rules_dropped_count")
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
	droppedErr   error
	warnings     []string
}

// scanGuardDutyRegion collects one region's detectors and, at internal level,
// their findings. It runs on its own Collector copy so concurrent regions
// buffer warnings independently; the caller replays them in region order.
func (c *Collector) scanGuardDutyRegion(ctx context.Context, client *aws.AWSClient, region, accountID string, level componentsdk.Level) guardDutyRegionScan {
	rc := c.regionCopy()
	var s guardDutyRegionScan

	s.detectors, s.listErr = client.ListGuardDutyDetectors(ctx, region, accountID)
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
			findings, truncated, err := client.ListGuardDutyFindings(ctx, region, d.DetectorID, accountID, GuardDutyFindingsCap)
			if err != nil {
				rc.warn("account %s region %s detector %s: failed to collect GuardDuty findings: %v", accountID, region, d.DetectorID, err)
				if s.findingsErr == nil {
					s.findingsErr = err
				}
				continue
			}
			// ListFindings has no criterion for sample findings, so they
			// are dropped here once fetched.
			for _, f := range findings {
				if !f.Sample {
					s.findings = append(s.findings, guardDutyFindingToRow(f, region))
				}
			}
			if truncated {
				s.truncated = true
				// The findings past the cap are the detector's count less
				// those listed, unknown when the count could not be read.
				// Both include sample findings.
				if d.FindingsErr != nil {
					s.droppedErr = d.FindingsErr
				} else if n := d.HighOrCriticalFindings - len(findings); n > 0 {
					s.dropped += n
				}
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
	var firstErr, findingsErr error
	status.EnabledInAllRegions = len(regions) > 0
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
		if !guardDutyDetectorEnabled(s.detectors) {
			status.EnabledInAllRegions = false
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
			// A detector whose findings could not be read may hold more
			// than the cap, so the truncation is unknown too.
			status.missing.add(s.findingsErr, "findings", "findings_dropped_count")
			findingsErr = cmp.Or(findingsErr, s.findingsErr)
			if s.truncated {
				status.FindingsTruncated = true
			}
			status.FindingsDroppedCount += s.dropped
			status.missing.add(s.droppedErr, "findings_dropped_count")
		}
	}

	if failedRegions > 0 {
		if !status.Enabled {
			status.missing.addPartial(firstErr, failedRegions, "enabled")
		}
		if status.EnabledInAllRegions {
			status.missing.addPartial(firstErr, failedRegions, "enabled_in_all_regions")
		}
		status.missing.addPartial(firstErr, failedRegions, "unremediated_findings_over_48h", "finding_notification")
		if audit {
			status.missing.add(firstErr, "detectors")
		}
		if internal {
			status.missing.add(firstErr, "findings")
		}
	}
	if !status.FindingsTruncated {
		status.missing.add(findingsErr, "findings_truncated")
	}
}

// guardDutyDetectorEnabled reports whether a region's detectors include one
// whose status is ENABLED. A suspended detector does not count.
func guardDutyDetectorEnabled(detectors []aws.GuardDutyDetector) bool {
	for _, d := range detectors {
		if d.Status == guardDutyDetectorStatusEnabled {
			return true
		}
	}
	return false
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
		finalizeCISLevelCompliance(&status.CISAWSFoundationsBenchmarkLevel1, false)
		finalizeCISLevelCompliance(&status.CISAWSFoundationsBenchmarkLevel2, false)
		finalizeCISLevelCompliance(&status.CISAWSFoundationsBenchmarkUnknownLevel, false)
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

		complianceByLevel, err := client.GetSecurityHubCISComplianceByLevel(ctx, region, accountID, standardID)
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
	// Every CIS standard Security Hub offers covers both levels.
	cisEnabled := slices.ContainsFunc(hubConfig.StandardsARNs, isCISStandard)
	finalizeCISLevelCompliance(&status.CISAWSFoundationsBenchmarkLevel1, cisEnabled)
	finalizeCISLevelCompliance(&status.CISAWSFoundationsBenchmarkLevel2, cisEnabled)
	finalizeCISLevelCompliance(&status.CISAWSFoundationsBenchmarkUnknownLevel, cisEnabled)

	if audit {
		status.AutoEnableControls = hubConfig.AutoEnableControls
		status.missing.add(hubConfig.AutoEnableControlsErr, "auto_enable_controls")
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
	GetInspectorAccountStatus(ctx context.Context, region, accountID string) (aws.InspectorAccountStatus, error)
	GetInspectorSummaryFromSecurityHub(ctx context.Context, region, accountID string) (*aws.InspectorSummary, error)
}

// collectInspectorStatus collects whether Inspector is on from Inspector's
// own status, and its vulnerability posture from its findings in Security
// Hub. Each read that fails leaves out only the values it feeds.
func (c *Collector) collectInspectorStatus(ctx context.Context, client inspectorSummarizer, region string, accountID string, status *InspectorStatus, level componentsdk.Level) {
	account, statusErr := client.GetInspectorAccountStatus(ctx, region, accountID)
	if statusErr != nil {
		c.warn("account %s: failed to read the Inspector status: %v", accountID, statusErr)
	}
	status.Enabled = account.Enabled
	status.missing.add(statusErr, "enabled")

	summary, err := client.GetInspectorSummaryFromSecurityHub(ctx, region, accountID)
	if err != nil {
		status.StatusErrorCode = apiErrorCode(err)
		c.warn("account %s: failed to collect Inspector findings: %v", accountID, err)
		status.missing.add(err, "unpatched_server_percent", "total_affected_resources", "unpatched_resources")
		if level.AtLeast(componentsdk.LevelAudit) {
			status.missing.add(err, "total_findings", "patched_findings", "unpatched_findings")
		}
		return
	}
	status.StatusEvaluated = true
	if summary == nil {
		summary = &aws.InspectorSummary{}
	}

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

// standardIDFromARN returns the standards ID a standard's findings carry,
// the ARN's resource after its last colon. Most standards have a
// standards/... resource, and CIS AWS Foundations Benchmark v1.2.0 has
// ruleset/cis-aws-foundations-benchmark/v/1.2.0.
func standardIDFromARN(standardARN string) string {
	for _, kind := range []string{"standards/", "ruleset/"} {
		if idx := strings.Index(standardARN, ":"+kind); idx != -1 {
			return kind + standardARN[idx+len(kind)+1:]
		}
	}
	return ""
}

func mergeCISLevelCompliance(target *CISComplianceByLevel, source aws.SecurityHubCISCompliance) {
	target.PassedControls += source.PassedControls
	target.FailedControls += source.FailedControls
	target.WarningControls += source.WarningControls
	target.NotAvailableControls += source.NotAvailableControls
}

// finalizeCISLevelCompliance scores a level from its control counts.
// standardEnabled is whether Security Hub has a CIS standard enabled, which
// decides whether the level is on even before it has a finding.
func finalizeCISLevelCompliance(level *CISComplianceByLevel, standardEnabled bool) {
	scoredControls := level.PassedControls + level.FailedControls + level.WarningControls
	level.Enabled = standardEnabled
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
