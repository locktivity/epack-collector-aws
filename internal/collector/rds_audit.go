package collector

import (
	"context"
	"strings"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

// DML logging classification for a database instance. Only what the engine
// configuration can prove: per-user overrides inside the database are not
// visible to any AWS API and stay a manual check.
const (
	dmlLoggingConfigured    = "configured"
	dmlLoggingNotExported   = "configured_not_exported"
	dmlLoggingPending       = "pending_reboot"
	dmlLoggingNotConfigured = "not_configured"
	dmlLoggingUnknown       = "unknown"
	dmlLoggingNotClassified = "not_classified"
)

// classifyDMLLogging classifies one instance's data-change logging.
//
// The bar for configured: pgaudit loaded with a write-covering pgaudit.log, or
// log_statement at mod or all, with the parameter group in sync and the
// postgresql log exported off the instance. Desired values that are not in
// force yet classify pending rather than configured, because a pack certifying
// logging from a pending-reboot group would certify logging that is not
// happening.
func classifyDMLLogging(instance aws.DBInstance, params map[string]string, paramsErr error) string {
	if !strings.HasPrefix(instance.Engine, "postgres") {
		// aurora-postgresql keeps these settings in cluster parameter groups,
		// which this classifier does not read yet.
		return dmlLoggingNotClassified
	}
	if paramsErr != nil {
		return dmlLoggingUnknown
	}

	pgauditLoaded := listContains(params["shared_preload_libraries"], "pgaudit")
	pgauditWrites := listContains(params["pgaudit.log"], "write") || listContains(params["pgaudit.log"], "all")
	logStatement := strings.EqualFold(strings.TrimSpace(params["log_statement"]), "mod") ||
		strings.EqualFold(strings.TrimSpace(params["log_statement"]), "all")

	configured := (pgauditLoaded && pgauditWrites) || logStatement
	if !configured {
		return dmlLoggingNotConfigured
	}
	if instance.ParameterApplyStatus != "" && instance.ParameterApplyStatus != "in-sync" {
		return dmlLoggingPending
	}
	for _, export := range instance.LogExports {
		if export == "postgresql" {
			return dmlLoggingConfigured
		}
	}
	return dmlLoggingNotExported
}

func listContains(commaList, want string) bool {
	for _, item := range strings.Split(commaList, ",") {
		if strings.EqualFold(strings.TrimSpace(item), want) {
			return true
		}
	}
	return false
}

// subscriptionCoversBackupFailures reports whether an event subscription would
// carry a backup failure. Empty categories cover everything, and an empty
// source type covers all source types, so absence reads as the broadest
// coverage.
func subscriptionCoversBackupFailures(sub aws.RDSEventSubscription) bool {
	if !sub.Enabled {
		return false
	}
	if sub.SourceType != "" && sub.SourceType != "db-instance" && sub.SourceType != "db-cluster" {
		return false
	}
	if len(sub.EventCategories) == 0 {
		return true
	}
	for _, category := range sub.EventCategories {
		if strings.EqualFold(category, "backup") || strings.EqualFold(category, "failure") {
			return true
		}
	}
	return false
}

// collectRDSEventAlerting resolves the backup-alerting chain for a region:
// subscription enabled, covering backup failures, delivering to a topic with a
// confirmed subscriber.
func (c *Collector) collectRDSEventAlerting(ctx context.Context, client *aws.AWSClient, region string, metrics *RDSMetrics) {
	subs, err := client.ListRDSEventSubscriptions(ctx, region)
	if err != nil {
		c.warn("region %s: failed to read RDS event subscriptions; backup alerting is unproven: %v", region, err)
		metrics.EventSubscriptionsUnresolvedRegionCount++
		return
	}

	for _, sub := range subs {
		metrics.EventSubscriptionCount++
		if !subscriptionCoversBackupFailures(sub) {
			continue
		}
		metrics.BackupFailureAlertingSubscriptionCount++

		subscribers, err := client.GetSNSTopicSubscribers(ctx, region, sub.TopicARN)
		if err != nil {
			c.warn("region %s: failed to read subscribers for RDS event subscription %s", region, sub.ID)
			metrics.BackupAlertingTopicsUnresolvedCount++
			continue
		}
		if subscribers.Confirmed > 0 {
			metrics.BackupFailureAlertingReachingSubscriberCount++
		}
	}
}
