package collector

import (
	"context"
	"strings"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// rdsMetricsWithCounts is used internally to track counts for weighted averaging across regions.
type rdsMetricsWithCounts struct {
	RDSMetrics
	instanceCount int
	clusterCount  int
}

// collectRDSMetrics collects RDS security metrics for a single region.
//
// At trust, only the aggregate percentages are populated. At audit, per-instance
// and per-cluster rows are surfaced from the same ListDBInstances /
// ListDBClusters iteration (no extra API calls). Each row carries its region.
func (c *Collector) collectRDSMetrics(ctx context.Context, client *aws.AWSClient, region string, level componentsdk.Level) (*rdsMetricsWithCounts, error) {
	result := &rdsMetricsWithCounts{}

	// Get instances
	instances, err := client.ListDBInstances(ctx, region)
	if err != nil {
		return result, err
	}

	// Get clusters. A cluster-listing failure fails the region: aggregates
	// computed over instances alone would silently overstate posture (for
	// example a retention minimum that ignores the clusters).
	clusters, err := client.ListDBClusters(ctx, region)
	if err != nil {
		return result, err
	}

	result.instanceCount = len(instances)
	result.clusterCount = len(clusters)

	c.collectRDSEventAlerting(ctx, client, region, &result.RDSMetrics)

	// One parameter read per distinct in-use group, not per instance.
	paramsByGroup := map[string]map[string]string{}
	paramErrByGroup := map[string]error{}
	dmlByInstance := map[string]string{}
	for _, inst := range instances {
		if !strings.HasPrefix(inst.Engine, "postgres") || inst.ParameterGroupName == "" {
			dmlByInstance[inst.DBInstanceIdentifier] = classifyDMLLogging(inst, nil, nil)
			continue
		}
		if _, seen := paramsByGroup[inst.ParameterGroupName]; !seen {
			params, err := client.GetDBParameters(ctx, region, inst.ParameterGroupName)
			paramsByGroup[inst.ParameterGroupName] = params
			paramErrByGroup[inst.ParameterGroupName] = err
			if err != nil {
				c.warn("region %s: failed to read parameter group %s; data-change logging is unknown, not absent: %v", region, inst.ParameterGroupName, err)
			}
		}
		dmlByInstance[inst.DBInstanceIdentifier] = classifyDMLLogging(inst, paramsByGroup[inst.ParameterGroupName], paramErrByGroup[inst.ParameterGroupName])
	}
	for _, verdict := range dmlByInstance {
		switch verdict {
		case dmlLoggingConfigured:
			result.DMLLoggingConfiguredCount++
		case dmlLoggingNotExported:
			result.DMLLoggingNotExportedCount++
		case dmlLoggingPending:
			result.DMLLoggingPendingCount++
		case dmlLoggingNotConfigured:
			result.DMLLoggingNotConfiguredCount++
		case dmlLoggingUnknown:
			result.DMLLoggingUnknownCount++
		case dmlLoggingNotClassified:
			result.DMLLoggingNotClassifiedCount++
		}
	}

	if level.AtLeast(componentsdk.LevelAudit) {
		for _, inst := range instances {
			row := dbInstanceToRow(inst, region, level)
			row.DMLLogging = dmlByInstance[inst.DBInstanceIdentifier]
			result.Instances = append(result.Instances, row)
		}
		for _, cl := range clusters {
			result.Clusters = append(result.Clusters, dbClusterToRow(cl, region, level))
		}
	}

	// Calculate metrics for instances
	var encrypted, publicAccess, deletionProtection, multiAZ, adequateBackup int
	minRetention := -1 // -1 means no instances found yet

	for _, inst := range instances {
		if inst.StorageEncrypted {
			encrypted++
		}
		if inst.PubliclyAccessible {
			publicAccess++
		}
		if inst.DeletionProtection {
			deletionProtection++
		}
		if inst.MultiAZ {
			multiAZ++
		}
		if inst.BackupRetentionPeriod >= MinBackupRetentionDays {
			adequateBackup++
		}
		// Track minimum retention
		if minRetention == -1 || inst.BackupRetentionPeriod < minRetention {
			minRetention = inst.BackupRetentionPeriod
		}
	}

	// Also count clusters
	for _, cluster := range clusters {
		if cluster.StorageEncrypted {
			encrypted++
		}
		if cluster.DeletionProtection {
			deletionProtection++
		}
		if cluster.MultiAZ {
			multiAZ++
		}
		if cluster.BackupRetentionPeriod >= MinBackupRetentionDays {
			adequateBackup++
		}
		// Track minimum retention
		if minRetention == -1 || cluster.BackupRetentionPeriod < minRetention {
			minRetention = cluster.BackupRetentionPeriod
		}
	}

	total := len(instances) + len(clusters)
	result.EncryptedAtRest = percent(encrypted, total)
	result.PubliclyAccessible = percent(publicAccess, len(instances)) // Only instances can be public
	result.DeletionProtection = percent(deletionProtection, total)
	result.BackupRetentionAdequate = percent(adequateBackup, total)
	result.MultiAZEnabled = percent(multiAZ, total)

	// Set minimum retention (0 if no instances found)
	if minRetention == -1 {
		result.BackupRetentionMin = 0
	} else {
		result.BackupRetentionMin = minRetention
	}

	return result, nil
}

// dbInstanceToRow projects a single DBInstance onto the audit-level row, with
// the internal-only LatestRestorableTime populated when level >= internal.
func dbInstanceToRow(inst aws.DBInstance, region string, level componentsdk.Level) RDSInstance {
	row := RDSInstance{
		Identifier:            inst.DBInstanceIdentifier,
		Region:                region,
		Engine:                inst.Engine,
		EngineVersion:         inst.EngineVersion,
		StorageEncrypted:      inst.StorageEncrypted,
		PubliclyAccessible:    inst.PubliclyAccessible,
		DeletionProtection:    inst.DeletionProtection,
		BackupRetentionPeriod: inst.BackupRetentionPeriod,
		PreferredBackupWindow: inst.PreferredBackupWindow,
		MultiAZ:               inst.MultiAZ,
	}
	if level.AtLeast(componentsdk.LevelInternal) {
		row.LatestRestorableTime = formatRFC3339(inst.LatestRestorableTime)
	}
	return row
}

// dbClusterToRow projects a single DBCluster onto the audit-level row.
// Same level-gating as dbInstanceToRow.
func dbClusterToRow(cl aws.DBCluster, region string, level componentsdk.Level) RDSCluster {
	row := RDSCluster{
		Identifier:            cl.DBClusterIdentifier,
		Region:                region,
		Engine:                cl.Engine,
		EngineVersion:         cl.EngineVersion,
		StorageEncrypted:      cl.StorageEncrypted,
		DeletionProtection:    cl.DeletionProtection,
		BackupRetentionPeriod: cl.BackupRetentionPeriod,
		MultiAZ:               cl.MultiAZ,
	}
	if level.AtLeast(componentsdk.LevelInternal) {
		row.LatestRestorableTime = formatRFC3339(cl.LatestRestorableTime)
	}
	return row
}

// mergeRDSMetrics merges RDS metrics from multiple regions.
//
// Trust-level aggregates are weighted-averaged across regions; audit-level
// per-instance and per-cluster inventories are concatenated.
func mergeRDSMetrics(a, b rdsMetricsWithCounts) rdsMetricsWithCounts {
	result := a
	result.instanceCount += b.instanceCount
	result.clusterCount += b.clusterCount

	// New-count fields sum across regions.
	result.EventSubscriptionCount += b.EventSubscriptionCount
	result.BackupFailureAlertingSubscriptionCount += b.BackupFailureAlertingSubscriptionCount
	result.BackupFailureAlertingReachingSubscriberCount += b.BackupFailureAlertingReachingSubscriberCount
	result.BackupAlertingTopicsUnresolvedCount += b.BackupAlertingTopicsUnresolvedCount
	result.EventSubscriptionsUnresolvedRegionCount += b.EventSubscriptionsUnresolvedRegionCount
	result.DMLLoggingConfiguredCount += b.DMLLoggingConfiguredCount
	result.DMLLoggingNotExportedCount += b.DMLLoggingNotExportedCount
	result.DMLLoggingPendingCount += b.DMLLoggingPendingCount
	result.DMLLoggingNotConfiguredCount += b.DMLLoggingNotConfiguredCount
	result.DMLLoggingUnknownCount += b.DMLLoggingUnknownCount
	result.DMLLoggingNotClassifiedCount += b.DMLLoggingNotClassifiedCount

	// Audit-level slices: concatenate across regions.
	if len(b.Instances) > 0 {
		result.Instances = append(result.Instances, b.Instances...)
	}
	if len(b.Clusters) > 0 {
		result.Clusters = append(result.Clusters, b.Clusters...)
	}

	// Weighted averages for percentages
	totalA := a.instanceCount + a.clusterCount
	totalB := b.instanceCount + b.clusterCount
	totalAll := totalA + totalB

	if totalAll > 0 {
		result.EncryptedAtRest = (a.EncryptedAtRest*totalA + b.EncryptedAtRest*totalB) / totalAll
		result.DeletionProtection = (a.DeletionProtection*totalA + b.DeletionProtection*totalB) / totalAll
		result.BackupRetentionAdequate = (a.BackupRetentionAdequate*totalA + b.BackupRetentionAdequate*totalB) / totalAll
		result.MultiAZEnabled = (a.MultiAZEnabled*totalA + b.MultiAZEnabled*totalB) / totalAll
	}

	// Instance-specific metrics
	instancesAll := a.instanceCount + b.instanceCount
	if instancesAll > 0 {
		result.PubliclyAccessible = (a.PubliclyAccessible*a.instanceCount + b.PubliclyAccessible*b.instanceCount) / instancesAll
	}

	// Minimum retention is the min across regions (only if both have instances)
	if totalA > 0 && totalB > 0 {
		if a.BackupRetentionMin < b.BackupRetentionMin {
			result.BackupRetentionMin = a.BackupRetentionMin
		} else {
			result.BackupRetentionMin = b.BackupRetentionMin
		}
	} else if totalB > 0 {
		result.BackupRetentionMin = b.BackupRetentionMin
	}
	// else keep a's value (already in result)

	return result
}
