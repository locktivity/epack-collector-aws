package collector

import (
	"context"
	"sort"
	"strings"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// rdsMetricsWithCounts is used internally to track counts for weighted averaging across regions.
type rdsMetricsWithCounts struct {
	RDSMetrics
	instanceCount int
	clusterCount  int

	// Raw counts the percentages come from once every region is merged.
	encrypted          int
	publicAccess       int
	deletionProtection int
	multiAZ            int
	adequateBackup     int
	minRetention       int // -1 until a database is seen
}

func (c *Collector) collectRDSMetrics(ctx context.Context, client *aws.AWSClient, region string, level componentsdk.Level) (*rdsMetricsWithCounts, error) {
	result := &rdsMetricsWithCounts{minRetention: -1}

	instances, err := client.ListDBInstances(ctx, region)
	if err != nil {
		return result, err
	}

	clusters, err := client.ListDBClusters(ctx, region)
	if err != nil {
		return result, err
	}

	result.instanceCount = len(instances)
	result.clusterCount = len(clusters)

	c.collectRDSEventAlerting(ctx, client, region, &result.RDSMetrics)

	// Data-change logging per postgres instance. Parameter groups are shared
	// across instances, so each is read once.
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
	for _, inst := range instances {
		switch dmlByInstance[inst.DBInstanceIdentifier] {
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
			result.missing.addPartial(paramErrByGroup[inst.ParameterGroupName], 1, "dml_logging_configured_count", "dml_logging_not_exported_count",
				"dml_logging_pending_count", "dml_logging_not_configured_count")
		case dmlLoggingNotClassified:
			result.DMLLoggingNotClassifiedCount++
		}
	}

	ingressByInstance, ingressErr := c.collectDBPortIngress(ctx, client, region, instances)
	for _, verdict := range ingressByInstance {
		if !verdict.evaluated {
			result.DBPortIngressUnevaluatedCount++
			continue
		}
		if verdict.openToInternet {
			result.DBPortOpenToInternetCount++
		}
	}
	if ingressErr != nil {
		result.missing.addPartial(ingressErr, countWithSecurityGroups(instances), "db_port_open_to_internet_count")
	}

	if level.AtLeast(componentsdk.LevelAudit) {
		result.Instances = make([]RDSInstance, 0, len(instances))
		for _, inst := range instances {
			row := dbInstanceToRow(inst, region, level)
			row.DMLLogging = dmlByInstance[inst.DBInstanceIdentifier]
			if row.DMLLogging == dmlLoggingUnknown {
				row.missing.add(paramErrByGroup[inst.ParameterGroupName], "dml_logging")
			}
			verdict := ingressByInstance[inst.DBInstanceIdentifier]
			row.DBPortIngressEvaluated = boolPtr(verdict.evaluated)
			if verdict.evaluated {
				row.DBPortOpenToInternet = boolPtr(verdict.openToInternet)
				row.DBPortIngressSources = verdict.sources
			} else if ingressErr != nil && inst.EndpointPort != 0 && len(inst.VpcSecurityGroupIDs) > 0 {
				row.missing.add(ingressErr, "db_port_open_to_internet", "db_port_ingress_sources")
			}
			result.Instances = append(result.Instances, row)
		}
		result.Clusters = make([]RDSCluster, 0, len(clusters))
		for _, cl := range clusters {
			result.Clusters = append(result.Clusters, dbClusterToRow(cl, region, level))
		}
	}

	for _, inst := range instances {
		result.countDatabase(inst.StorageEncrypted, inst.DeletionProtection, inst.MultiAZ, inst.BackupRetentionPeriod)
		if inst.PubliclyAccessible {
			result.publicAccess++
		}
	}
	for _, cluster := range clusters {
		result.countDatabase(cluster.StorageEncrypted, cluster.DeletionProtection, cluster.MultiAZ, cluster.BackupRetentionPeriod)
	}

	return result, nil
}

func (m *rdsMetricsWithCounts) countDatabase(encrypted, deletionProtection, multiAZ bool, retention int) {
	if encrypted {
		m.encrypted++
	}
	if deletionProtection {
		m.deletionProtection++
	}
	if multiAZ {
		m.multiAZ++
	}
	if retention >= MinBackupRetentionDays {
		m.adequateBackup++
	}
	if m.minRetention == -1 || retention < m.minRetention {
		m.minRetention = retention
	}
}

// finalize computes the percentages and the minimum retention from the
// merged counts. Each is nil over an empty population.
func (m *rdsMetricsWithCounts) finalize() {
	total := m.instanceCount + m.clusterCount
	m.DatabaseCount = total
	m.InstanceCount = m.instanceCount
	m.EncryptedAtRest = pctOf(m.encrypted, total)
	m.EncryptedAtRestDatabaseCount = m.encrypted
	m.PubliclyAccessible = pctOf(m.publicAccess, m.instanceCount)
	m.PubliclyAccessibleInstanceCount = m.publicAccess
	m.DeletionProtection = pctOf(m.deletionProtection, total)
	m.DeletionProtectionDatabaseCount = m.deletionProtection
	m.BackupRetentionAdequate = pctOf(m.adequateBackup, total)
	m.BackupRetentionAdequateDatabaseCount = m.adequateBackup
	m.MultiAZEnabled = pctOf(m.multiAZ, total)
	m.MultiAZEnabledDatabaseCount = m.multiAZ
	m.BackupRetentionMin = nil
	if m.minRetention >= 0 {
		v := m.minRetention
		m.BackupRetentionMin = &v
	}
}

func countWithSecurityGroups(instances []aws.DBInstance) int {
	n := 0
	for _, inst := range instances {
		if inst.EndpointPort != 0 && len(inst.VpcSecurityGroupIDs) > 0 {
			n++
		}
	}
	return n
}

type dbPortIngress struct {
	evaluated      bool
	openToInternet bool
	sources        []string
}

// collectDBPortIngress fetches the security groups attached to the region's
// instances and evaluates database-port reachability. On a fetch failure every
// instance stays unevaluated: reachability is unproven, not closed.
func (c *Collector) collectDBPortIngress(ctx context.Context, client *aws.AWSClient, region string, instances []aws.DBInstance) (map[string]dbPortIngress, error) {
	if len(instances) == 0 {
		return nil, nil
	}

	seen := map[string]bool{}
	var groupIDs []string
	for _, inst := range instances {
		for _, id := range inst.VpcSecurityGroupIDs {
			if !seen[id] {
				seen[id] = true
				groupIDs = append(groupIDs, id)
			}
		}
	}

	var sgs []aws.SecurityGroup
	var sgErr error
	if len(groupIDs) > 0 {
		sgs, sgErr = client.ListSecurityGroupsByID(ctx, region, groupIDs)
		if sgErr != nil {
			c.warn("region %s: failed to read security groups for database-port ingress; reachability is unproven, not closed: %v", region, sgErr)
			sgs = nil
		}
	}

	return evaluateDBPortIngress(instances, sgs), sgErr
}

// evaluateDBPortIngress resolves, per instance, which sources the security
// groups allow on the instance's listening port. An instance with no endpoint
// port or with an attached group missing from sgs stays unevaluated.
func evaluateDBPortIngress(instances []aws.DBInstance, sgs []aws.SecurityGroup) map[string]dbPortIngress {
	byID := make(map[string]aws.SecurityGroup, len(sgs))
	for _, sg := range sgs {
		byID[sg.GroupID] = sg
	}

	out := make(map[string]dbPortIngress, len(instances))
	for _, inst := range instances {
		out[inst.DBInstanceIdentifier] = instanceDBPortIngress(inst, byID)
	}
	return out
}

func instanceDBPortIngress(inst aws.DBInstance, byID map[string]aws.SecurityGroup) dbPortIngress {
	if inst.EndpointPort == 0 || len(inst.VpcSecurityGroupIDs) == 0 {
		return dbPortIngress{}
	}

	verdict := dbPortIngress{evaluated: true, sources: []string{}}
	seen := map[string]bool{}
	for _, id := range inst.VpcSecurityGroupIDs {
		sg, ok := byID[id]
		if !ok {
			return dbPortIngress{}
		}
		for _, rule := range sg.IngressRules {
			if !rule.CoversTCPPort(inst.EndpointPort) {
				continue
			}
			if rule.IsOpenToWorld() {
				verdict.openToInternet = true
			}
			for _, source := range rule.CIDRBlocks {
				if !seen[source] {
					seen[source] = true
					verdict.sources = append(verdict.sources, source)
				}
			}
			for _, source := range rule.SourceSGIDs {
				if !seen[source] {
					seen[source] = true
					verdict.sources = append(verdict.sources, source)
				}
			}
		}
	}
	sort.Strings(verdict.sources)
	return verdict
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
	result.encrypted += b.encrypted
	result.publicAccess += b.publicAccess
	result.deletionProtection += b.deletionProtection
	result.multiAZ += b.multiAZ
	result.adequateBackup += b.adequateBackup
	if b.minRetention >= 0 && (result.minRetention == -1 || b.minRetention < result.minRetention) {
		result.minRetention = b.minRetention
	}

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
	result.DBPortOpenToInternetCount += b.DBPortOpenToInternetCount
	result.DBPortIngressUnevaluatedCount += b.DBPortIngressUnevaluatedCount
	result.missing.merge(b.missing)

	result.Instances = appendRows(result.Instances, b.Instances)
	result.Clusters = appendRows(result.Clusters, b.Clusters)
	return result
}
