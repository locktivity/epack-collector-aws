package collector

import (
	"context"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

// rdsMetricsWithCounts is used internally to track counts for weighted averaging across regions.
type rdsMetricsWithCounts struct {
	RDSMetrics
	instanceCount int
	clusterCount  int
}

// collectRDSMetrics collects RDS security metrics for a single region.
func (c *Collector) collectRDSMetrics(ctx context.Context, client *aws.AWSClient, region string) (*rdsMetricsWithCounts, error) {
	result := &rdsMetricsWithCounts{}

	// Get instances
	instances, err := client.ListDBInstances(ctx, region)
	if err != nil {
		return result, err
	}

	// Get clusters
	clusters, err := client.ListDBClusters(ctx, region)
	if err != nil {
		clusters = nil
	}

	result.instanceCount = len(instances)
	result.clusterCount = len(clusters)

	// Calculate metrics for instances
	var encrypted, publicAccess, deletionProtection, multiAZ, adequateBackup int

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
	}

	total := len(instances) + len(clusters)
	result.EncryptedAtRest = percent(encrypted, total)
	result.PubliclyAccessible = percent(publicAccess, len(instances)) // Only instances can be public
	result.DeletionProtection = percent(deletionProtection, total)
	result.BackupRetentionAdequate = percent(adequateBackup, total)
	result.MultiAZEnabled = percent(multiAZ, total)

	return result, nil
}

// mergeRDSMetrics merges RDS metrics from multiple regions.
func mergeRDSMetrics(a, b rdsMetricsWithCounts) rdsMetricsWithCounts {
	result := a
	result.instanceCount += b.instanceCount
	result.clusterCount += b.clusterCount

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

	return result
}
