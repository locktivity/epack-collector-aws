package collector

import "testing"

func TestMergeRDSMetrics(t *testing.T) {
	a := rdsMetricsWithCounts{
		RDSMetrics: RDSMetrics{
			EncryptedAtRest:         100,
			PubliclyAccessible:      50,
			DeletionProtection:      100,
			BackupRetentionAdequate: 100,
			MultiAZEnabled:          100,
		},
		instanceCount: 2,
		clusterCount:  1,
	}
	b := rdsMetricsWithCounts{
		RDSMetrics: RDSMetrics{
			EncryptedAtRest:         0,
			PubliclyAccessible:      0,
			DeletionProtection:      0,
			BackupRetentionAdequate: 0,
			MultiAZEnabled:          0,
		},
		instanceCount: 2,
		clusterCount:  1,
	}

	got := mergeRDSMetrics(a, b)
	if got.EncryptedAtRest != 50 {
		t.Fatalf("expected EncryptedAtRest=50, got %d", got.EncryptedAtRest)
	}
	if got.PubliclyAccessible != 25 {
		t.Fatalf("expected PubliclyAccessible=25, got %d", got.PubliclyAccessible)
	}
	if got.DeletionProtection != 50 {
		t.Fatalf("expected DeletionProtection=50, got %d", got.DeletionProtection)
	}
	if got.BackupRetentionAdequate != 50 {
		t.Fatalf("expected BackupRetentionAdequate=50, got %d", got.BackupRetentionAdequate)
	}
	if got.MultiAZEnabled != 50 {
		t.Fatalf("expected MultiAZEnabled=50, got %d", got.MultiAZEnabled)
	}
	if got.instanceCount != 4 {
		t.Fatalf("expected instanceCount=4, got %d", got.instanceCount)
	}
	if got.clusterCount != 2 {
		t.Fatalf("expected clusterCount=2, got %d", got.clusterCount)
	}
}

func TestMergeRDSMetricsZeroCounts(t *testing.T) {
	got := mergeRDSMetrics(rdsMetricsWithCounts{}, rdsMetricsWithCounts{})
	if got.EncryptedAtRest != 0 || got.PubliclyAccessible != 0 || got.MultiAZEnabled != 0 {
		t.Fatalf("expected zero metrics, got %+v", got.RDSMetrics)
	}
}
