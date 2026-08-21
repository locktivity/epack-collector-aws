package collector

import (
	"testing"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

func TestDBInstanceToRow_TrustOmitsRestorableTime(t *testing.T) {
	restorable := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	inst := aws.DBInstance{
		DBInstanceIdentifier: "i-prod",
		Engine:               "postgres",
		EngineVersion:        "15.4",
		LatestRestorableTime: &restorable,
	}
	row := dbInstanceToRow(inst, "us-west-2", componentsdk.LevelAudit)
	if row.LatestRestorableTime != "" {
		t.Errorf("audit-only row should omit LatestRestorableTime, got %q", row.LatestRestorableTime)
	}
	if row.Region != "us-west-2" || row.Identifier != "i-prod" {
		t.Errorf("base audit fields mis-projected: %+v", row)
	}
}

func TestDBInstanceToRow_InternalPopulatesRestorableTime(t *testing.T) {
	restorable := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	inst := aws.DBInstance{DBInstanceIdentifier: "i-prod", LatestRestorableTime: &restorable}
	row := dbInstanceToRow(inst, "us-east-1", componentsdk.LevelInternal)
	if row.LatestRestorableTime != "2026-05-14T10:00:00Z" {
		t.Errorf("internal row should have RFC3339 restorable time, got %q", row.LatestRestorableTime)
	}
}

func TestDBClusterToRow_InternalPopulatesRestorableTime(t *testing.T) {
	restorable := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	cl := aws.DBCluster{DBClusterIdentifier: "c-prod", LatestRestorableTime: &restorable}
	row := dbClusterToRow(cl, "us-east-1", componentsdk.LevelInternal)
	if row.LatestRestorableTime != "2026-04-01T00:00:00Z" {
		t.Errorf("internal cluster row should have RFC3339 restorable time, got %q", row.LatestRestorableTime)
	}
}

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

func TestMergeRDSMetrics_ConcatenatesAuditInventories(t *testing.T) {
	a := rdsMetricsWithCounts{
		RDSMetrics: RDSMetrics{
			Instances: []RDSInstance{{Identifier: "i-east", Region: "us-east-1"}},
			Clusters:  []RDSCluster{{Identifier: "c-east", Region: "us-east-1"}},
		},
		instanceCount: 1,
		clusterCount:  1,
	}
	b := rdsMetricsWithCounts{
		RDSMetrics: RDSMetrics{
			Instances: []RDSInstance{
				{Identifier: "i-west-1", Region: "us-west-2"},
				{Identifier: "i-west-2", Region: "us-west-2"},
			},
		},
		instanceCount: 2,
		clusterCount:  0,
	}

	got := mergeRDSMetrics(a, b)
	if len(got.Instances) != 3 {
		t.Fatalf("expected 3 instances after merge, got %d", len(got.Instances))
	}
	if got.Instances[0].Region != "us-east-1" || got.Instances[1].Region != "us-west-2" || got.Instances[2].Region != "us-west-2" {
		t.Errorf("merge did not preserve insertion order: %+v", got.Instances)
	}
	if len(got.Clusters) != 1 {
		t.Errorf("expected 1 cluster (no clusters in b), got %d", len(got.Clusters))
	}
}

func TestMergeRDSMetrics_EmptyAuditSlicesStayEmpty(t *testing.T) {
	// Trust-only collection: no Instances/Clusters populated.
	a := rdsMetricsWithCounts{instanceCount: 5}
	b := rdsMetricsWithCounts{instanceCount: 3}

	got := mergeRDSMetrics(a, b)
	if len(got.Instances) != 0 || len(got.Clusters) != 0 {
		t.Errorf("trust-only merge should not populate audit slices, got %+v / %+v", got.Instances, got.Clusters)
	}
}

func TestEvaluateDBPortIngress(t *testing.T) {
	prod := aws.DBInstance{
		DBInstanceIdentifier: "prod-db",
		EndpointPort:         5432,
		VpcSecurityGroupIDs:  []string{"sg-db"},
	}

	t.Run("a source-group rule on the endpoint port is the only allowed source", func(t *testing.T) {
		sg := aws.SecurityGroup{GroupID: "sg-db", IngressRules: []aws.SecurityGroupRule{
			{Protocol: "tcp", FromPort: 5432, ToPort: 5432, SourceSGIDs: []string{"sg-app"}},
			{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRBlocks: []string{"0.0.0.0/0"}},
		}}

		got := evaluateDBPortIngress([]aws.DBInstance{prod}, []aws.SecurityGroup{sg})["prod-db"]

		if !got.evaluated {
			t.Fatal("verdict should be evaluated")
		}
		if got.openToInternet {
			t.Error("a world-open rule on another port must not open the database port")
		}
		if len(got.sources) != 1 || got.sources[0] != "sg-app" {
			t.Errorf("sources = %v, want [sg-app]", got.sources)
		}
	})

	t.Run("an all-protocol rule from the internet opens the port", func(t *testing.T) {
		sg := aws.SecurityGroup{GroupID: "sg-db", IngressRules: []aws.SecurityGroupRule{
			{Protocol: "-1", CIDRBlocks: []string{"0.0.0.0/0"}},
		}}

		got := evaluateDBPortIngress([]aws.DBInstance{prod}, []aws.SecurityGroup{sg})["prod-db"]

		if !got.openToInternet {
			t.Error("an all-protocol world rule covers every port, including the database port")
		}
		if len(got.sources) != 1 || got.sources[0] != "0.0.0.0/0" {
			t.Errorf("sources = %v, want [0.0.0.0/0]", got.sources)
		}
	})

	t.Run("an attached group missing from the fetch leaves the instance unevaluated", func(t *testing.T) {
		got := evaluateDBPortIngress([]aws.DBInstance{prod}, nil)["prod-db"]

		if got.evaluated {
			t.Error("reachability without the attached group is unproven, not closed")
		}
	})

	t.Run("no endpoint port leaves the instance unevaluated", func(t *testing.T) {
		pending := aws.DBInstance{DBInstanceIdentifier: "creating-db", VpcSecurityGroupIDs: []string{"sg-db"}}
		sg := aws.SecurityGroup{GroupID: "sg-db"}

		got := evaluateDBPortIngress([]aws.DBInstance{pending}, []aws.SecurityGroup{sg})["creating-db"]

		if got.evaluated {
			t.Error("no port means no reachability question to answer yet")
		}
	})

	t.Run("sources dedupe and sort across attached groups", func(t *testing.T) {
		inst := aws.DBInstance{DBInstanceIdentifier: "prod-db", EndpointPort: 5432, VpcSecurityGroupIDs: []string{"sg-a", "sg-b"}}
		sgA := aws.SecurityGroup{GroupID: "sg-a", IngressRules: []aws.SecurityGroupRule{
			{Protocol: "tcp", FromPort: 5432, ToPort: 5432, SourceSGIDs: []string{"sg-app"}},
		}}
		sgB := aws.SecurityGroup{GroupID: "sg-b", IngressRules: []aws.SecurityGroupRule{
			{Protocol: "tcp", FromPort: 0, ToPort: 65535, CIDRBlocks: []string{"10.0.0.0/16"}, SourceSGIDs: []string{"sg-app"}},
		}}

		got := evaluateDBPortIngress([]aws.DBInstance{inst}, []aws.SecurityGroup{sgA, sgB})["prod-db"]

		want := []string{"10.0.0.0/16", "sg-app"}
		if len(got.sources) != 2 || got.sources[0] != want[0] || got.sources[1] != want[1] {
			t.Errorf("sources = %v, want %v", got.sources, want)
		}
	})

	t.Run("an evaluated instance with nothing allowed keeps an empty source list", func(t *testing.T) {
		sg := aws.SecurityGroup{GroupID: "sg-db", IngressRules: []aws.SecurityGroupRule{
			{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRBlocks: []string{"10.0.0.0/16"}},
		}}

		got := evaluateDBPortIngress([]aws.DBInstance{prod}, []aws.SecurityGroup{sg})["prod-db"]

		if !got.evaluated || got.sources == nil || len(got.sources) != 0 {
			t.Errorf("verdict = %+v, want evaluated with an empty, non-nil source list", got)
		}
	})
}

func TestMergeRDSMetrics_SumsDBPortIngressCounts(t *testing.T) {
	a := rdsMetricsWithCounts{RDSMetrics: RDSMetrics{DBPortOpenToInternetCount: 1, DBPortIngressUnevaluatedCount: 2}}
	b := rdsMetricsWithCounts{RDSMetrics: RDSMetrics{DBPortIngressUnevaluatedCount: 1}}

	got := mergeRDSMetrics(a, b)

	if got.DBPortOpenToInternetCount != 1 {
		t.Errorf("DBPortOpenToInternetCount = %d, want 1", got.DBPortOpenToInternetCount)
	}
	if got.DBPortIngressUnevaluatedCount != 3 {
		t.Errorf("DBPortIngressUnevaluatedCount = %d, want 3", got.DBPortIngressUnevaluatedCount)
	}
}
