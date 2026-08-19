package collector

import (
	"testing"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

func TestEC2InstanceToRow_AuditOmitsInternalFields(t *testing.T) {
	launched := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	in := aws.EC2Instance{
		InstanceID:            "i-abc",
		InstanceType:          "t3.medium",
		State:                 "running",
		LaunchTime:            &launched,
		ImageID:               "ami-1",
		VPCID:                 "vpc-1",
		SubnetID:              "subnet-1",
		HasPublicIP:           true,
		PublicIP:              "203.0.113.10",
		HTTPTokens:            "required",
		HTTPHopLimit:          1,
		SecurityGroupIDs:      []string{"sg-1", "sg-2"},
		IAMInstanceProfileARN: "arn:aws:iam::123:instance-profile/x",
		KeyName:               "alice",
		AttachedVolumeIDs:     []string{"vol-1", "vol-2"},
		Tags:                  map[string]string{"Env": "prod", "Team": "platform"},
	}
	row := ec2InstanceToRow(in, "us-east-1", false, true, componentsdk.LevelAudit)
	if row.InstanceID != "i-abc" || row.Region != "us-east-1" || !row.HasPublicIP {
		t.Errorf("audit base fields mis-projected: %+v", row)
	}
	if row.LaunchTime != "2026-05-14T10:00:00Z" {
		t.Errorf("expected RFC3339 launch_time, got %q", row.LaunchTime)
	}
	if !row.RootVolumeEncrypted {
		t.Errorf("RootVolumeEncrypted should be true")
	}
	if row.IAMInstanceProfileARN != "" || row.KeyName != "" {
		t.Errorf("audit-level row must omit internal-only fields: %+v", row)
	}
	if len(row.Tags) != 0 || len(row.AttachedVolumeIDs) != 0 {
		t.Errorf("audit-level row must omit internal-only slices: %+v", row)
	}
}

func TestEC2InstanceToRow_InternalPopulatesAllFields(t *testing.T) {
	in := aws.EC2Instance{
		InstanceID:            "i-abc",
		IAMInstanceProfileARN: "arn:aws:iam::123:instance-profile/x",
		KeyName:               "alice",
		AttachedVolumeIDs:     []string{"vol-1"},
		Tags:                  map[string]string{"Env": "prod"},
	}
	row := ec2InstanceToRow(in, "us-east-1", true, false, componentsdk.LevelInternal)
	if row.IAMInstanceProfileARN == "" || row.KeyName == "" {
		t.Errorf("internal-level row must populate IAM profile and key name: %+v", row)
	}
	if len(row.AttachedVolumeIDs) != 1 || len(row.Tags) != 1 {
		t.Errorf("internal-level row must populate volume IDs and tags: %+v", row)
	}
	if !row.InDefaultVPC {
		t.Errorf("InDefaultVPC should propagate from caller")
	}
}

func TestEC2InstanceToRow_DefensiveCopyOnSlices(t *testing.T) {
	sgs := []string{"sg-1"}
	in := aws.EC2Instance{InstanceID: "i-abc", SecurityGroupIDs: sgs}
	row := ec2InstanceToRow(in, "us-east-1", false, false, componentsdk.LevelAudit)
	sgs[0] = "mutated"
	if row.SecurityGroupIDs[0] == "mutated" {
		t.Errorf("ec2InstanceToRow did not defensively copy SecurityGroupIDs")
	}
}

func TestInstanceHasUnencryptedVolume(t *testing.T) {
	encrypted := map[string]aws.EBSVolumeState{
		"vol-1": {Encrypted: true, Attached: true},
		"vol-2": {Encrypted: false, Attached: true},
		"vol-3": {Encrypted: true, Attached: true},
	}

	if !instanceHasUnencryptedVolume(aws.EC2Instance{AttachedVolumeIDs: []string{"vol-1", "vol-2"}}, encrypted) {
		t.Errorf("instance with vol-2 (unencrypted) should return true")
	}
	if instanceHasUnencryptedVolume(aws.EC2Instance{AttachedVolumeIDs: []string{"vol-1", "vol-3"}}, encrypted) {
		t.Errorf("instance with all encrypted volumes should return false")
	}
	if instanceHasUnencryptedVolume(aws.EC2Instance{AttachedVolumeIDs: []string{"vol-unknown"}}, encrypted) {
		t.Errorf("instance with unknown volume (no info) should return false (not flag as unencrypted)")
	}
}

func TestTruncateTags(t *testing.T) {
	in := map[string]string{"a": "1", "b": "2", "c": "3"}
	if got := truncateTags(in, 5); len(got) != 3 {
		t.Errorf("under-cap should preserve all tags, got %d", len(got))
	}
	if got := truncateTags(in, 2); len(got) != 2 {
		t.Errorf("over-cap should truncate, got %d", len(got))
	}
	if got := truncateTags(map[string]string{}, 5); len(got) != 0 {
		t.Errorf("empty input should return empty map, got %d", len(got))
	}
}

func TestMergeEC2Metrics_SumsAggregatesAndConcatsInstances(t *testing.T) {
	a := EC2Metrics{
		InstanceCount:                       3,
		IMDSv2RequiredCount:                 2,
		PublicIPCount:                       1,
		DefaultVPCCount:                     1,
		InstancesWithUnencryptedVolumeCount: 0,
		Instances:                           []EC2InstanceRow{{InstanceID: "i-east-1"}, {InstanceID: "i-east-2"}},
	}
	b := EC2Metrics{
		InstanceCount:                       5,
		IMDSv2RequiredCount:                 4,
		PublicIPCount:                       2,
		DefaultVPCCount:                     0,
		InstancesWithUnencryptedVolumeCount: 1,
		Instances:                           []EC2InstanceRow{{InstanceID: "i-west-1"}},
	}
	got := mergeEC2Metrics(a, b)
	if got.InstanceCount != 8 || got.IMDSv2RequiredCount != 6 || got.PublicIPCount != 3 {
		t.Errorf("aggregate sums incorrect: %+v", got)
	}
	if got.InstancesWithUnencryptedVolumeCount != 1 {
		t.Errorf("InstancesWithUnencryptedVolumeCount: expected 1, got %d", got.InstancesWithUnencryptedVolumeCount)
	}
	if len(got.Instances) != 3 {
		t.Errorf("expected 3 instances after merge, got %d", len(got.Instances))
	}
	if got.Instances[0].InstanceID != "i-east-1" || got.Instances[2].InstanceID != "i-west-1" {
		t.Errorf("merge did not preserve insertion order: %+v", got.Instances)
	}
}

// Unattached volumes keep their data but are invisible to the instance join,
// so they are counted separately rather than folded into the instance figure.
func TestCountUnattachedVolumes(t *testing.T) {
	volumes := map[string]aws.EBSVolumeState{
		"vol-attached-enc":   {Encrypted: true, Attached: true},
		"vol-attached-plain": {Encrypted: false, Attached: true},
		"vol-loose-enc":      {Encrypted: true, Attached: false},
		"vol-loose-plain":    {Encrypted: false, Attached: false},
		"vol-loose-plain-2":  {Encrypted: false, Attached: false},
	}

	total, unencrypted := countUnattachedVolumes(volumes)

	if total != 3 {
		t.Errorf("total = %d, want 3 unattached volumes", total)
	}
	if unencrypted != 2 {
		t.Errorf("unencrypted = %d, want 2", unencrypted)
	}
}

func TestCountUnattachedVolumesEmpty(t *testing.T) {
	total, unencrypted := countUnattachedVolumes(map[string]aws.EBSVolumeState{})
	if total != 0 || unencrypted != 0 {
		t.Fatalf("got %d and %d, want 0 and 0", total, unencrypted)
	}
}
