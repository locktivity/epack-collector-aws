package collector

import (
	"testing"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

func TestKMSKeyToRow_AuditOmitsInternalFields(t *testing.T) {
	created := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	in := aws.KMSKey{
		KeyID:           "abc-123",
		ARN:             "arn:aws:kms:us-east-1:123:key/abc-123",
		KeyState:        "Enabled",
		KeyUsage:        "ENCRYPT_DECRYPT",
		KeySpec:         "SYMMETRIC_DEFAULT",
		Origin:          "AWS_KMS",
		MultiRegion:     true,
		CreationDate:    &created,
		RotationEnabled: true,
		Description:     "Used for RDS at-rest encryption",
		Aliases:         []string{"alias/rds-prod"},
	}
	row := kmsKeyToRow(in, "us-east-1", componentsdk.LevelAudit)
	if row.Region != "us-east-1" || row.KeyID != "abc-123" {
		t.Errorf("audit base fields mis-projected: %+v", row)
	}
	if row.CreationDate != "2026-05-14T10:00:00Z" {
		t.Errorf("expected RFC3339 creation_date, got %q", row.CreationDate)
	}
	if !row.MultiRegion || !row.RotationEnabled {
		t.Errorf("MultiRegion and RotationEnabled must propagate: %+v", row)
	}
	if len(row.Aliases) != 1 || row.Aliases[0] != "alias/rds-prod" {
		t.Errorf("aliases mis-projected: %+v", row)
	}
	if row.Description != "" {
		t.Errorf("audit-level row must omit Description: %+v", row)
	}
}

func TestKMSKeyToRow_InternalPopulatesDescription(t *testing.T) {
	in := aws.KMSKey{KeyID: "abc-123", Description: "Used for S3 at-rest encryption"}
	row := kmsKeyToRow(in, "us-east-1", componentsdk.LevelInternal)
	if row.Description != "Used for S3 at-rest encryption" {
		t.Errorf("internal-level row must populate Description, got %q", row.Description)
	}
}

func TestKMSKeyToRow_PendingDeletionPopulatesDate(t *testing.T) {
	deletion := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	in := aws.KMSKey{
		KeyID:        "abc-123",
		KeyState:     "PendingDeletion",
		DeletionDate: &deletion,
	}
	row := kmsKeyToRow(in, "us-east-1", componentsdk.LevelAudit)
	if row.KeyState != "PendingDeletion" || row.DeletionDate != "2026-08-14T10:00:00Z" {
		t.Errorf("deletion fields mis-projected: %+v", row)
	}
}

func TestKMSKeyToRow_DefensiveCopyOnAliases(t *testing.T) {
	aliases := []string{"alias/prod"}
	in := aws.KMSKey{KeyID: "k", Aliases: aliases}
	row := kmsKeyToRow(in, "us-east-1", componentsdk.LevelAudit)
	aliases[0] = "mutated"
	if row.Aliases[0] == "mutated" {
		t.Errorf("kmsKeyToRow did not defensively copy Aliases")
	}
}

func TestMergeKMSMetrics_SumsAggregatesAndConcatsKeys(t *testing.T) {
	a := KMSMetrics{
		CustomerManagedKeyCount:       3,
		CMKsWithRotationDisabledCount: 1,
		CMKsPendingDeletionCount:      0,
		Keys:                          []KMSKeyRow{{KeyID: "east-1"}, {KeyID: "east-2"}},
	}
	b := KMSMetrics{
		CustomerManagedKeyCount:       5,
		CMKsWithRotationDisabledCount: 2,
		CMKsPendingDeletionCount:      1,
		Keys:                          []KMSKeyRow{{KeyID: "west-1"}},
	}
	got := mergeKMSMetrics(a, b)
	if got.CustomerManagedKeyCount != 8 {
		t.Errorf("CustomerManagedKeyCount: expected 8, got %d", got.CustomerManagedKeyCount)
	}
	if got.CMKsWithRotationDisabledCount != 3 {
		t.Errorf("CMKsWithRotationDisabledCount: expected 3, got %d", got.CMKsWithRotationDisabledCount)
	}
	if got.CMKsPendingDeletionCount != 1 {
		t.Errorf("CMKsPendingDeletionCount: expected 1, got %d", got.CMKsPendingDeletionCount)
	}
	if len(got.Keys) != 3 {
		t.Errorf("expected 3 keys after merge, got %d", len(got.Keys))
	}
	if got.Keys[0].KeyID != "east-1" || got.Keys[2].KeyID != "west-1" {
		t.Errorf("merge did not preserve insertion order: %+v", got.Keys)
	}
}
