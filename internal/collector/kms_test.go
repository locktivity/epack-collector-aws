package collector

import (
	"net/http"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
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

// A multi-Region primary key scheduled for deletion is in the
// PendingReplicaDeletion state until its replicas are gone, and counts as
// pending deletion, as a key in PendingDeletion does. KMS reports a key
// pending deletion with rotation off, and restores the setting if the
// deletion is canceled. Such a key is not counted as one with rotation off.
// A disabled key keeps its owner's setting.
func TestKMS_KeysScheduledForDeletionAreCounted(t *testing.T) {
	const (
		keyID  = "mrk-1234abcd12ab34cd56ef1234567890ab"
		keyARN = "arn:aws:kms:us-east-1:111122223333:key/" + keyID
	)
	for _, tc := range []struct {
		state                string
		extra                map[string]any
		pending, rotationOff int
	}{
		{"PendingDeletion", map[string]any{"DeletionDate": 1769904000}, 1, 0},
		{"PendingReplicaDeletion", map[string]any{"PendingDeletionWindowInDays": 30}, 1, 0},
		{"Disabled", nil, 0, 1},
	} {
		t.Run(tc.state, func(t *testing.T) {
			meta := map[string]any{
				"KeyId": keyID, "Arn": keyARN, "AWSAccountId": kitAccountID,
				"KeyManager": "CUSTOMER", "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT", "KeyState": tc.state, "Origin": "AWS_KMS",
				"Enabled": false, "MultiRegion": true, "CreationDate": 1735689600,
			}
			for k, v := range tc.extra {
				meta[k] = v
			}
			responses := replaceResponses(kitResponses(),
				jsonResponse("aws.kms.ListKeys", regional("kms"), map[string]any{"Keys": []any{
					map[string]any{"KeyId": kitKMSKeyID, "KeyArn": "arn:aws:kms:us-east-1:111122223333:key/" + kitKMSKeyID},
					map[string]any{"KeyId": keyID, "KeyArn": keyARN},
				}, "Truncated": false}))
			responses = append(responses,
				jsonItemResponse("aws.kms.DescribeKey", regional("kms"), map[string]any{"KeyId": keyID}, map[string]any{"KeyMetadata": meta}),
				jsonItemResponse("aws.kms.GetKeyRotationStatus", regional("kms"), map[string]any{"KeyId": keyID}, map[string]any{"KeyId": keyARN, "KeyRotationEnabled": false}))

			k := runOutput(t, responses).Accounts[0].KMS
			if k.CustomerManagedKeyCount != 2 || k.CMKsPendingDeletionCount != tc.pending {
				t.Errorf("customer_managed_key_count = %d, cmks_pending_deletion_count = %d; want 2 and %d", k.CustomerManagedKeyCount, k.CMKsPendingDeletionCount, tc.pending)
			}
			if k.CMKsWithRotationDisabledCount != tc.rotationOff {
				t.Errorf("cmks_with_rotation_disabled_count = %d, want %d", k.CMKsWithRotationDisabledCount, tc.rotationOff)
			}
		})
	}
}

// Only the audit-level key rows carry aliases, and kms:ListAliases is an
// audit-level action. A trust-level run does not read aliases, so a role
// without that action still gets the key counts.
func TestCollectKMSMetrics_TrustLevelDoesNotReadAliases(t *testing.T) {
	trust := map[string]any{"role_arn": kitRoleARN, "auth_mode": "oidc", "level": "trust"}
	denied := collectortest.Response{
		Operation: "aws.kms.ListAliases", Method: http.MethodPost, URL: regional("kms"), Status: http.StatusBadRequest,
		Header: jsonHeader("application/x-amz-json-1.1"),
		Body: kitJSON(map[string]any{"__type": "AccessDeniedException", "message": kitCaller +
			"kms:ListAliases on resource: * because no identity-based policy allows the kms:ListAliases action"}),
	}
	res, out := runWithGaps(t, trust, replaceResponses(kitResponses(), denied))
	if k := out.Accounts[0].KMS; k.CustomerManagedKeyCount != 1 || k.CMKsWithRotationDisabledCount != 0 || k.CMKsPendingDeletionCount != 0 {
		t.Errorf("kms counts = %d, %d, %d; want 1, 0, 0", k.CustomerManagedKeyCount, k.CMKsWithRotationDisabledCount, k.CMKsPendingDeletionCount)
	}
	if gap := gapAt(res, awsPath, "/accounts/0/kms"); gap != nil {
		t.Errorf("unexpected gap at /accounts/0/kms: %+v", gap)
	}
}
