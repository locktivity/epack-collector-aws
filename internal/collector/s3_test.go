package collector

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

func TestS3BucketsToInventory_PreservesAllFlags(t *testing.T) {
	in := []aws.Bucket{
		{
			Name:                     "alpha",
			Region:                   "us-east-1",
			PublicAccessBlocked:      true,
			DefaultEncryptionEnabled: true,
			VersioningEnabled:        true,
			LoggingEnabled:           false,
		},
		{
			Name:                     "beta",
			Region:                   "us-west-2",
			PublicAccessBlocked:      false,
			DefaultEncryptionEnabled: true,
			VersioningEnabled:        false,
			LoggingEnabled:           true,
		},
	}

	out := s3BucketsToInventory(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(out))
	}
	if out[0].Name != "alpha" || out[0].Region != "us-east-1" || !out[0].PublicAccessBlocked || !out[0].VersioningEnabled || out[0].LoggingEnabled {
		t.Errorf("alpha row mis-projected: %+v", out[0])
	}
	if out[1].Name != "beta" || out[1].PublicAccessBlocked || !out[1].LoggingEnabled {
		t.Errorf("beta row mis-projected: %+v", out[1])
	}
}

func TestS3BucketsToInventory_EmptyInputReturnsEmpty(t *testing.T) {
	out := s3BucketsToInventory(nil)
	if len(out) != 0 {
		t.Errorf("expected empty inventory for nil input, got %d rows", len(out))
	}
}

// fakeS3Enricher is a focused mock for the s3BucketEnricher interface.
type fakeS3Enricher struct {
	policies   map[string]*aws.BucketPolicy
	acls       map[string]*aws.BucketACL
	lifecycles map[string]*aws.BucketLifecycle
	errs       map[string]error // keyed by "bucket:op" (e.g., "alpha:policy")
}

func (f fakeS3Enricher) GetBucketPolicy(_ context.Context, _, bucket string) (*aws.BucketPolicy, error) {
	if err, ok := f.errs[bucket+":policy"]; ok {
		return nil, err
	}
	return f.policies[bucket], nil
}

func (f fakeS3Enricher) GetBucketACL(_ context.Context, _, bucket string) (*aws.BucketACL, error) {
	if err, ok := f.errs[bucket+":acl"]; ok {
		return nil, err
	}
	return f.acls[bucket], nil
}

func (f fakeS3Enricher) GetBucketLifecycle(_ context.Context, _, bucket string) (*aws.BucketLifecycle, error) {
	if err, ok := f.errs[bucket+":lifecycle"]; ok {
		return nil, err
	}
	return f.lifecycles[bucket], nil
}

func TestEnrichS3BucketsForInternal_PopulatesAllFields(t *testing.T) {
	buckets := []S3Bucket{
		{Name: "alpha", Region: "us-east-1"},
	}
	enricher := fakeS3Enricher{
		policies: map[string]*aws.BucketPolicy{
			"alpha": {Document: `{"Version":"2012-10-17","Statement":[]}`},
		},
		acls: map[string]*aws.BucketACL{
			"alpha": {
				OwnerID: "owner123",
				Grants: []aws.BucketACLGrant{
					{GranteeType: "CanonicalUser", GranteeID: "owner123", Permission: "FULL_CONTROL"},
				},
				HasPublicGrant: false,
			},
		},
		lifecycles: map[string]*aws.BucketLifecycle{
			"alpha": {Rules: []aws.BucketLifecycleRule{
				{ID: "expire-old", Status: "Enabled", Prefix: "logs/", Expiration: "90d"},
			}},
		},
	}

	c := &Collector{}
	c.enrichS3BucketsForInternal(context.Background(), enricher, "111111111111", buckets)

	if buckets[0].Policy == nil || !strings.Contains(buckets[0].Policy.Document, "2012-10-17") {
		t.Errorf("Policy not populated correctly: %+v", buckets[0].Policy)
	}
	if buckets[0].ACL == nil || buckets[0].ACL.OwnerID != "owner123" || len(buckets[0].ACL.Grants) != 1 {
		t.Errorf("ACL not populated correctly: %+v", buckets[0].ACL)
	}
	if buckets[0].Lifecycle == nil || len(buckets[0].Lifecycle.Rules) != 1 || buckets[0].Lifecycle.Rules[0].Expiration != "90d" {
		t.Errorf("Lifecycle not populated correctly: %+v", buckets[0].Lifecycle)
	}
	if len(c.warnings) != 0 {
		t.Errorf("expected no warnings on success path, got %v", c.warnings)
	}
}

func TestEnrichS3BucketsForInternal_AbsentPolicyAndLifecycle(t *testing.T) {
	// Most buckets have no policy or lifecycle config — both should remain nil
	// (omitempty drops them from the artifact) without producing warnings.
	buckets := []S3Bucket{{Name: "no-extras", Region: "us-east-1"}}
	enricher := fakeS3Enricher{
		acls: map[string]*aws.BucketACL{
			"no-extras": {OwnerID: "owner"},
		},
		// no policies, no lifecycles
	}

	c := &Collector{}
	c.enrichS3BucketsForInternal(context.Background(), enricher, "111111111111", buckets)

	if buckets[0].Policy != nil {
		t.Errorf("expected nil Policy for absent-policy bucket, got %+v", buckets[0].Policy)
	}
	if buckets[0].Lifecycle != nil {
		t.Errorf("expected nil Lifecycle for absent-lifecycle bucket, got %+v", buckets[0].Lifecycle)
	}
	if buckets[0].ACL == nil {
		t.Errorf("expected ACL to populate")
	}
	if len(c.warnings) != 0 {
		t.Errorf("absent-policy / absent-lifecycle is not an error condition; got warnings: %v", c.warnings)
	}
}

func TestEnrichS3BucketsForInternal_AccessDeniedDiagnostic(t *testing.T) {
	buckets := []S3Bucket{{Name: "denied-bucket", Region: "us-east-1"}}
	enricher := fakeS3Enricher{
		errs: map[string]error{
			"denied-bucket:policy": errors.New("AccessDenied: caller has no s3:GetBucketPolicy permission on this bucket"),
		},
	}

	c := &Collector{}
	c.enrichS3BucketsForInternal(context.Background(), enricher, "111111111111", buckets)

	if buckets[0].Policy != nil {
		t.Errorf("expected nil Policy on AccessDenied, got %+v", buckets[0].Policy)
	}
	if len(c.warnings) != 1 {
		t.Fatalf("expected 1 warning for AccessDenied, got %d: %v", len(c.warnings), c.warnings)
	}
	if !strings.Contains(c.warnings[0], "denied-bucket") || !strings.Contains(c.warnings[0], "s3:GetBucketPolicy") {
		t.Errorf("warning missing structured detail: %q", c.warnings[0])
	}
}

func TestEnrichS3BucketsForInternal_NonAccessDeniedErrorEmitsGenericWarning(t *testing.T) {
	buckets := []S3Bucket{{Name: "transient", Region: "us-east-1"}}
	enricher := fakeS3Enricher{
		errs: map[string]error{
			"transient:acl": errors.New("connection refused"),
		},
	}

	c := &Collector{}
	c.enrichS3BucketsForInternal(context.Background(), enricher, "111111111111", buckets)

	if len(c.warnings) != 1 {
		t.Fatalf("expected 1 warning for transient error, got %d: %v", len(c.warnings), c.warnings)
	}
	if strings.Contains(c.warnings[0], "access denied") {
		t.Errorf("non-AccessDenied error should not produce access-denied warning text: %q", c.warnings[0])
	}
}
