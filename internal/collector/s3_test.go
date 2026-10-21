package collector

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

func TestS3BucketsToInventory_PreservesAllFlags(t *testing.T) {
	in := []aws.Bucket{
		{
			Name:                         "alpha",
			Region:                       "us-east-1",
			EffectivePublicAccessBlocked: true,
			DefaultEncryptionEnabled:     true,
			DefaultEncryptionEvaluated:   true,
			VersioningEnabled:            true,
			LoggingEnabled:               false,
		},
		{
			Name:                         "beta",
			Region:                       "us-west-2",
			EffectivePublicAccessBlocked: false,
			DefaultEncryptionEnabled:     true,
			DefaultEncryptionEvaluated:   true,
			VersioningEnabled:            false,
			LoggingEnabled:               true,
		},
		{
			Name:                         "gamma",
			Region:                       "us-west-1",
			EffectivePublicAccessBlocked: true,
			DefaultEncryptionErrorCode:   "AccessDenied",
			VersioningEnabled:            true,
			LoggingEnabled:               true,
		},
	}

	out := s3BucketsToInventory(in, aws.PublicAccessBlockSettings{})
	if len(out) != 3 {
		t.Fatalf("expected 3 buckets, got %d", len(out))
	}
	if out[0].Name != "alpha" || out[0].Region != "us-east-1" || !out[0].PublicAccessBlocked || !out[0].DefaultEncryptionEvaluated || !out[0].VersioningEnabled || out[0].LoggingEnabled {
		t.Errorf("alpha row mis-projected: %+v", out[0])
	}
	if out[0].DefaultEncryptionEnabled == nil || !*out[0].DefaultEncryptionEnabled {
		t.Errorf("alpha default encryption should be true, got %v", out[0].DefaultEncryptionEnabled)
	}
	if out[1].Name != "beta" || out[1].PublicAccessBlocked || !out[1].DefaultEncryptionEvaluated || !out[1].LoggingEnabled {
		t.Errorf("beta row mis-projected: %+v", out[1])
	}
	if out[1].DefaultEncryptionEnabled == nil || !*out[1].DefaultEncryptionEnabled {
		t.Errorf("beta default encryption should be true, got %v", out[1].DefaultEncryptionEnabled)
	}
	if out[2].Name != "gamma" || out[2].DefaultEncryptionEvaluated {
		t.Errorf("gamma row should preserve unevaluated encryption state: %+v", out[2])
	}
	if out[2].DefaultEncryptionEnabled != nil {
		t.Errorf("gamma default encryption should be nil when unevaluated, got %v", out[2].DefaultEncryptionEnabled)
	}
	if out[2].DefaultEncryptionErrorCode != "AccessDenied" {
		t.Errorf("gamma error code = %q, want AccessDenied", out[2].DefaultEncryptionErrorCode)
	}
}

func TestS3BucketsToInventory_EmptyInputReturnsEmpty(t *testing.T) {
	out := s3BucketsToInventory(nil, aws.PublicAccessBlockSettings{})
	if len(out) != 0 {
		t.Errorf("expected empty inventory for nil input, got %d rows", len(out))
	}
}

func TestSummarizeS3Buckets_DefaultEncryptionMarksUnknownBuckets(t *testing.T) {
	buckets := []aws.Bucket{
		{
			Name:                       "encrypted",
			DefaultEncryptionEnabled:   true,
			DefaultEncryptionEvaluated: true,
		},
		{
			Name:                       "inferred",
			DefaultEncryptionEnabled:   true,
			DefaultEncryptionEvaluated: true,
			DefaultEncryptionErrorCode: "ServerSideEncryptionConfigurationNotFoundError",
		},
		{
			Name:                       "not-encrypted",
			DefaultEncryptionEvaluated: true,
		},
		{
			Name:                 "unknown",
			DefaultEncryptionErr: errors.New("getting default encryption: AccessDenied"),
		},
	}

	metrics := &S3Metrics{}
	summarizeS3Buckets(metrics, buckets)

	if metrics.BucketCount != 4 {
		t.Errorf("BucketCount = %d, want 4", metrics.BucketCount)
	}
	// The percentage is over every bucket, and the one bucket that could not
	// be read leaves it out of the artifact with a partial gap.
	if !pctIs(metrics.DefaultEncryptionEnabled, 50) {
		t.Errorf("DefaultEncryptionEnabled = %s, want 50", showPct(metrics.DefaultEncryptionEnabled))
	}
	if !hasUnread(metrics.missing, "default_encryption_enabled", 1) {
		t.Errorf("default_encryption_enabled is not marked unread for 1 bucket: %+v", metrics.missing)
	}
	if metrics.DefaultEncryptionEvaluatedCount != 3 {
		t.Errorf("DefaultEncryptionEvaluatedCount = %d, want 3", metrics.DefaultEncryptionEvaluatedCount)
	}
	if metrics.DefaultEncryptionInferredCount != 1 {
		t.Errorf("DefaultEncryptionInferredCount = %d, want 1", metrics.DefaultEncryptionInferredCount)
	}
	if metrics.DefaultEncryptionUnknownCount != 1 {
		t.Errorf("DefaultEncryptionUnknownCount = %d, want 1", metrics.DefaultEncryptionUnknownCount)
	}
}

func TestSummarizeS3Buckets_NoBuckets(t *testing.T) {
	metrics := &S3Metrics{}
	summarizeS3Buckets(metrics, nil)

	if metrics.BucketCount != 0 {
		t.Errorf("BucketCount = %d, want 0", metrics.BucketCount)
	}
	// No buckets is no population: every percentage is null, not 100.
	for name, got := range map[string]*int{
		"PublicAccessBlocked":      metrics.PublicAccessBlocked,
		"DefaultEncryptionEnabled": metrics.DefaultEncryptionEnabled,
		"VersioningEnabled":        metrics.VersioningEnabled,
		"LoggingEnabled":           metrics.LoggingEnabled,
	} {
		if got != nil {
			t.Errorf("%s = %s, want null", name, showPct(got))
		}
	}
}

func TestApplyEffectivePublicAccessBlock_UsesAccountAndBucketSettings(t *testing.T) {
	accountPublicAccessBlock := aws.PublicAccessBlockSettings{
		BlockPublicACLs:  true,
		IgnorePublicACLs: true,
		Evaluated:        true,
	}
	buckets := []aws.Bucket{
		{
			Name: "combined",
			PublicAccessBlock: aws.PublicAccessBlockSettings{
				BlockPublicPolicy:     true,
				RestrictPublicBuckets: true,
				Evaluated:             true,
			},
		},
		{
			Name: "bucket-only",
			PublicAccessBlock: aws.PublicAccessBlockSettings{
				BlockPublicACLs:       true,
				IgnorePublicACLs:      true,
				BlockPublicPolicy:     true,
				RestrictPublicBuckets: true,
				Evaluated:             true,
			},
		},
		{
			Name: "not-covered",
			PublicAccessBlock: aws.PublicAccessBlockSettings{
				BlockPublicPolicy: true,
				Evaluated:         true,
			},
		},
	}

	metrics := &S3Metrics{}
	unknown := applyEffectivePublicAccessBlock(buckets, accountPublicAccessBlock)
	summarizeS3Buckets(metrics, buckets)

	if !pctIs(metrics.PublicAccessBlocked, 66) {
		t.Errorf("PublicAccessBlocked = %s, want 66", showPct(metrics.PublicAccessBlocked))
	}
	if unknown != 0 {
		t.Errorf("unknown public access block count = %d, want 0", unknown)
	}
	if !buckets[0].EffectivePublicAccessBlocked || !buckets[1].EffectivePublicAccessBlocked {
		t.Errorf("combined and bucket-only buckets should be effectively blocked: %+v", buckets)
	}
	if buckets[2].EffectivePublicAccessBlocked {
		t.Errorf("not-covered bucket should not be effectively blocked: %+v", buckets[2])
	}
}

func TestApplyEffectivePublicAccessBlock_AccountSettingsCoverUnreadableBuckets(t *testing.T) {
	accountPublicAccessBlock := aws.PublicAccessBlockSettings{
		BlockPublicACLs:       true,
		IgnorePublicACLs:      true,
		BlockPublicPolicy:     true,
		RestrictPublicBuckets: true,
		Evaluated:             true,
	}
	buckets := []aws.Bucket{
		{
			Name: "bucket-without-readable-pab",
			PublicAccessBlock: aws.PublicAccessBlockSettings{
				ErrorCode: "AccessDenied",
				Err:       errors.New("getting bucket public access block: AccessDenied"),
			},
		},
	}

	metrics := &S3Metrics{accountPAB: accountPublicAccessBlock}
	unknown := applyEffectivePublicAccessBlock(buckets, accountPublicAccessBlock)
	summarizeS3Buckets(metrics, buckets)

	if !pctIs(metrics.PublicAccessBlocked, 100) {
		t.Errorf("PublicAccessBlocked = %s, want 100", showPct(metrics.PublicAccessBlocked))
	}
	if unknown != 0 {
		t.Errorf("unknown public access block count = %d, want 0", unknown)
	}
	if !buckets[0].EffectivePublicAccessBlocked {
		t.Errorf("bucket should be effectively blocked by account-level settings: %+v", buckets[0])
	}
	if len(metrics.missing.fields) != 0 {
		t.Errorf("the account block decides the value, so nothing is left out: %+v", metrics.missing)
	}
	rows := s3BucketsToInventory(buckets, accountPublicAccessBlock)
	if !rows[0].PublicAccessBlocked || len(rows[0].missing.fields) != 0 {
		t.Errorf("the bucket row should read as blocked with nothing left out: %+v", rows[0])
	}
}

func TestApplyEffectivePublicAccessBlock_UnreadableBucketIsUnknownUnderPartialAccountBlock(t *testing.T) {
	accountPublicAccessBlock := aws.PublicAccessBlockSettings{
		BlockPublicACLs:  true,
		IgnorePublicACLs: true,
		Evaluated:        true,
	}
	buckets := []aws.Bucket{
		{
			Name: "bucket-without-readable-pab",
			PublicAccessBlock: aws.PublicAccessBlockSettings{
				ErrorCode: "AccessDenied",
				Err:       errors.New("getting bucket public access block: AccessDenied"),
			},
		},
	}

	metrics := &S3Metrics{accountPAB: accountPublicAccessBlock}
	unknown := applyEffectivePublicAccessBlock(buckets, accountPublicAccessBlock)
	summarizeS3Buckets(metrics, buckets)

	if !hasUnread(metrics.missing, "public_access_blocked", 1) {
		t.Errorf("public_access_blocked is not marked unread for the bucket: %+v", metrics.missing)
	}
	if unknown != 1 {
		t.Errorf("unknown public access block count = %d, want 1", unknown)
	}
	if buckets[0].EffectivePublicAccessBlocked {
		t.Errorf("the bucket's own block could set the flags the account leaves off, so it is unknown: %+v", buckets[0])
	}
	rows := s3BucketsToInventory(buckets, accountPublicAccessBlock)
	if !hasUnread(rows[0].missing, "public_access_blocked", 0) {
		t.Errorf("the bucket row's public_access_blocked is not marked unread: %+v", rows[0].missing)
	}
}

func TestApplyEffectivePublicAccessBlock_UnknownWhenNeededSettingUnreadable(t *testing.T) {
	accountErr := errors.New("getting account public access block: AccessDenied")
	accountPublicAccessBlock := aws.PublicAccessBlockSettings{ErrorCode: "AccessDenied", Err: accountErr}
	buckets := []aws.Bucket{
		{
			Name: "partial-bucket-config",
			PublicAccessBlock: aws.PublicAccessBlockSettings{
				BlockPublicACLs: true,
				Evaluated:       true,
			},
		},
	}

	metrics := &S3Metrics{accountPAB: accountPublicAccessBlock, accountPABErr: accountErr}
	unknown := applyEffectivePublicAccessBlock(buckets, accountPublicAccessBlock)
	summarizeS3Buckets(metrics, buckets)

	if !hasUnread(metrics.missing, "public_access_blocked", 1) {
		t.Errorf("public_access_blocked is not marked unread for the bucket: %+v", metrics.missing)
	}
	if unknown != 1 {
		t.Errorf("unknown public access block count = %d, want 1", unknown)
	}
	if buckets[0].EffectivePublicAccessBlocked {
		t.Errorf("bucket should not be treated as blocked when needed flags are unknown: %+v", buckets[0])
	}
}

// fakeS3Enricher is a focused mock for the s3BucketEnricher interface.
type fakeS3Enricher struct {
	acls       map[string]*aws.BucketACL
	lifecycles map[string]*aws.BucketLifecycle
	errs       map[string]error // keyed by "bucket:op" (e.g., "alpha:acl")
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

	c := newTestCollector(Config{})
	c.enrichS3BucketsForInternal(context.Background(), enricher, "111111111111", buckets, map[string]aws.Bucket{
		"alpha": {Name: "alpha", Policy: &aws.BucketPolicy{Document: `{"Version":"2012-10-17","Statement":[]}`}},
	})

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
		// no lifecycles
	}

	c := newTestCollector(Config{})
	c.enrichS3BucketsForInternal(context.Background(), enricher, "111111111111", buckets, map[string]aws.Bucket{
		"no-extras": {Name: "no-extras"},
	})

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
	denied := errors.New("AccessDenied: caller has no s3:GetBucketPolicy permission on this bucket")

	c := newTestCollector(Config{})
	c.enrichS3BucketsForInternal(context.Background(), fakeS3Enricher{}, "111111111111", buckets, map[string]aws.Bucket{
		"denied-bucket": {Name: "denied-bucket", PolicyErr: denied},
	})

	if buckets[0].Policy != nil {
		t.Errorf("expected nil Policy on AccessDenied, got %+v", buckets[0].Policy)
	}
	if !hasUnread(buckets[0].missing, "policy", 0) {
		t.Errorf("the policy is not marked unread: %+v", buckets[0].missing)
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

	c := newTestCollector(Config{})
	c.enrichS3BucketsForInternal(context.Background(), enricher, "111111111111", buckets, map[string]aws.Bucket{
		"transient": {Name: "transient"},
	})

	if len(c.warnings) != 1 {
		t.Fatalf("expected 1 warning for transient error, got %d: %v", len(c.warnings), c.warnings)
	}
	if !hasUnread(buckets[0].missing, "acl", 0) {
		t.Errorf("the ACL is not marked unread: %+v", buckets[0].missing)
	}
	if strings.Contains(c.warnings[0], "access denied") {
		t.Errorf("non-AccessDenied error should not produce access-denied warning text: %q", c.warnings[0])
	}
}

func TestSummarizeS3Buckets_LogSinkExcludedFromLoggingDenominator(t *testing.T) {
	buckets := []aws.Bucket{
		{Name: "app-bucket", LoggingEnabled: true, LoggingTargetBucket: "log-bucket"},
		{Name: "data-bucket", LoggingEnabled: false},
		{Name: "log-bucket", LoggingEnabled: false},
	}

	metrics := &S3Metrics{}
	summarizeS3Buckets(metrics, buckets)

	if metrics.BucketCount != 3 {
		t.Errorf("BucketCount = %d, want 3", metrics.BucketCount)
	}
	if metrics.LogSinkBucketCount != 1 {
		t.Errorf("LogSinkBucketCount = %d, want 1", metrics.LogSinkBucketCount)
	}
	// Only app-bucket and data-bucket require logging (2 buckets).
	// app-bucket has logging → 1/2 = 50%.
	if !pctIs(metrics.LoggingEnabled, 50) || metrics.LoggingRequiredBucketCount != 2 {
		t.Errorf("LoggingEnabled = %s over %d buckets, want 50 over 2 (log sink excluded from denominator)", showPct(metrics.LoggingEnabled), metrics.LoggingRequiredBucketCount)
	}
}

func TestSummarizeS3Buckets_AllBucketsAreLogSinks(t *testing.T) {
	buckets := []aws.Bucket{
		{Name: "sink-a", LoggingEnabled: false},
		{Name: "sink-b", LoggingEnabled: true, LoggingTargetBucket: "sink-a"},
	}
	// sink-a is a log sink (target of sink-b's logging)
	// sink-b is the only non-sink, and it has logging enabled → 100%.

	metrics := &S3Metrics{}
	summarizeS3Buckets(metrics, buckets)

	if metrics.LogSinkBucketCount != 1 {
		t.Errorf("LogSinkBucketCount = %d, want 1", metrics.LogSinkBucketCount)
	}
	if !pctIs(metrics.LoggingEnabled, 100) {
		t.Errorf("LoggingEnabled = %s, want 100", showPct(metrics.LoggingEnabled))
	}
}

func TestSummarizeS3Buckets_OnlyLogSinkBucketsHasNoLoggingPopulation(t *testing.T) {
	// Every bucket is a log sink for some other bucket, so no bucket requires
	// logging and the percentage has no population.
	buckets := []aws.Bucket{
		{Name: "a", LoggingEnabled: true, LoggingTargetBucket: "b"},
		{Name: "b", LoggingEnabled: true, LoggingTargetBucket: "a"},
	}

	metrics := &S3Metrics{}
	summarizeS3Buckets(metrics, buckets)

	if metrics.LogSinkBucketCount != 2 {
		t.Errorf("LogSinkBucketCount = %d, want 2", metrics.LogSinkBucketCount)
	}
	if metrics.LoggingEnabled != nil || metrics.LoggingRequiredBucketCount != 0 {
		t.Errorf("LoggingEnabled = %s over %d buckets, want null over none", showPct(metrics.LoggingEnabled), metrics.LoggingRequiredBucketCount)
	}
}

func TestS3BucketsToInventory_SetsIsLogSink(t *testing.T) {
	in := []aws.Bucket{
		{Name: "app", LoggingEnabled: true, LoggingTargetBucket: "logs"},
		{Name: "logs", LoggingEnabled: false},
	}

	out := s3BucketsToInventory(in, aws.PublicAccessBlockSettings{})
	if len(out) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(out))
	}
	if out[0].IsLogSink {
		t.Errorf("app bucket should not be a log sink")
	}
	if !out[1].IsLogSink {
		t.Errorf("logs bucket should be a log sink")
	}
	if !out[0].LoggingEnabled {
		t.Errorf("app bucket logging_enabled should be true")
	}
	if out[1].LoggingEnabled {
		t.Errorf("logs bucket logging_enabled should stay false (truthful)")
	}
}

// fakeS3Client is a focused mock for the s3Client interface.
type fakeS3Client struct {
	fakeS3Enricher
	pab     aws.PublicAccessBlockSettings
	pabErr  error
	buckets []aws.Bucket
	listErr error
}

func (f fakeS3Client) GetAccountPublicAccessBlock(_ context.Context, _ string) (aws.PublicAccessBlockSettings, error) {
	return f.pab, f.pabErr
}

func (f fakeS3Client) ListBuckets(_ context.Context) ([]aws.Bucket, error) {
	return f.buckets, f.listErr
}

func TestCollectS3Metrics_ListBucketsFailureSetsSentinels(t *testing.T) {
	c := newTestCollector(Config{})
	client := fakeS3Client{listErr: errors.New("Throttling: rate exceeded")}

	metrics := c.collectS3Metrics(context.Background(), client, "111111111111", accountAt(0), componentsdk.LevelTrust)

	if metrics.BucketListingEvaluated {
		t.Error("expected BucketListingEvaluated false on listing failure")
	}
	if metrics.BucketListingErrorCode == "" {
		t.Error("expected BucketListingErrorCode set on listing failure")
	}
	if metrics.PublicAccessBlocked != nil || metrics.DefaultEncryptionEnabled != nil {
		t.Errorf("expected unset aggregates on listing failure, got %+v", metrics)
	}
	requireGap(t, c, "/accounts/0/s3/bucket_count", "/accounts/0/s3/public_access_blocked", "/accounts/0/s3/default_encryption_enabled",
		"/accounts/0/s3/versioning_enabled", "/accounts/0/s3/logging_enabled")
	if len(c.warnings) != 1 || !strings.Contains(c.warnings[0], "failed to collect S3 metrics") {
		t.Errorf("expected S3 failure warning, got %v", c.warnings)
	}
}

func TestCollectS3Metrics_SuccessSetsEvaluated(t *testing.T) {
	c := newTestCollector(Config{})
	client := fakeS3Client{
		pab: aws.PublicAccessBlockSettings{
			Evaluated:             true,
			BlockPublicACLs:       true,
			IgnorePublicACLs:      true,
			BlockPublicPolicy:     true,
			RestrictPublicBuckets: true,
		},
	}

	metrics := c.collectS3Metrics(context.Background(), client, "111111111111", accountAt(0), componentsdk.LevelTrust)

	if !metrics.BucketListingEvaluated {
		t.Error("expected BucketListingEvaluated true on success")
	}
	if !metrics.AccountPublicAccessBlockEvaluated {
		t.Error("expected AccountPublicAccessBlockEvaluated true on success")
	}
	if metrics.BucketListingErrorCode != "" {
		t.Errorf("expected empty BucketListingErrorCode, got %q", metrics.BucketListingErrorCode)
	}
	if metrics.PublicAccessBlocked != nil {
		t.Errorf("expected null with zero buckets, got %s", showPct(metrics.PublicAccessBlocked))
	}
	requireNoGaps(t, c)
}

func TestCollectS3Metrics_AccountPABFailureLeavesEvaluatedFalse(t *testing.T) {
	c := newTestCollector(Config{})
	client := fakeS3Client{pabErr: errors.New("AccessDenied")}

	metrics := c.collectS3Metrics(context.Background(), client, "111111111111", accountAt(0), componentsdk.LevelTrust)

	if metrics.AccountPublicAccessBlockEvaluated {
		t.Error("expected AccountPublicAccessBlockEvaluated false on PAB failure")
	}
	if !metrics.BucketListingEvaluated {
		t.Error("expected BucketListingEvaluated true when only PAB failed")
	}
	requireGap(t, c, "/accounts/0/s3/account_public_access_block_enabled")
}
