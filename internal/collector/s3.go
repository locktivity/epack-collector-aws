package collector

import (
	"context"
	"fmt"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// s3Client is the slice of the AWS client used by collectS3Metrics, extracted
// so the failure paths can be tested without AWS.
type s3Client interface {
	GetAccountPublicAccessBlock(ctx context.Context, accountID string) (aws.PublicAccessBlockSettings, error)
	ListBuckets(ctx context.Context) ([]aws.Bucket, error)
	s3BucketEnricher
}

// collectS3Metrics collects S3 security metrics.
//
// At trust, only aggregate percentages and the account-level PAB flag are
// populated. At audit, per-bucket rows are also surfaced from the same
// ListBuckets iteration (no extra API calls).
//
// Failures never abort the surface: the evaluated flags on S3Metrics record
// which sources succeeded so a consumer never mistakes an uncollected
// aggregate for a genuine zero.
func (c *Collector) collectS3Metrics(ctx context.Context, client s3Client, accountID string, at at, level componentsdk.Level) *S3Metrics {
	metrics := &S3Metrics{}
	s3At := at.sub("s3")
	audit := level.AtLeast(componentsdk.LevelAudit)

	// Get account-level public access block
	accountPublicAccessBlock, err := client.GetAccountPublicAccessBlock(ctx, accountID)
	metrics.accountPAB, metrics.accountPABErr = accountPublicAccessBlock, err
	if err != nil {
		c.warn("account %s: failed to collect account-level S3 public access block: %v", accountID, err)
		c.gaps.leaveOut(err, s3At.p("account_public_access_block_enabled"))
	} else {
		metrics.AccountPublicAccessBlockEnabled = accountPublicAccessBlock.BlocksPublicAccess()
		metrics.AccountPublicAccessBlockEvaluated = true
	}

	// List buckets and get their settings
	buckets, err := client.ListBuckets(ctx)
	if err != nil {
		metrics.BucketListingErrorCode = apiErrorCode(err)
		c.warn("account %s: failed to collect S3 metrics: %v", accountID, err)
		c.gaps.leaveOut(err, s3At.p("bucket_count"), s3At.p("tls_enforced_bucket_count"), s3At.p("tls_enforcement_partial_bucket_count"),
			s3At.p("tls_unenforced_bucket_count"), s3At.p("public_access_blocked"), s3At.p("public_access_blocked_bucket_count"),
			s3At.p("default_encryption_enabled"), s3At.p("default_encryption_enabled_bucket_count"), s3At.p("versioning_enabled"),
			s3At.p("versioning_enabled_bucket_count"), s3At.p("logging_enabled"), s3At.p("logging_enabled_bucket_count"),
			s3At.p("log_sink_bucket_count"), s3At.p("logging_required_bucket_count"))
		if audit {
			c.gaps.leaveOut(err, s3At.p("buckets"))
		}
		return metrics
	}
	metrics.BucketListingEvaluated = true
	metrics.bucketNames = make(map[string]bool, len(buckets))
	for _, b := range buckets {
		metrics.bucketNames[b.Name] = true
	}

	transport := classifyBucketTransport(buckets)
	for _, b := range buckets {
		switch transport[b.Name] {
		case tlsEnforcementEnforced:
			metrics.TLSEnforcedBucketCount++
		case tlsEnforcementPartial:
			metrics.TLSEnforcementPartialBucketCount++
		case tlsEnforcementNone:
			metrics.TLSUnenforcedBucketCount++
		case tlsEnforcementUnknown:
			metrics.TLSEnforcementUnknownBucketCount++
			metrics.missing.addPartial(policyReadError(b), 1, "tls_enforced_bucket_count", "tls_enforcement_partial_bucket_count", "tls_unenforced_bucket_count")
		}
	}
	if metrics.TLSEnforcementUnknownBucketCount > 0 {
		c.warn(
			"account %s: failed to read the bucket policy for %d bucket(s); their TLS enforcement is unknown, not unenforced",
			accountID,
			metrics.TLSEnforcementUnknownBucketCount,
		)
	}

	publicAccessUnknownCount := applyEffectivePublicAccessBlock(buckets, accountPublicAccessBlock)
	metrics.PublicAccessBlockUnknownCount = publicAccessUnknownCount
	summarizeS3Buckets(metrics, buckets)
	if publicAccessUnknownCount > 0 {
		c.warn(
			"account %s: failed to fully evaluate S3 public access block for %d bucket(s); check s3:GetAccountPublicAccessBlock, s3:GetBucketPublicAccessBlock, and per-bucket access",
			accountID,
			publicAccessUnknownCount,
		)
	}
	if metrics.DefaultEncryptionUnknownCount > 0 {
		c.warn(
			"account %s: failed to evaluate S3 default encryption for %d bucket(s); check s3:GetEncryptionConfiguration and per-bucket access",
			accountID,
			metrics.DefaultEncryptionUnknownCount,
		)
	}
	c.recordUnread(s3At, metrics.missing)

	if audit {
		inventory := s3BucketsToInventory(buckets, accountPublicAccessBlock)
		// 10,000-bucket cap. Sort by name for stable truncation.
		kept, dropped, truncated := Truncate(inventory, S3BucketsCap, func(a, b S3Bucket) bool {
			return a.Name < b.Name
		})
		metrics.Buckets = kept
		byName := make(map[string]aws.Bucket, len(buckets))
		for _, b := range buckets {
			byName[b.Name] = b
		}
		for i := range metrics.Buckets {
			metrics.Buckets[i].TLSEnforcement = transport[metrics.Buckets[i].Name]
		}
		if truncated {
			c.warn("account %s: S3 bucket inventory truncated to %d (dropped %d)", accountID, S3BucketsCap, dropped)
		}

		if level.AtLeast(componentsdk.LevelInternal) {
			c.enrichS3BucketsForInternal(ctx, client, accountID, metrics.Buckets, byName)
		}
		recordRowsUnread(c, s3At.sub("buckets"), metrics.Buckets, func(r *S3Bucket) unread { return r.missing })
	}

	return metrics
}

func applyEffectivePublicAccessBlock(buckets []aws.Bucket, accountPublicAccessBlock aws.PublicAccessBlockSettings) int {
	var publicAccessUnknown int

	for i := range buckets {
		publicAccess := effectivePublicAccessBlock(accountPublicAccessBlock, buckets[i].PublicAccessBlock)
		buckets[i].EffectivePublicAccessBlocked = publicAccess.blocked
		if publicAccess.unknown {
			publicAccessUnknown++
		}
	}

	return publicAccessUnknown
}

// logSinkBuckets returns the set of bucket names that serve as server access
// log destinations for at least one other bucket. These buckets don't need
// their own logging enabled and should be excluded from the LoggingEnabled
// denominator.
func logSinkBuckets(buckets []aws.Bucket) map[string]struct{} {
	sinks := map[string]struct{}{}
	for _, b := range buckets {
		if b.LoggingTargetBucket != "" {
			sinks[b.LoggingTargetBucket] = struct{}{}
		}
	}
	return sinks
}

// firstLoggingError returns how many bucket logging reads failed and the
// first failure. While any did, a bucket it may name as its log destination
// is not known to be a sink.
func firstLoggingError(buckets []aws.Bucket) (int, error) {
	var first error
	failed := 0
	for _, b := range buckets {
		if b.LoggingErr != nil {
			failed++
			if first == nil {
				first = b.LoggingErr
			}
		}
	}
	return failed, first
}

// summarizeS3Buckets computes the bucket rollups. A rollup over buckets whose
// settings were read in part is left out, and each percentage is nil when it
// covers no buckets.
func summarizeS3Buckets(metrics *S3Metrics, buckets []aws.Bucket) {
	var publicBlocked, encrypted, encryptionEvaluated, encryptionInferred, encryptionUnknown, versioned, logging int

	sinks := logSinkBuckets(buckets)
	loggingFailed, loggingErr := firstLoggingError(buckets)
	var logSinkCount int
	bucketsRequiringLogging := 0

	for _, b := range buckets {
		if b.EffectivePublicAccessBlocked {
			publicBlocked++
		} else if why := publicAccessReadError(b, metrics.accountPAB, metrics.accountPABErr); why != nil {
			metrics.missing.addPartial(why, 1, "public_access_blocked", "public_access_blocked_bucket_count")
		}
		if bucketDefaultEncryptionEvaluated(b) {
			encryptionEvaluated++
			if b.DefaultEncryptionEnabled {
				encrypted++
			}
			if bucketDefaultEncryptionInferred(b) {
				encryptionInferred++
			}
		} else {
			encryptionUnknown++
			metrics.missing.addPartial(b.DefaultEncryptionErr, 1, "default_encryption_enabled", "default_encryption_enabled_bucket_count")
		}
		if b.VersioningErr != nil {
			metrics.missing.addPartial(b.VersioningErr, 1, "versioning_enabled", "versioning_enabled_bucket_count")
		} else if b.VersioningEnabled {
			versioned++
		}

		_, isSink := sinks[b.Name]
		if isSink {
			logSinkCount++
		} else {
			bucketsRequiringLogging++
			switch {
			case b.LoggingErr != nil:
				metrics.missing.addPartial(b.LoggingErr, 1, "logging_enabled", "logging_enabled_bucket_count")
			case b.LoggingEnabled:
				logging++
			}
		}
	}
	if loggingErr != nil {
		metrics.missing.addPartial(loggingErr, loggingFailed, "log_sink_bucket_count", "logging_required_bucket_count", "logging_enabled", "logging_enabled_bucket_count")
	}

	metrics.BucketCount = len(buckets)
	metrics.LogSinkBucketCount = logSinkCount
	metrics.LoggingRequiredBucketCount = bucketsRequiringLogging
	metrics.DefaultEncryptionEvaluatedCount = encryptionEvaluated
	metrics.DefaultEncryptionInferredCount = encryptionInferred
	metrics.DefaultEncryptionUnknownCount = encryptionUnknown

	metrics.PublicAccessBlocked = pctOf(publicBlocked, len(buckets))
	metrics.PublicAccessBlockedBucketCount = publicBlocked
	metrics.DefaultEncryptionEnabled = pctOf(encrypted, len(buckets))
	metrics.DefaultEncryptionEnabledBucketCount = encrypted
	metrics.VersioningEnabled = pctOf(versioned, len(buckets))
	metrics.VersioningEnabledBucketCount = versioned
	metrics.LoggingEnabled = pctOf(logging, bucketsRequiringLogging)
	metrics.LoggingEnabledBucketCount = logging
}

// publicAccessReadError is why a bucket's effective public access block is
// unknown, or nil when it is known.
func publicAccessReadError(b aws.Bucket, account aws.PublicAccessBlockSettings, accountErr error) error {
	status := effectivePublicAccessBlock(account, b.PublicAccessBlock)
	if !status.unknown {
		return nil
	}
	if b.PublicAccessBlock.Err != nil {
		return b.PublicAccessBlock.Err
	}
	return accountErr
}

// policyReadError is why a bucket's policy could not be read.
func policyReadError(b aws.Bucket) error {
	return b.PolicyErr
}

type effectivePublicAccessBlockStatus struct {
	blocked bool
	unknown bool
}

// effectivePublicAccessBlock resolves a bucket's block the way S3 enforces
// it: each flag is on when the account or the bucket sets it. An account
// block that sets every flag decides the bucket even when the bucket's own
// block could not be read. Not blocked needs both sides read, because an
// unreadable side could set the missing flags; only S3's documented 404
// says a side has no block.
func effectivePublicAccessBlock(account, bucket aws.PublicAccessBlockSettings) effectivePublicAccessBlockStatus {
	blocked := (account.BlockPublicACLs || bucket.BlockPublicACLs) &&
		(account.IgnorePublicACLs || bucket.IgnorePublicACLs) &&
		(account.BlockPublicPolicy || bucket.BlockPublicPolicy) &&
		(account.RestrictPublicBuckets || bucket.RestrictPublicBuckets)
	if blocked {
		return effectivePublicAccessBlockStatus{blocked: true}
	}
	return effectivePublicAccessBlockStatus{unknown: !account.Evaluated || !bucket.Evaluated}
}

func bucketDefaultEncryptionEvaluated(b aws.Bucket) bool {
	return b.DefaultEncryptionEvaluated
}

func bucketDefaultEncryptionInferred(b aws.Bucket) bool {
	return b.DefaultEncryptionEvaluated &&
		b.DefaultEncryptionEnabled &&
		b.DefaultEncryptionErrorCode == "ServerSideEncryptionConfigurationNotFoundError"
}

func bucketDefaultEncryptionEnabled(b aws.Bucket) *bool {
	if !bucketDefaultEncryptionEvaluated(b) {
		return nil
	}
	enabled := b.DefaultEncryptionEnabled
	return &enabled
}

// s3BucketsToInventory projects the bucket list onto audit-level per-bucket
// rows. The same iteration produced the trust-level aggregates; this just
// surfaces the rows. A setting that could not be read is left out of its row.
func s3BucketsToInventory(buckets []aws.Bucket, account aws.PublicAccessBlockSettings) []S3Bucket {
	sinks := logSinkBuckets(buckets)
	_, loggingErr := firstLoggingError(buckets)
	out := make([]S3Bucket, 0, len(buckets))
	for _, b := range buckets {
		_, isSink := sinks[b.Name]
		row := S3Bucket{
			Name:                       b.Name,
			Region:                     b.Region,
			PublicAccessBlocked:        b.EffectivePublicAccessBlocked,
			DefaultEncryptionEnabled:   bucketDefaultEncryptionEnabled(b),
			DefaultEncryptionEvaluated: bucketDefaultEncryptionEvaluated(b),
			DefaultEncryptionErrorCode: b.DefaultEncryptionErrorCode,
			VersioningEnabled:          b.VersioningEnabled,
			LoggingEnabled:             b.LoggingEnabled,
			IsLogSink:                  isSink,
		}
		row.missing.add(b.RegionErr, "region")
		if !b.EffectivePublicAccessBlocked {
			row.missing.add(publicAccessReadError(b, account, account.Err), "public_access_blocked")
		}
		row.missing.add(b.DefaultEncryptionErr, "default_encryption_enabled")
		row.missing.add(b.VersioningErr, "versioning_enabled")
		row.missing.add(b.LoggingErr, "logging_enabled")
		row.missing.add(b.PolicyErr, "tls_enforcement")
		if !isSink {
			row.missing.add(loggingErr, "is_log_sink")
		}
		out = append(out, row)
	}
	return out
}

// s3BucketEnricher is the focused interface enrichS3BucketsForInternal needs.
// *aws.AWSClient satisfies it; tests substitute a fake.
type s3BucketEnricher interface {
	GetBucketACL(ctx context.Context, region, bucket string) (*aws.BucketACL, error)
	GetBucketLifecycle(ctx context.Context, region, bucket string) (*aws.BucketLifecycle, error)
}

// enrichS3BucketsForInternal populates Policy / ACL / Lifecycle on each bucket
// in place. The policy is the one the bucket listing read. A field that could
// not be read is left out of its row with a warning, without affecting the
// rest of the inventory.
func (c *Collector) enrichS3BucketsForInternal(ctx context.Context, client s3BucketEnricher, accountID string, buckets []S3Bucket, byName map[string]aws.Bucket) {
	for i := range buckets {
		b := &buckets[i]
		region := bucketRegion(b)
		source := byName[b.Name]
		switch {
		case source.PolicyErr != nil:
			c.warnBucketError(accountID, b.Name, "policy", "s3:GetBucketPolicy", source.PolicyErr)
			b.missing.add(source.PolicyErr, "policy")
		case source.Policy != nil:
			b.Policy = &S3BucketPolicy{Document: source.Policy.Document}
		}
		c.fetchBucketACL(ctx, client, accountID, region, b)
		c.fetchBucketLifecycle(ctx, client, accountID, region, b)
	}
}

// bucketRegion returns the bucket's region, defaulting to us-east-1 if unset.
// Buckets created via the legacy S3 API report an empty location constraint,
// which AWS treats as us-east-1 — we mirror that.
func bucketRegion(b *S3Bucket) string {
	if b.Region != "" {
		return b.Region
	}
	return "us-east-1"
}

func (c *Collector) fetchBucketACL(ctx context.Context, client s3BucketEnricher, accountID, region string, b *S3Bucket) {
	acl, err := client.GetBucketACL(ctx, region, b.Name)
	if err != nil {
		c.warnBucketError(accountID, b.Name, "acl", "s3:GetBucketAcl", err)
		b.missing.add(err, "acl")
		return
	}
	if acl == nil {
		return
	}
	b.ACL = &S3BucketACL{
		OwnerID:        acl.OwnerID,
		HasPublicGrant: acl.HasPublicGrant,
		Grants:         convertACLGrants(acl.Grants),
	}
}

func (c *Collector) fetchBucketLifecycle(ctx context.Context, client s3BucketEnricher, accountID, region string, b *S3Bucket) {
	lc, err := client.GetBucketLifecycle(ctx, region, b.Name)
	if err != nil {
		c.warnBucketError(accountID, b.Name, "lifecycle", "s3:GetLifecycleConfiguration", err)
		b.missing.add(err, "lifecycle")
		return
	}
	if lc == nil {
		return
	}
	b.Lifecycle = &S3BucketLifecycle{Rules: convertLifecycleRules(lc.Rules)}
}

// warnBucketError routes per-bucket fetch errors to the structured
// access-denied diagnostic if applicable, or a generic warning otherwise.
func (c *Collector) warnBucketError(accountID, bucketName, fieldName, permission string, err error) {
	if isAccessDeniedErr(err) {
		c.warnAccessDenied(accountID, fmt.Sprintf("s3_bucket_%s:%s", fieldName, bucketName), permission)
		return
	}
	c.warn("account %s: bucket %s: failed to get %s: %v", accountID, bucketName, fieldName, err)
}

func convertACLGrants(in []aws.BucketACLGrant) []S3BucketACLGrant {
	if len(in) == 0 {
		return nil
	}
	out := make([]S3BucketACLGrant, 0, len(in))
	for _, g := range in {
		out = append(out, S3BucketACLGrant{
			GranteeType: g.GranteeType,
			GranteeURI:  g.GranteeURI,
			GranteeID:   g.GranteeID,
			Permission:  g.Permission,
		})
	}
	return out
}

func convertLifecycleRules(in []aws.BucketLifecycleRule) []S3LifecycleRule {
	if len(in) == 0 {
		return nil
	}
	out := make([]S3LifecycleRule, 0, len(in))
	for _, r := range in {
		out = append(out, S3LifecycleRule{
			ID:          r.ID,
			Status:      r.Status,
			Prefix:      r.Prefix,
			Transitions: r.Transitions,
			Expiration:  r.Expiration,
		})
	}
	return out
}
