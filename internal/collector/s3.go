package collector

import (
	"context"
	"fmt"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// collectS3Metrics collects S3 security metrics.
//
// At trust, only aggregate percentages and the account-level PAB flag are
// populated. At audit, per-bucket rows are also surfaced from the same
// ListBuckets iteration (no extra API calls).
func (c *Collector) collectS3Metrics(ctx context.Context, client *aws.AWSClient, accountID string, level componentsdk.Level) (*S3Metrics, error) {
	metrics := &S3Metrics{}

	// Get account-level public access block
	accountPublicAccessBlock, err := client.GetAccountPublicAccessBlock(ctx, accountID)
	if err != nil {
		c.warn("account %s: failed to collect account-level S3 public access block: %v", accountID, err)
	} else {
		metrics.AccountPublicAccessBlockEnabled = accountPublicAccessBlock.BlocksPublicAccess()
	}

	// List buckets and get their settings
	buckets, err := client.ListBuckets(ctx)
	if err != nil {
		return metrics, fmt.Errorf("listing buckets: %w", err)
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

	if level.AtLeast(componentsdk.LevelAudit) {
		inventory := s3BucketsToInventory(buckets)
		// 10,000-bucket cap. Sort by name for stable truncation.
		kept, dropped, truncated := Truncate(inventory, S3BucketsCap, func(a, b S3Bucket) bool {
			return a.Name < b.Name
		})
		metrics.Buckets = kept
		if truncated {
			c.warn("account %s: S3 bucket inventory truncated to %d (dropped %d)", accountID, S3BucketsCap, dropped)
		}

		if level.AtLeast(componentsdk.LevelInternal) {
			c.enrichS3BucketsForInternal(ctx, client, accountID, metrics.Buckets)
		}
	}

	return metrics, nil
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

func summarizeS3Buckets(metrics *S3Metrics, buckets []aws.Bucket) {
	var publicBlocked, encrypted, encryptionEvaluated, encryptionInferred, encryptionUnknown, versioned, logging int

	sinks := logSinkBuckets(buckets)
	var logSinkCount int
	bucketsRequiringLogging := 0

	for _, b := range buckets {
		if b.EffectivePublicAccessBlocked {
			publicBlocked++
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
		}
		if b.VersioningEnabled {
			versioned++
		}

		_, isSink := sinks[b.Name]
		if isSink {
			logSinkCount++
		} else {
			bucketsRequiringLogging++
			if b.LoggingEnabled {
				logging++
			}
		}
	}

	metrics.BucketCount = len(buckets)
	metrics.LogSinkBucketCount = logSinkCount
	metrics.DefaultEncryptionEvaluatedCount = encryptionEvaluated
	metrics.DefaultEncryptionInferredCount = encryptionInferred
	metrics.DefaultEncryptionUnknownCount = encryptionUnknown

	if len(buckets) == 0 {
		metrics.PublicAccessBlocked = MaxPercentage
		metrics.DefaultEncryptionEnabled = MaxPercentage
		metrics.VersioningEnabled = MaxPercentage
		metrics.LoggingEnabled = MaxPercentage
		return
	}

	metrics.PublicAccessBlocked = percent(publicBlocked, len(buckets))
	metrics.DefaultEncryptionEnabled = percent(encrypted, encryptionEvaluated)
	metrics.VersioningEnabled = percent(versioned, len(buckets))
	if bucketsRequiringLogging == 0 {
		metrics.LoggingEnabled = MaxPercentage
	} else {
		metrics.LoggingEnabled = percent(logging, bucketsRequiringLogging)
	}
}

type effectivePublicAccessBlockStatus struct {
	blocked bool
	unknown bool
}

func effectivePublicAccessBlock(account, bucket aws.PublicAccessBlockSettings) effectivePublicAccessBlockStatus {
	blocked := (account.BlockPublicACLs || bucket.BlockPublicACLs) &&
		(account.IgnorePublicACLs || bucket.IgnorePublicACLs) &&
		(account.BlockPublicPolicy || bucket.BlockPublicPolicy) &&
		(account.RestrictPublicBuckets || bucket.RestrictPublicBuckets)
	if blocked {
		return effectivePublicAccessBlockStatus{blocked: true}
	}

	return effectivePublicAccessBlockStatus{
		unknown: publicAccessBlockFlagUnknown(account.Evaluated, account.BlockPublicACLs, bucket.Evaluated, bucket.BlockPublicACLs) ||
			publicAccessBlockFlagUnknown(account.Evaluated, account.IgnorePublicACLs, bucket.Evaluated, bucket.IgnorePublicACLs) ||
			publicAccessBlockFlagUnknown(account.Evaluated, account.BlockPublicPolicy, bucket.Evaluated, bucket.BlockPublicPolicy) ||
			publicAccessBlockFlagUnknown(account.Evaluated, account.RestrictPublicBuckets, bucket.Evaluated, bucket.RestrictPublicBuckets),
	}
}

func publicAccessBlockFlagUnknown(accountEvaluated, accountEnabled, bucketEvaluated, bucketEnabled bool) bool {
	if accountEnabled || bucketEnabled {
		return false
	}
	return !accountEvaluated || !bucketEvaluated
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
// surfaces the rows.
func s3BucketsToInventory(buckets []aws.Bucket) []S3Bucket {
	sinks := logSinkBuckets(buckets)
	out := make([]S3Bucket, 0, len(buckets))
	for _, b := range buckets {
		_, isSink := sinks[b.Name]
		out = append(out, S3Bucket{
			Name:                       b.Name,
			Region:                     b.Region,
			PublicAccessBlocked:        b.EffectivePublicAccessBlocked,
			DefaultEncryptionEnabled:   bucketDefaultEncryptionEnabled(b),
			DefaultEncryptionEvaluated: bucketDefaultEncryptionEvaluated(b),
			DefaultEncryptionErrorCode: b.DefaultEncryptionErrorCode,
			VersioningEnabled:          b.VersioningEnabled,
			LoggingEnabled:             b.LoggingEnabled,
			IsLogSink:                  isSink,
		})
	}
	return out
}

// s3BucketEnricher is the focused interface enrichS3BucketsForInternal needs.
// *aws.AWSClient satisfies it; tests substitute a fake.
type s3BucketEnricher interface {
	GetBucketPolicy(ctx context.Context, region, bucket string) (*aws.BucketPolicy, error)
	GetBucketACL(ctx context.Context, region, bucket string) (*aws.BucketACL, error)
	GetBucketLifecycle(ctx context.Context, region, bucket string) (*aws.BucketLifecycle, error)
}

// enrichS3BucketsForInternal populates Policy / ACL / Lifecycle on each bucket
// in place. Per-bucket per-field failures emit warnings and skip just that
// field without affecting the rest of the inventory.
func (c *Collector) enrichS3BucketsForInternal(ctx context.Context, client s3BucketEnricher, accountID string, buckets []S3Bucket) {
	for i := range buckets {
		b := &buckets[i]
		region := bucketRegion(b)
		c.fetchBucketPolicy(ctx, client, accountID, region, b)
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

func (c *Collector) fetchBucketPolicy(ctx context.Context, client s3BucketEnricher, accountID, region string, b *S3Bucket) {
	policy, err := client.GetBucketPolicy(ctx, region, b.Name)
	if err != nil {
		c.warnBucketError(accountID, b.Name, "policy", "s3:GetBucketPolicy", err)
		return
	}
	if policy == nil {
		return
	}
	b.Policy = &S3BucketPolicy{Document: policy.Document}
}

func (c *Collector) fetchBucketACL(ctx context.Context, client s3BucketEnricher, accountID, region string, b *S3Bucket) {
	acl, err := client.GetBucketACL(ctx, region, b.Name)
	if err != nil {
		c.warnBucketError(accountID, b.Name, "acl", "s3:GetBucketAcl", err)
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
