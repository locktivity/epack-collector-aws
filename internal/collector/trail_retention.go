package collector

import (
	"context"
	"strings"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

// Trail bucket retention classification: the S3 side of CloudTrail retention.
const (
	trailRetentionIndefinite   = "indefinite"
	trailRetentionExpiring     = "expiring"
	trailRetentionNotInAccount = "not_in_account"
	trailRetentionUnknown      = "unknown"
)

// Public access states for trail buckets share not_in_account and unknown
// vocabulary with retention, but the two dimensions resolve independently: a
// readable lifecycle does not imply a readable public access block.
const (
	trailBucketAccessBlocked    = "blocked"
	trailBucketAccessNotBlocked = "not_blocked"
)

type trailBucketVerdict struct {
	state          string
	expirationDays int32
	objectLockMode string
	publicAccess   string
}

// resolveTrailBucketRetention resolves, per trail delivery bucket, how long
// the audit log objects survive: the covering lifecycle expiration if any, and
// whether object lock pins retention against deletion.
//
// A bucket outside this account, the normal shape for organization trails
// delivering to a log archive account, classifies not_in_account rather than
// anything about its rules: enrolling that account is what makes it readable.
func (c *Collector) resolveTrailBucketRetention(ctx context.Context, client *aws.AWSClient, accountID string, trails []aws.Trail, status *CloudTrailStatus) {
	verdicts := map[string]trailBucketVerdict{}

	// The account-level block overrides every bucket, so it is read once. A
	// failed read leaves the account side unknown rather than open.
	var accountBlocks *bool
	if accountPAB, err := client.GetAccountPublicAccessBlock(ctx, accountID); err == nil {
		blocks := accountPAB.BlocksPublicAccess()
		accountBlocks = &blocks
	}

	for _, trail := range trails {
		if trail.S3BucketName == "" {
			continue
		}
		if _, seen := verdicts[trail.S3BucketName]; seen {
			continue
		}

		region, err := client.GetBucketRegion(ctx, trail.S3BucketName)
		if err != nil {
			verdicts[trail.S3BucketName] = trailBucketVerdict{state: trailRetentionNotInAccount, publicAccess: trailRetentionNotInAccount}
			continue
		}

		verdict := trailBucketVerdict{}
		lifecycle, err := client.GetBucketLifecycle(ctx, region, trail.S3BucketName)
		switch {
		case err != nil:
			c.warn("account %s: failed to read lifecycle for trail bucket %s; its retention is unknown, not indefinite", accountID, trail.S3BucketName)
			verdict.state = trailRetentionUnknown
		default:
			verdict.state, verdict.expirationDays = classifyTrailRetention(lifecycle, trailObjectPrefix(trail))
		}

		if lock, err := client.GetBucketObjectLock(ctx, region, trail.S3BucketName); err == nil && lock != nil {
			verdict.objectLockMode = lock.Mode
		}

		bucketPAB := client.GetBucketPublicAccessBlock(ctx, region, trail.S3BucketName)
		var bucketBlocks *bool
		if bucketPAB.Evaluated {
			blocks := bucketPAB.BlocksPublicAccess()
			bucketBlocks = &blocks
		}
		verdict.publicAccess = effectivePublicAccess(accountBlocks, bucketBlocks)
		if verdict.publicAccess == trailBucketAccessNotBlocked {
			c.warn("account %s: trail delivery bucket %s has no effective public access block; audit logs have no legitimate public readership", accountID, trail.S3BucketName)
		}
		verdicts[trail.S3BucketName] = verdict
	}

	minExpiration := int32(0)
	for _, v := range verdicts {
		switch v.state {
		case trailRetentionIndefinite:
			status.TrailBucketsRetainedIndefinitelyCount++
		case trailRetentionExpiring:
			status.TrailBucketsExpiringCount++
			if minExpiration == 0 || v.expirationDays < minExpiration {
				minExpiration = v.expirationDays
			}
		case trailRetentionNotInAccount:
			status.TrailBucketsNotInAccountCount++
		case trailRetentionUnknown:
			status.TrailBucketsRetentionUnknownCount++
		}
		if v.objectLockMode != "" {
			status.TrailBucketsObjectLockedCount++
		}
		switch v.publicAccess {
		case trailBucketAccessBlocked:
			status.TrailBucketsPublicAccessBlockedCount++
		case trailBucketAccessNotBlocked:
			status.TrailBucketsPublicAccessNotBlockedCount++
		case trailRetentionUnknown:
			status.TrailBucketsPublicAccessUnknownCount++
		}
	}
	status.TrailBucketMinExpirationDays = minExpiration

	for i := range status.Trails {
		if v, ok := verdicts[status.Trails[i].S3BucketName]; ok {
			status.Trails[i].BucketRetention = v.state
			status.Trails[i].BucketExpirationDays = v.expirationDays
			status.Trails[i].BucketObjectLockMode = v.objectLockMode
			status.Trails[i].BucketPublicAccess = v.publicAccess
		}
	}
}

// effectivePublicAccess resolves the block state the way S3 enforces it: the
// account-level block or the bucket-level block suffices alone. Either side
// blocking decides blocked even when the other is unreadable; not-blocked
// needs both sides known, because an unreadable side could be the one that
// blocks.
func effectivePublicAccess(accountBlocks, bucketBlocks *bool) string {
	if (accountBlocks != nil && *accountBlocks) || (bucketBlocks != nil && *bucketBlocks) {
		return trailBucketAccessBlocked
	}
	if accountBlocks != nil && bucketBlocks != nil {
		return trailBucketAccessNotBlocked
	}
	return trailRetentionUnknown
}

// trailObjectPrefix is where the trail writes its objects, which is what a
// lifecycle rule must cover to govern them.
func trailObjectPrefix(trail aws.Trail) string {
	if trail.S3KeyPrefix == "" {
		return "AWSLogs/"
	}
	return strings.TrimSuffix(trail.S3KeyPrefix, "/") + "/AWSLogs/"
}

// classifyTrailRetention reduces a bucket's lifecycle rules to the fate of the
// trail's objects. Only enabled rules whose prefix covers the trail path
// count, and only expiration ends retention: a transition to colder storage
// preserves the data and must never read as deletion.
func classifyTrailRetention(lifecycle *aws.BucketLifecycle, trailPrefix string) (string, int32) {
	if lifecycle == nil {
		return trailRetentionIndefinite, 0
	}

	minDays := int32(0)
	sawDateExpiration := false
	for _, rule := range lifecycle.Rules {
		if !strings.EqualFold(rule.Status, "Enabled") {
			continue
		}
		if rule.Prefix != "" && !strings.HasPrefix(trailPrefix, rule.Prefix) {
			continue
		}
		if rule.ExpirationIsDate {
			sawDateExpiration = true
			continue
		}
		if rule.ExpirationDays <= 0 {
			continue
		}
		if minDays == 0 || rule.ExpirationDays < minDays {
			minDays = rule.ExpirationDays
		}
	}

	if minDays > 0 {
		return trailRetentionExpiring, minDays
	}
	if sawDateExpiration {
		// A covering one-off date expiration governs, but not as a rolling
		// retention period anyone can state in days.
		return trailRetentionUnknown, 0
	}
	return trailRetentionIndefinite, 0
}
