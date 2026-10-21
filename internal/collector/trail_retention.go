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

	// missing holds the trail rows' bucket fields a failed read left
	// unknown.
	missing unread
}

// trailBucketCounts are the CloudTrail counts over trail buckets.
var (
	trailRetentionCounts    = []string{"trail_buckets_retained_indefinitely_count", "trail_buckets_expiring_count", "trail_bucket_min_expiration_days", "trail_buckets_not_in_account_count"}
	trailObjectLockCounts   = []string{"trail_buckets_object_locked_count"}
	trailPublicAccessCounts = []string{"trail_buckets_public_access_blocked_count", "trail_buckets_public_access_not_blocked_count"}
)

// resolveTrailBucketRetention resolves, per trail delivery bucket, how long
// the audit log objects survive: the covering lifecycle expiration if any, and
// whether object lock pins retention against deletion.
//
// A bucket missing from the account's own bucket list, the normal shape for
// organization trails delivering to a log archive account, classifies
// not_in_account rather than anything about its rules: enrolling that account
// is what makes it readable. A read that fails leaves its values unknown.
func (c *Collector) resolveTrailBucketRetention(ctx context.Context, client *aws.AWSClient, accountID string, at at, trails []aws.Trail, s3 *S3Metrics, status *CloudTrailStatus) {
	verdicts := map[string]*trailBucketVerdict{}
	var order []string

	for _, trail := range trails {
		name := trail.S3BucketName
		if name == "" || verdicts[name] != nil {
			continue
		}
		v := &trailBucketVerdict{}
		verdicts[name] = v
		order = append(order, name)

		if s3.bucketNames != nil && !s3.bucketNames[name] {
			v.state = trailRetentionNotInAccount
			v.publicAccess = trailRetentionNotInAccount
			continue
		}

		region, err := client.GetBucketRegion(ctx, name)
		if err != nil {
			c.warn("account %s: failed to locate trail bucket %s; its retention is unknown: %v", accountID, name, err)
			v.state, v.publicAccess = trailRetentionUnknown, trailRetentionUnknown
			v.missing.add(err, "bucket_retention", "bucket_expiration_days", "bucket_object_lock_mode", "bucket_public_access")
			status.missing.addPartial(err, 1, trailRetentionCounts...)
			status.missing.addPartial(err, 1, trailObjectLockCounts...)
			status.missing.addPartial(err, 1, trailPublicAccessCounts...)
			continue
		}

		lifecycle, err := client.GetBucketLifecycle(ctx, region, name)
		if err != nil {
			c.warn("account %s: failed to read lifecycle for trail bucket %s; its retention is unknown, not indefinite", accountID, name)
			v.state = trailRetentionUnknown
			v.missing.add(err, "bucket_retention", "bucket_expiration_days")
			status.missing.addPartial(err, 1, trailRetentionCounts...)
		} else {
			v.state, v.expirationDays = classifyTrailRetention(lifecycle, trailObjectPrefix(trail))
		}

		lock, err := client.GetBucketObjectLock(ctx, region, name)
		switch {
		case err != nil:
			c.warn("account %s: failed to read object lock for trail bucket %s: %v", accountID, name, err)
			v.missing.add(err, "bucket_object_lock_mode")
			status.missing.addPartial(err, 1, trailObjectLockCounts...)
		case lock != nil:
			v.objectLockMode = lock.Mode
		}

		bucketPAB := client.GetBucketPublicAccessBlock(ctx, region, name)
		v.publicAccess = trailBucketPublicAccess(s3.accountPAB, bucketPAB)
		switch v.publicAccess {
		case trailBucketAccessNotBlocked:
			c.warn("account %s: trail delivery bucket %s has no effective public access block; audit logs have no legitimate public readership", accountID, name)
		case trailRetentionUnknown:
			why := bucketPAB.Err
			if why == nil {
				why = s3.accountPABErr
			}
			v.missing.add(why, "bucket_public_access")
			status.missing.addPartial(why, 1, trailPublicAccessCounts...)
		}
	}

	minExpiration := int32(0)
	for _, name := range order {
		v := verdicts[name]
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
			status.Trails[i].missing.merge(v.missing)
		}
	}
}

// trailBucketPublicAccess resolves a delivery bucket's block from the account
// block the S3 surface read and the bucket's own, by the rule the bucket
// inventory uses, so a trail's row and its bucket's row never disagree.
func trailBucketPublicAccess(account, bucket aws.PublicAccessBlockSettings) string {
	switch block := effectivePublicAccessBlock(account, bucket); {
	case block.blocked:
		return trailBucketAccessBlocked
	case block.unknown:
		return trailRetentionUnknown
	}
	return trailBucketAccessNotBlocked
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
