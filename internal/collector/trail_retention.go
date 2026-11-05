package collector

import (
	"context"
	"regexp"
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
	// objectLockDays is the bucket's default object lock retention in days.
	objectLockDays int32

	// lifecycle is the bucket's lifecycle configuration when it was read,
	// and lifecycleRead is true then. Each trail's retention comes from the
	// rules that cover that trail's own prefix. versioned is whether the
	// bucket keeps noncurrent versions, and versioningErr is why that could
	// not be read.
	lifecycle     *aws.BucketLifecycle
	lifecycleRead bool
	versioned     bool
	versioningErr error

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
//
// Each trail's retention comes from the lifecycle rules that cover its own
// key prefix. A bucket that several trails deliver to counts as expiring when
// any of their objects expire, with the shortest expiration. Otherwise it
// counts as unknown when any trail's retention is unknown. The counts do not
// depend on the order DescribeTrails lists the trails in.
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
			v.lifecycle, v.lifecycleRead = lifecycle, true
			v.versioned, v.versioningErr = client.GetBucketVersioning(ctx, region, name)
			if v.versioningErr != nil {
				c.warn("account %s: failed to read versioning for trail bucket %s; whether expired objects are deleted is unknown: %v", accountID, name, v.versioningErr)
			}
		}

		lock, err := client.GetBucketObjectLock(ctx, region, name)
		switch {
		case err != nil:
			c.warn("account %s: failed to read object lock for trail bucket %s: %v", accountID, name, err)
			v.missing.add(err, "bucket_object_lock_mode")
			status.missing.addPartial(err, 1, trailObjectLockCounts...)
		case lock != nil:
			v.objectLockMode = lock.Mode
			v.objectLockDays = lock.Days + 365*lock.Years
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

	// A bucket whose lifecycle was read takes its state from the trails that
	// deliver to it, each judged by the rules covering its own prefix.
	for _, trail := range trails {
		v := verdicts[trail.S3BucketName]
		if v == nil || !v.lifecycleRead {
			continue
		}
		state, days := v.classify(trail)
		v.state, v.expirationDays = combineTrailRetention(v.state, v.expirationDays, state, days)
	}
	for _, name := range order {
		if v := verdicts[name]; v.lifecycleRead && v.versioningErr != nil && v.state == trailRetentionUnknown {
			status.missing.addPartial(v.versioningErr, 1, trailRetentionCounts...)
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
		row := &status.Trails[i]
		v, ok := verdicts[row.S3BucketName]
		if !ok {
			continue
		}
		row.BucketRetention, row.BucketExpirationDays = v.state, v.expirationDays
		if v.lifecycleRead {
			row.BucketRetention, row.BucketExpirationDays = v.classify(aws.Trail{
				S3KeyPrefix: row.S3KeyPrefix, TrailARN: row.TrailARN, IsOrganizationTrail: row.IsOrganizationTrail,
			})
			if row.BucketRetention == trailRetentionUnknown && v.versioningErr != nil {
				row.missing.add(v.versioningErr, "bucket_retention", "bucket_expiration_days")
			}
		}
		row.BucketObjectLockMode = v.objectLockMode
		row.BucketPublicAccess = v.publicAccess
		row.missing.merge(v.missing)
	}
}

// combineTrailRetention folds one more trail's retention into a bucket's. A
// bucket with no state yet takes the trail's. Expiring wins with the shorter
// expiration, then unknown, then indefinite.
func combineTrailRetention(state string, days int32, trailState string, trailDays int32) (string, int32) {
	rank := map[string]int{"": 0, trailRetentionIndefinite: 1, trailRetentionUnknown: 2, trailRetentionExpiring: 3}
	switch {
	case rank[trailState] > rank[state]:
		return trailState, trailDays
	case trailState == trailRetentionExpiring && state == trailRetentionExpiring && trailDays < days:
		return state, trailDays
	}
	return state, days
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
// lifecycle rule must cover to govern them. A trail that is not an
// organization trail writes only under its own account's folder,
// AWSLogs/<account ID>/. An organization trail writes a folder for each
// account under AWSLogs/<organization ID>/.
func trailObjectPrefix(trail aws.Trail) string {
	prefix := "AWSLogs/"
	if trail.S3KeyPrefix != "" {
		prefix = strings.TrimSuffix(trail.S3KeyPrefix, "/") + "/AWSLogs/"
	}
	if account := trailAccountID(trail.TrailARN); account != "" && !trail.IsOrganizationTrail {
		prefix += account + "/"
	}
	return prefix
}

// trailAccountID is the account in a trail's ARN, arn:<partition>:cloudtrail:
// <region>:<account>:trail/<name>, or "" when the ARN has none.
func trailAccountID(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 || parts[0] != "arn" || parts[2] != "cloudtrail" {
		return ""
	}
	return parts[4]
}

// classify judges the trail's objects by the bucket's lifecycle and
// versioning. When the versioning could not be read and the two answers
// differ, the retention is unknown. A lifecycle expiration cannot delete an
// object version while object lock retains it, so an expiring object is kept
// for at least the bucket's default retention. A year of retention counts as
// 365 days.
func (v *trailBucketVerdict) classify(trail aws.Trail) (string, int32) {
	trailPrefix, organization := trailObjectPrefix(trail), trail.IsOrganizationTrail
	state, days := classifyTrailRetention(v.lifecycle, trailPrefix, organization, v.versioned)
	if v.versioningErr != nil {
		state, days = classifyTrailRetention(v.lifecycle, trailPrefix, organization, false)
		if versionedState, versionedDays := classifyTrailRetention(v.lifecycle, trailPrefix, organization, true); versionedState != state || versionedDays != days {
			return trailRetentionUnknown, 0
		}
	}
	if state == trailRetentionExpiring && days < v.objectLockDays {
		days = v.objectLockDays
	}
	return state, days
}

// classifyTrailRetention reduces a bucket's lifecycle rules to the fate of the
// trail's objects. Only enabled rules whose prefix covers the trail path
// count, and only expiration ends retention: a transition to colder storage
// preserves the data and must never read as deletion. A rule that also
// filters by tag or object size covers only some objects, so it does not
// count. CloudTrail log files carry no tags.
//
// In a versioned bucket an expiration only makes the object noncurrent, so
// the object is deleted only when a covering rule also expires noncurrent
// versions. It is then kept for the two periods together. A trail object is
// written once and has at most one noncurrent version, so a rule that keeps
// any newer noncurrent versions never deletes it.
func classifyTrailRetention(lifecycle *aws.BucketLifecycle, trailPrefix string, organization, versioned bool) (string, int32) {
	if lifecycle == nil {
		return trailRetentionIndefinite, 0
	}

	minDays, minNoncurrentDays := int32(0), int32(0)
	sawDateExpiration := false
	for _, rule := range lifecycle.Rules {
		if !strings.EqualFold(rule.Status, "Enabled") {
			continue
		}
		if !ruleCoversTrailObjects(rule.Prefix, trailPrefix, organization) || rule.NarrowedBeyondPrefix() {
			continue
		}
		if rule.NoncurrentExpirationDays > 0 && rule.NewerNoncurrentVersions == 0 && (minNoncurrentDays == 0 || rule.NoncurrentExpirationDays < minNoncurrentDays) {
			minNoncurrentDays = rule.NoncurrentExpirationDays
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
	if versioned && minNoncurrentDays == 0 {
		return trailRetentionIndefinite, 0
	}

	if minDays > 0 {
		if versioned {
			return trailRetentionExpiring, minDays + minNoncurrentDays
		}
		return trailRetentionExpiring, minDays
	}
	if sawDateExpiration {
		// A covering one-off date expiration governs, but not as a rolling
		// retention period anyone can state in days.
		return trailRetentionUnknown, 0
	}
	return trailRetentionIndefinite, 0
}

// organizationFolder is an organization ID, with or without a trailing slash.
var organizationFolder = regexp.MustCompile(`^o-[a-z0-9]{10,32}/?$`)

// ruleCoversTrailObjects reports whether a lifecycle rule's prefix covers
// every object a trail writes under trailPrefix. An organization trail writes
// under trailPrefix followed by its organization ID. DescribeTrails does not
// return that ID, so a rule on one organization's folder counts as covering
// the trail.
func ruleCoversTrailObjects(rulePrefix, trailPrefix string, organization bool) bool {
	if strings.HasPrefix(trailPrefix, rulePrefix) {
		return true
	}
	folder, ok := strings.CutPrefix(rulePrefix, trailPrefix)
	return organization && ok && organizationFolder.MatchString(folder)
}
