package collector

import (
	"errors"
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

func rule(status, prefix string, days int32) aws.BucketLifecycleRule {
	return aws.BucketLifecycleRule{Status: status, Prefix: prefix, ExpirationDays: days}
}

func TestClassifyTrailRetention(t *testing.T) {
	tests := []struct {
		name     string
		rules    []aws.BucketLifecycleRule
		prefix   string
		want     string
		wantDays int32
	}{
		{
			name:   "no lifecycle keeps everything forever",
			rules:  nil,
			prefix: "AWSLogs/",
			want:   trailRetentionIndefinite,
		},
		{
			name:     "unfiltered expiration governs the trail",
			rules:    []aws.BucketLifecycleRule{rule("Enabled", "", 365)},
			prefix:   "AWSLogs/",
			want:     trailRetentionExpiring,
			wantDays: 365,
		},
		{
			name:     "prefix covering the trail path governs",
			rules:    []aws.BucketLifecycleRule{rule("Enabled", "AWSLogs/", 400)},
			prefix:   "AWSLogs/",
			want:     trailRetentionExpiring,
			wantDays: 400,
		},
		{
			// A rule scoped to tmp/ deletes nothing CloudTrail writes.
			name:   "rule scoped elsewhere does not govern",
			rules:  []aws.BucketLifecycleRule{rule("Enabled", "tmp/", 30)},
			prefix: "AWSLogs/",
			want:   trailRetentionIndefinite,
		},
		{
			// The trail writes under audit/AWSLogs/, so a bare AWSLogs/ rule
			// misses it.
			name:   "key prefix moves the trail out from under the rule",
			rules:  []aws.BucketLifecycleRule{rule("Enabled", "AWSLogs/", 30)},
			prefix: "audit/AWSLogs/",
			want:   trailRetentionIndefinite,
		},
		{
			name:   "disabled rules govern nothing",
			rules:  []aws.BucketLifecycleRule{rule("Disabled", "", 30)},
			prefix: "AWSLogs/",
			want:   trailRetentionIndefinite,
		},
		{
			name: "shortest covering expiration wins",
			rules: []aws.BucketLifecycleRule{
				rule("Enabled", "", 730),
				rule("Enabled", "AWSLogs/", 365),
			},
			prefix:   "AWSLogs/",
			want:     trailRetentionExpiring,
			wantDays: 365,
		},
		{
			// Moving to Glacier preserves the data. Only expiration ends
			// retention, so a transition-only rule reads as indefinite.
			name: "transitions are not expiration",
			rules: []aws.BucketLifecycleRule{
				{Status: "Enabled", Transitions: []string{"90d->GLACIER"}},
			},
			prefix: "AWSLogs/",
			want:   trailRetentionIndefinite,
		},
		{
			name: "a one-off date expiration is not a rolling period",
			rules: []aws.BucketLifecycleRule{
				{Status: "Enabled", ExpirationIsDate: true},
			},
			prefix: "AWSLogs/",
			want:   trailRetentionUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifecycle := &aws.BucketLifecycle{Rules: tt.rules}
			if tt.rules == nil {
				lifecycle = nil
			}
			state, days := classifyTrailRetention(lifecycle, tt.prefix)
			if state != tt.want || days != tt.wantDays {
				t.Fatalf("classifyTrailRetention() = %q %d, want %q %d", state, days, tt.want, tt.wantDays)
			}
		})
	}
}

func TestTrailObjectPrefix(t *testing.T) {
	if got := trailObjectPrefix(aws.Trail{}); got != "AWSLogs/" {
		t.Errorf("trailObjectPrefix() = %q, want AWSLogs/", got)
	}
	if got := trailObjectPrefix(aws.Trail{S3KeyPrefix: "audit"}); got != "audit/AWSLogs/" {
		t.Errorf("trailObjectPrefix() = %q, want audit/AWSLogs/", got)
	}
	if got := trailObjectPrefix(aws.Trail{S3KeyPrefix: "audit/"}); got != "audit/AWSLogs/" {
		t.Errorf("trailObjectPrefix() = %q, want audit/AWSLogs/ for a trailing slash", got)
	}
}

// Each flag is on when either side sets it. Every flag on decides blocked
// even when one side is unreadable, but not-blocked needs both sides read:
// the unreadable side could set the flags the other lacks.
func TestTrailBucketPublicAccess(t *testing.T) {
	full := aws.PublicAccessBlockSettings{BlockPublicACLs: true, IgnorePublicACLs: true, BlockPublicPolicy: true, RestrictPublicBuckets: true, Evaluated: true}
	acls := aws.PublicAccessBlockSettings{BlockPublicACLs: true, IgnorePublicACLs: true, Evaluated: true}
	policies := aws.PublicAccessBlockSettings{BlockPublicPolicy: true, RestrictPublicBuckets: true, Evaluated: true}
	none := aws.PublicAccessBlockSettings{Evaluated: true}
	unread := aws.PublicAccessBlockSettings{ErrorCode: "AccessDenied", Err: errors.New("getting public access block: AccessDenied")}

	tests := []struct {
		name    string
		account aws.PublicAccessBlockSettings
		bucket  aws.PublicAccessBlockSettings
		want    string
	}{
		{name: "account block alone suffices", account: full, bucket: none, want: trailBucketAccessBlocked},
		{name: "bucket block alone suffices", account: none, bucket: full, want: trailBucketAccessBlocked},
		{name: "flags split across the two sides block together", account: acls, bucket: policies, want: trailBucketAccessBlocked},
		{name: "account blocks even when the bucket is unreadable", account: full, bucket: unread, want: trailBucketAccessBlocked},
		{name: "bucket blocks even when the account is unreadable", account: unread, bucket: full, want: trailBucketAccessBlocked},
		{name: "a flag neither side sets is the finding", account: acls, bucket: acls, want: trailBucketAccessNotBlocked},
		{name: "both known open is the finding", account: none, bucket: none, want: trailBucketAccessNotBlocked},
		{name: "open bucket with unreadable account stays unknown", account: unread, bucket: none, want: trailRetentionUnknown},
		{name: "partial account with unreadable bucket stays unknown", account: acls, bucket: unread, want: trailRetentionUnknown},
		{name: "nothing readable is unknown", account: unread, bucket: unread, want: trailRetentionUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := trailBucketPublicAccess(tt.account, tt.bucket); got != tt.want {
				t.Fatalf("trailBucketPublicAccess() = %q, want %q", got, tt.want)
			}
		})
	}
}
