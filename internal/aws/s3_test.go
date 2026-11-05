package aws

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// s3TestClient returns a client in us-east-1 whose S3 calls answer gives the
// status and XML body of.
func s3TestClient(answer func(r *http.Request) (int, string)) *AWSClient {
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Body != nil {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		status, body := answer(r)
		return &http.Response{
			StatusCode: status,
			Status:     http.StatusText(status),
			Header:     http.Header{"Content-Type": []string{"application/xml"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    r,
		}, nil
	})
	cfg := aws.Config{
		Region:      DefaultRegionAWS,
		Credentials: credentials.NewStaticCredentialsProvider("AKIDKITEXAMPLE", "kit-secret", ""),
		HTTPClient:  &http.Client{Transport: rt},
	}
	return newAWSClient(cfg, "", Options{})
}

func s3Error(code string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><Error><Code>` + code + `</Code><Message>x</Message></Error>`
}

// S3 rejects an unpaginated ListBuckets for an account whose bucket quota is
// above 10,000, so the listing asks for pages and reads every one.
func TestListBuckets_ReadsEveryPage(t *testing.T) {
	pages := map[string]string{
		"":       `<Bucket><Name>a-bucket</Name></Bucket><Bucket><Name>b-bucket</Name></Bucket></Buckets><ContinuationToken>page-2</ContinuationToken>`,
		"page-2": `<Bucket><Name>c-bucket</Name></Bucket></Buckets>`,
	}
	client := s3TestClient(func(r *http.Request) (int, string) {
		q := r.URL.Query()
		if q.Get("x-id") != "ListBuckets" {
			return http.StatusNotFound, s3Error("NoSuchBucket")
		}
		if q.Get("max-buckets") == "" {
			return http.StatusBadRequest, s3Error("InvalidRequest")
		}
		return http.StatusOK, `<ListAllMyBucketsResult><Owner><ID>o</ID></Owner><Buckets>` + pages[q.Get("continuation-token")] + `</ListAllMyBucketsResult>`
	})

	buckets, err := client.ListBuckets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, b := range buckets {
		names = append(names, b.Name)
	}
	if got := strings.Join(names, ","); got != "a-bucket,b-bucket,c-bucket" {
		t.Errorf("buckets = %s, want every page's", got)
	}
}

// A lifecycle rule whose filter combines a prefix with a tag holds the prefix
// in And, and keeps it. An empty filter covers the whole bucket.
func TestGetBucketLifecycle_RulePrefix(t *testing.T) {
	expire := "<Status>Enabled</Status><Expiration><Days>90</Days></Expiration>"
	for _, tc := range []struct {
		name, rule, want string
	}{
		{"filter prefix", "<Filter><Prefix>logs/</Prefix></Filter>", "logs/"},
		{"and filter", "<Filter><And><Prefix>logs/</Prefix><Tag><Key>archive</Key><Value>true</Value></Tag></And></Filter>", "logs/"},
		{"legacy prefix", "<Prefix>old/</Prefix>", "old/"},
		{"empty filter", "<Filter></Filter>", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := s3TestClient(func(*http.Request) (int, string) {
				return http.StatusOK, `<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ID>r</ID>` + tc.rule + expire + `</Rule></LifecycleConfiguration>`
			})
			lc, err := client.GetBucketLifecycle(context.Background(), "us-east-1", "intake")
			if err != nil {
				t.Fatal(err)
			}
			if len(lc.Rules) != 1 || lc.Rules[0].Prefix != tc.want {
				t.Errorf("rules = %+v, want one rule with prefix %q", lc.Rules, tc.want)
			}
		})
	}
}

// A rule's filter can select objects by tag or size as well as prefix. Those
// are kept, so a narrowed rule never reads like one for the whole bucket.
func TestGetBucketLifecycle_RuleFilter(t *testing.T) {
	for _, tc := range []struct {
		name, filter string
		want         BucketLifecycleRule
	}{
		{"empty filter", "<Filter></Filter>", BucketLifecycleRule{}},
		{"tag", "<Filter><Tag><Key>archive</Key><Value>true</Value></Tag></Filter>", BucketLifecycleRule{Tags: map[string]string{"archive": "true"}}},
		{"minimum size", "<Filter><ObjectSizeGreaterThan>1048576</ObjectSizeGreaterThan></Filter>", BucketLifecycleRule{ObjectSizeGreaterThan: 1048576}},
		{"maximum size", "<Filter><ObjectSizeLessThan>1024</ObjectSizeLessThan></Filter>", BucketLifecycleRule{ObjectSizeLessThan: 1024}},
		{"and of tags", "<Filter><And><Tag><Key>a</Key><Value>1</Value></Tag><Tag><Key>b</Key><Value>2</Value></Tag></And></Filter>",
			BucketLifecycleRule{Tags: map[string]string{"a": "1", "b": "2"}}},
		{"and of prefix and size", "<Filter><And><Prefix>logs/</Prefix><ObjectSizeLessThan>1024</ObjectSizeLessThan></And></Filter>",
			BucketLifecycleRule{Prefix: "logs/", ObjectSizeLessThan: 1024}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := s3TestClient(func(*http.Request) (int, string) {
				return http.StatusOK, `<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule>` + tc.filter + `<Status>Enabled</Status></Rule></LifecycleConfiguration>`
			})
			lc, err := client.GetBucketLifecycle(context.Background(), "us-east-1", "intake")
			if err != nil {
				t.Fatal(err)
			}
			tc.want.Status = "Enabled"
			if len(lc.Rules) != 1 || !reflect.DeepEqual(lc.Rules[0], tc.want) {
				t.Errorf("rules = %+v, want %+v", lc.Rules, tc.want)
			}
			if got, want := lc.Rules[0].NarrowedBeyondPrefix(), tc.want.Tags != nil || tc.want.ObjectSizeGreaterThan > 0 || tc.want.ObjectSizeLessThan > 0; got != want {
				t.Errorf("NarrowedBeyondPrefix() = %v, want %v", got, want)
			}
		})
	}
}

// A noncurrent version expiration can keep the newest noncurrent versions.
func TestGetBucketLifecycle_NewerNoncurrentVersions(t *testing.T) {
	client := s3TestClient(func(*http.Request) (int, string) {
		return http.StatusOK, `<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><Filter></Filter><Status>Enabled</Status>` +
			`<NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays><NewerNoncurrentVersions>3</NewerNoncurrentVersions></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>`
	})
	lc, err := client.GetBucketLifecycle(context.Background(), "us-east-1", "intake")
	if err != nil {
		t.Fatal(err)
	}
	if len(lc.Rules) != 1 || lc.Rules[0].NoncurrentExpirationDays != 30 || lc.Rules[0].NewerNoncurrentVersions != 3 {
		t.Errorf("rules = %+v, want noncurrent days 30 keeping 3 newer versions", lc.Rules)
	}
}

// S3 answers a legacy eu-west-1 bucket's location as EU and a us-east-1
// bucket's as no constraint, and both read as the region.
func TestListBuckets_BucketRegion(t *testing.T) {
	for constraint, want := range map[string]string{"EU": "eu-west-1", "": "us-east-1", "eu-central-1": "eu-central-1"} {
		client := s3TestClient(func(r *http.Request) (int, string) {
			q := r.URL.Query()
			switch {
			case q.Get("x-id") == "ListBuckets":
				return http.StatusOK, `<ListAllMyBucketsResult><Owner><ID>o</ID></Owner><Buckets><Bucket><Name>legacy</Name></Bucket></Buckets></ListAllMyBucketsResult>`
			case q.Has("location"):
				return http.StatusOK, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` + constraint + `</LocationConstraint>`
			}
			return http.StatusNotFound, s3Error("NoSuchBucket")
		})
		buckets, err := client.ListBuckets(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(buckets) != 1 || buckets[0].Region != want {
			t.Errorf("constraint %q: buckets = %+v, want region %q", constraint, buckets, want)
		}
	}
}
