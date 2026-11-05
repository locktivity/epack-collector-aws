package collector

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// trailRow and cloudTrailValues are the CloudTrail values of the detailed
// artifact the tests below read.
type trailRow struct {
	Name                 string `json:"name"`
	BucketRetention      string `json:"bucket_retention"`
	BucketExpirationDays int32  `json:"bucket_expiration_days"`
	IsLogging            bool   `json:"is_logging"`
	ManagementEvents     string `json:"management_events"`
}

type cloudTrailValues struct {
	Enabled                      bool       `json:"enabled"`
	TrailBucketsExpiringCount    int        `json:"trail_buckets_expiring_count"`
	TrailBucketMinExpirationDays int32      `json:"trail_bucket_min_expiration_days"`
	Trails                       []trailRow `json:"trails"`
}

// runCloudTrail runs the kit's account with responses and returns its
// CloudTrail values.
func runCloudTrail(t *testing.T, responses []collectortest.Response) cloudTrailValues {
	t.Helper()
	isolateAWSEnvironment(t)
	res := runKit(t, kitConfig(), kitSecrets(), responses)
	var doc struct {
		Accounts []struct {
			AccountSecurity struct {
				CloudTrail cloudTrailValues `json:"cloudtrail"`
			} `json:"account_security"`
		} `json:"accounts"`
	}
	decodeArtifact(t, res, awsPath, &doc)
	if len(doc.Accounts) != 1 {
		t.Fatalf("accounts = %d, want 1", len(doc.Accounts))
	}
	return doc.Accounts[0].AccountSecurity.CloudTrail
}

// trailNamed returns the trail row called name.
func trailNamed(t *testing.T, ct cloudTrailValues, name string) trailRow {
	t.Helper()
	for _, r := range ct.Trails {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no trail row %q in %+v", name, ct.Trails)
	return trailRow{}
}

const (
	orgTrailARN    = "arn:aws:cloudtrail:us-east-1:999900001111:trail/org-trail"
	localTrailARN  = "arn:aws:cloudtrail:us-east-1:111122223333:trail/northwind-trail"
	westCloudTrail = "https://cloudtrail.us-west-2.amazonaws.com/"
)

// testTrail is a multi-region trail into the kit's log bucket.
func testTrail(name, arn, keyPrefix string, org bool) map[string]any {
	trail := map[string]any{"Name": name, "TrailARN": arn, "HomeRegion": kitRegion, "S3BucketName": kitLogsBucket,
		"IsMultiRegionTrail": true, "IsOrganizationTrail": org, "LogFileValidationEnabled": true}
	if keyPrefix != "" {
		trail["S3KeyPrefix"] = keyPrefix
	}
	return trail
}

// describeTrailsAt answers DescribeTrails at endpoint with trails.
func describeTrailsAt(endpoint string, trails ...map[string]any) collectortest.Response {
	list := make([]any, 0, len(trails))
	for _, tr := range trails {
		list = append(list, tr)
	}
	return jsonResponse("aws.cloudtrail.DescribeTrails", endpoint, map[string]any{"trailList": list})
}

// trailStatusAt answers GetTrailStatus for arn at endpoint.
func trailStatusAt(endpoint, arn string, logging bool) collectortest.Response {
	return jsonItemResponse("aws.cloudtrail.GetTrailStatus", endpoint, map[string]any{"Name": arn}, map[string]any{"IsLogging": logging})
}

// logBucketLifecycle answers the read of the log bucket's lifecycle with
// rules, XML <Rule> elements.
func logBucketLifecycle(rules string) collectortest.Response {
	return restResponse("aws.s3.GetBucketLifecycleConfiguration", "GET", bucketURL(kitLogsBucket, "lifecycle"), 0,
		"<LifecycleConfiguration>"+rules+"</LifecycleConfiguration>")
}

// logBucketVersioning answers the read of the log bucket's versioning with
// body.
func logBucketVersioning(body string) collectortest.Response {
	return restResponse("aws.s3.GetBucketVersioning", "GET", bucketURL(kitLogsBucket, "versioning"), 0, body)
}

// unversioned is the versioning of a bucket that never had it enabled.
const unversioned = "<VersioningConfiguration/>"

// eastAndWest answers the region listing with us-east-1 and us-west-2.
func eastAndWest() collectortest.Response {
	return ec2Response("aws.ec2.DescribeRegions",
		"<regionInfo><item><regionName>us-east-1</regionName><regionEndpoint>ec2.us-east-1.amazonaws.com</regionEndpoint><optInStatus>opt-in-not-required</optInStatus></item>"+
			"<item><regionName>us-west-2</regionName><regionEndpoint>ec2.us-west-2.amazonaws.com</regionEndpoint><optInStatus>opt-in-not-required</optInStatus></item></regionInfo>")
}

// DescribeTrails lists a single-region trail only in its own region, so the
// trails are listed in every scanned region.
func TestCloudTrail_SingleRegionTrailInAnotherRegionCounts(t *testing.T) {
	const arn = "arn:aws:cloudtrail:us-west-2:111122223333:trail/west-trail"
	west := map[string]any{"Name": "west-trail", "TrailARN": arn, "HomeRegion": "us-west-2", "S3BucketName": kitLogsBucket,
		"IsMultiRegionTrail": false, "IsOrganizationTrail": false, "LogFileValidationEnabled": true}
	responses := replaceResponses(kitResponses(), eastAndWest(), describeTrailsAt(regional("cloudtrail")))
	responses = append(responses, describeTrailsAt(westCloudTrail, west), trailStatusAt(westCloudTrail, arn, true))

	ct := runCloudTrail(t, responses)

	if !ct.Enabled {
		t.Error("enabled = false, want true for the logging trail in us-west-2")
	}
	if len(ct.Trails) != 1 || ct.Trails[0].Name != "west-trail" || !ct.Trails[0].IsLogging {
		t.Errorf("trails = %+v, want the logging west-trail", ct.Trails)
	}
}

// A logging trail counts as an audit log only when its event selectors
// record management events that change the account.
func TestCloudTrail_ManagementEventsDecideAuditLogging(t *testing.T) {
	isolateAWSEnvironment(t)
	const arn = "arn:aws:cloudtrail:us-east-1:111122223333:trail/selected-trail"
	run := func(t *testing.T, selectors []any) (CloudPostureLogging, cloudTrailValues) {
		t.Helper()
		trail := testTrail("selected-trail", arn, "", false)
		trail["HasCustomEventSelectors"] = true
		responses := replaceResponses(kitResponses(), describeTrailsAt(regional("cloudtrail"), trail))
		responses = append(responses,
			trailStatusAt(regional("cloudtrail"), arn, true),
			jsonItemResponse("aws.cloudtrail.GetEventSelectors", regional("cloudtrail"), map[string]any{"TrailName": arn},
				map[string]any{"TrailARN": arn, "EventSelectors": selectors}))
		res := runKit(t, kitConfig(), kitSecrets(), responses)
		var posture CloudPosture
		decodeArtifact(t, res, cloudPosturePath, &posture)
		var doc struct {
			Accounts []struct {
				AccountSecurity struct {
					CloudTrail cloudTrailValues `json:"cloudtrail"`
				} `json:"account_security"`
			} `json:"accounts"`
		}
		decodeArtifact(t, res, awsPath, &doc)
		return posture.Accounts[0].Logging, doc.Accounts[0].AccountSecurity.CloudTrail
	}

	for _, tc := range []struct {
		name      string
		selectors []any
		want      bool
		events    string
	}{
		{"every management event", []any{map[string]any{"ReadWriteType": "All", "IncludeManagementEvents": true, "DataResources": []any{}}}, true, "read_write"},
		{"write management events", []any{map[string]any{"ReadWriteType": "WriteOnly", "IncludeManagementEvents": true, "DataResources": []any{}}}, true, "write_only"},
		{"read management events", []any{map[string]any{"ReadWriteType": "ReadOnly", "IncludeManagementEvents": true, "DataResources": []any{}}}, false, "read_only"},
		{"data events only", []any{map[string]any{"ReadWriteType": "All", "IncludeManagementEvents": false,
			"DataResources": []any{map[string]any{"Type": "AWS::S3::Object", "Values": []string{"arn:aws:s3"}}}}}, false, "none"},
		{"every management event except KMS", []any{map[string]any{"ReadWriteType": "All", "IncludeManagementEvents": true, "DataResources": []any{},
			"ExcludeManagementEventSources": []string{"kms.amazonaws.com"}}}, false, "read_write"},
		{"every management event except KMS and RDS Data API", []any{map[string]any{"ReadWriteType": "All", "IncludeManagementEvents": true, "DataResources": []any{},
			"ExcludeManagementEventSources": []string{"kms.amazonaws.com", "rdsdata.amazonaws.com"}}}, false, "read_write"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logging, ct := run(t, tc.selectors)
			for name, got := range map[string]*bool{
				"audit_log_enabled":      logging.AuditLogEnabled,
				"audit_log_all_regions":  logging.AuditLogAllRegions,
				"cloudtrail_enabled":     logging.CloudTrailEnabled,
				"cloudtrail_multiregion": logging.CloudTrailMultiregion,
			} {
				if got == nil || *got != tc.want {
					t.Errorf("logging/%s = %s, want %v", name, showBool(got), tc.want)
				}
			}
			if row := trailNamed(t, ct, "selected-trail"); row.ManagementEvents != tc.events {
				t.Errorf("management_events = %q, want %q", row.ManagementEvents, tc.events)
			}
		})
	}
}

// Each trail's retention follows the lifecycle rules that cover its own key
// prefix, whichever trail DescribeTrails lists first.
func TestCloudTrail_RetentionFollowsEachTrailsKeyPrefix(t *testing.T) {
	const awsLogsRule = "<Rule><ID>expire</ID><Filter><Prefix>AWSLogs/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>365</Days></Expiration></Rule>"
	org := testTrail("org-trail", orgTrailARN, "", true)
	local := testTrail("northwind-trail", localTrailARN, "local", false)
	for _, tc := range []struct {
		name   string
		trails []map[string]any
	}{
		{"covered trail listed first", []map[string]any{org, local}},
		{"uncovered trail listed first", []map[string]any{local, org}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct := runCloudTrail(t, replaceResponses(kitResponses(), logBucketVersioning(unversioned), logBucketLifecycle(awsLogsRule),
				describeTrailsAt(regional("cloudtrail"), tc.trails...)))
			if r := trailNamed(t, ct, "org-trail"); r.BucketRetention != trailRetentionExpiring || r.BucketExpirationDays != 365 {
				t.Errorf("org-trail: bucket_retention=%q days=%d, want expiring 365", r.BucketRetention, r.BucketExpirationDays)
			}
			if r := trailNamed(t, ct, "northwind-trail"); r.BucketRetention != trailRetentionIndefinite || r.BucketExpirationDays != 0 {
				t.Errorf("northwind-trail: bucket_retention=%q days=%d, want indefinite 0", r.BucketRetention, r.BucketExpirationDays)
			}
		})
	}
}

// An expiration in a versioned bucket only makes the object noncurrent, so
// the trail's objects are deleted only when a rule also expires noncurrent
// versions.
func TestCloudTrail_VersionedBucketKeepsNoncurrentVersions(t *testing.T) {
	const expire = "<Rule><ID>expire</ID><Filter><Prefix>AWSLogs/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>365</Days></Expiration></Rule>"
	const noncurrent = "<Rule><ID>noncurrent</ID><Filter><Prefix>AWSLogs/</Prefix></Filter><Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays></NoncurrentVersionExpiration></Rule>"
	versioned := "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"
	for _, tc := range []struct {
		name, versioning, rules string
		want                    string
		days                    int32
	}{
		{"unversioned", unversioned, expire, trailRetentionExpiring, 365},
		{"versioned", versioned, expire, trailRetentionIndefinite, 0},
		{"versioned with noncurrent expiration", versioned, expire + noncurrent, trailRetentionExpiring, 395},
		{"versioned with noncurrent expiration keeping newer versions", versioned,
			expire + strings.Replace(noncurrent, "</NoncurrentDays>", "</NoncurrentDays><NewerNoncurrentVersions>3</NewerNoncurrentVersions>", 1), trailRetentionIndefinite, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct := runCloudTrail(t, replaceResponses(kitResponses(), logBucketVersioning(tc.versioning), logBucketLifecycle(tc.rules)))
			if r := trailNamed(t, ct, "org-trail"); r.BucketRetention != tc.want || r.BucketExpirationDays != tc.days {
				t.Errorf("bucket_retention=%q days=%d, want %s %d", r.BucketRetention, r.BucketExpirationDays, tc.want, tc.days)
			}
		})
	}
}

// A rule governs the trail when its prefix covers every object the trail
// writes. A trail that is not an organization trail writes only under its
// own account's folder, and a rule whose filter combines a prefix with a tag
// applies only under that prefix. A rule that also filters by tag or object
// size covers only some of the trail's objects.
func TestCloudTrail_LifecycleRuleScope(t *testing.T) {
	expire := func(filter string) string {
		return "<Rule><ID>expire</ID><Filter>" + filter + "</Filter><Status>Enabled</Status><Expiration><Days>90</Days></Expiration></Rule>"
	}
	local := describeTrailsAt(regional("cloudtrail"), testTrail("northwind-trail", localTrailARN, "", false))
	for _, tc := range []struct {
		name, filter string
		want         string
		days         int32
	}{
		{"this account's folder", "<Prefix>AWSLogs/" + kitAccountID + "/</Prefix>", trailRetentionExpiring, 90},
		{"another account's folder", "<Prefix>AWSLogs/999999999999/</Prefix>", trailRetentionIndefinite, 0},
		{"another prefix with a tag", "<And><Prefix>tmp/</Prefix><Tag><Key>temp</Key><Value>true</Value></Tag></And>", trailRetentionIndefinite, 0},
		{"a tag only", "<Tag><Key>temp</Key><Value>true</Value></Tag>", trailRetentionIndefinite, 0},
		{"a covering prefix with a tag", "<And><Prefix>AWSLogs/</Prefix><Tag><Key>temp</Key><Value>true</Value></Tag></And>", trailRetentionIndefinite, 0},
		{"a minimum object size", "<ObjectSizeGreaterThan>1048576</ObjectSizeGreaterThan>", trailRetentionIndefinite, 0},
		{"a covering prefix with a maximum object size", "<And><Prefix>AWSLogs/</Prefix><ObjectSizeLessThan>1024</ObjectSizeLessThan></And>", trailRetentionIndefinite, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct := runCloudTrail(t, replaceResponses(kitResponses(), logBucketVersioning(unversioned), logBucketLifecycle(expire(tc.filter)), local))
			if r := trailNamed(t, ct, "northwind-trail"); r.BucketRetention != tc.want || r.BucketExpirationDays != tc.days {
				t.Errorf("bucket_retention=%q days=%d, want %s %d", r.BucketRetention, r.BucketExpirationDays, tc.want, tc.days)
			}
		})
	}
}

// An organization trail writes under AWSLogs/<organization ID>/, so a rule on
// the organization's folder covers its objects.
func TestCloudTrail_OrganizationTrailFolder(t *testing.T) {
	expire := func(prefix string) string {
		return "<Rule><ID>expire</ID><Filter><Prefix>" + prefix + "</Prefix></Filter><Status>Enabled</Status><Expiration><Days>90</Days></Expiration></Rule>"
	}
	org := describeTrailsAt(regional("cloudtrail"), testTrail("org-trail", orgTrailARN, "", true))
	for _, tc := range []struct {
		name, prefix string
		want         string
		days         int32
	}{
		{"AWSLogs/", "AWSLogs/", trailRetentionExpiring, 90},
		{"the organization folder", "AWSLogs/o-exampleorg1/", trailRetentionExpiring, 90},
		{"one account's folder", "AWSLogs/o-exampleorg1/" + kitAccountID + "/", trailRetentionIndefinite, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct := runCloudTrail(t, replaceResponses(kitResponses(), logBucketVersioning(unversioned), logBucketLifecycle(expire(tc.prefix)), org))
			if r := trailNamed(t, ct, "org-trail"); r.BucketRetention != tc.want || r.BucketExpirationDays != tc.days {
				t.Errorf("bucket_retention=%q days=%d, want %s %d", r.BucketRetention, r.BucketExpirationDays, tc.want, tc.days)
			}
		})
	}
}

// A multi-region trail with IncludeGlobalServiceEvents false records no IAM,
// STS or CloudFront events, so it does not log every region.
func TestCloudTrail_MultiRegionTrailNeedsGlobalServiceEvents(t *testing.T) {
	const arn = "arn:aws:cloudtrail:us-east-1:111122223333:trail/global-trail"
	for _, global := range []bool{true, false} {
		t.Run(fmt.Sprintf("IncludeGlobalServiceEvents %v", global), func(t *testing.T) {
			isolateAWSEnvironment(t)
			trail := testTrail("global-trail", arn, "", false)
			trail["IncludeGlobalServiceEvents"] = global
			responses := replaceResponses(kitResponses(), describeTrailsAt(regional("cloudtrail"), trail))
			responses = append(responses, trailStatusAt(regional("cloudtrail"), arn, true))
			res := runKit(t, kitConfig(), kitSecrets(), responses)
			var posture CloudPosture
			decodeArtifact(t, res, cloudPosturePath, &posture)
			var doc struct {
				Accounts []struct {
					AccountSecurity struct {
						CloudTrail struct {
							Enabled            *bool `json:"enabled"`
							MultiRegionEnabled *bool `json:"multi_region_enabled"`
						} `json:"cloudtrail"`
					} `json:"account_security"`
				} `json:"accounts"`
			}
			decodeArtifact(t, res, awsPath, &doc)
			ct, logging := doc.Accounts[0].AccountSecurity.CloudTrail, posture.Accounts[0].Logging
			if ct.Enabled == nil || !*ct.Enabled {
				t.Errorf("enabled = %s, want true", showBool(ct.Enabled))
			}
			for name, got := range map[string]*bool{
				"multi_region_enabled":   ct.MultiRegionEnabled,
				"audit_log_all_regions":  logging.AuditLogAllRegions,
				"cloudtrail_multiregion": logging.CloudTrailMultiregion,
			} {
				if got == nil || *got != global {
					t.Errorf("%s = %s, want %v", name, showBool(got), global)
				}
			}
		})
	}
}

// objectLockResponse answers the read of the log bucket's object lock with a
// default retention of days, or as a bucket without object lock when days is
// 0.
func objectLockResponse(mode string, days int) collectortest.Response {
	if days == 0 {
		return restResponse("aws.s3.GetObjectLockConfiguration", http.MethodGet, bucketURL(kitLogsBucket, "object-lock"),
			http.StatusNotFound, s3Error("ObjectLockConfigurationNotFoundError"))
	}
	return restResponse("aws.s3.GetObjectLockConfiguration", http.MethodGet, bucketURL(kitLogsBucket, "object-lock"), 0,
		fmt.Sprintf("<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>%s</Mode><Days>%d</Days></DefaultRetention></Rule></ObjectLockConfiguration>", mode, days))
}

// A lifecycle expiration cannot delete a locked object version, so a default
// retention longer than the lifecycle sets how long the trail's objects are
// kept.
func TestCloudTrail_ObjectLockRetentionOutlastsLifecycle(t *testing.T) {
	const versioned = "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"
	for _, tc := range []struct {
		name                         string
		lockMode                     string
		lockDays, expire, noncurrent int
		want                         int32
	}{
		{"compliance lock longer than the lifecycle", "COMPLIANCE", 365, 90, 1, 365},
		{"governance lock longer than the lifecycle", "GOVERNANCE", 400, 30, 1, 400},
		{"no object lock", "", 0, 90, 1, 91},
		{"lock shorter than the lifecycle", "COMPLIANCE", 30, 90, 1, 91},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := fmt.Sprintf("<Rule><ID>expire</ID><Filter><Prefix>AWSLogs/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>%d</Days></Expiration></Rule>"+
				"<Rule><ID>noncurrent</ID><Filter><Prefix>AWSLogs/</Prefix></Filter><Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>%d</NoncurrentDays></NoncurrentVersionExpiration></Rule>",
				tc.expire, tc.noncurrent)
			org := describeTrailsAt(regional("cloudtrail"), testTrail("org-trail", orgTrailARN, "", true))
			ct := runCloudTrail(t, replaceResponses(kitResponses(), logBucketVersioning(versioned), logBucketLifecycle(rules), objectLockResponse(tc.lockMode, tc.lockDays), org))
			row := trailNamed(t, ct, "org-trail")
			if row.BucketRetention != trailRetentionExpiring || row.BucketExpirationDays != tc.want {
				t.Errorf("bucket_retention = %q, bucket_expiration_days = %d, want expiring after %d days", row.BucketRetention, row.BucketExpirationDays, tc.want)
			}
			if ct.TrailBucketsExpiringCount != 1 || ct.TrailBucketMinExpirationDays != tc.want {
				t.Errorf("trail_buckets_expiring_count = %d, trail_bucket_min_expiration_days = %d, want 1 and %d", ct.TrailBucketsExpiringCount, ct.TrailBucketMinExpirationDays, tc.want)
			}
		})
	}
}

// orgTrailValues is the part of the CloudTrail values the organization trail
// tests read. A value that was left out reads as nil.
type orgTrailValues struct {
	Enabled                  *bool `json:"enabled"`
	OrganizationTrailEnabled *bool `json:"organization_trail_enabled"`
	TrailStatusInferredCount int   `json:"trail_status_inferred_count"`
	Trails                   []struct {
		TrailStatusInferred bool `json:"trail_status_inferred"`
	} `json:"trails"`
}

// cloudTrailDenied answers the CloudTrail call op for request with
// AccessDenied.
func cloudTrailDenied(op string, request map[string]any) collectortest.Response {
	return withRequestBody(collectortest.Response{
		Operation: op, Method: http.MethodPost, URL: regional("cloudtrail"), Status: http.StatusBadRequest,
		Header: jsonHeader("application/x-amz-json-1.1"),
		Body:   `{"__type":"AccessDeniedException","message":"User: arn:aws:sts::111122223333:assumed-role/epack-collector/kit is not authorized to perform: ` + op + `"}`,
	}, request)
}

// runOrganizationTrail runs the kit's account with one logging organization
// trail whose ARN is arn. statusDenied and selectorsDenied refuse the reads
// of its status and of its custom event selectors.
func runOrganizationTrail(t *testing.T, arn string, statusDenied, selectorsDenied bool) orgTrailValues {
	t.Helper()
	isolateAWSEnvironment(t)
	trail := testTrail("org-trail", arn, "", true)
	trail["HasCustomEventSelectors"] = selectorsDenied
	responses := replaceResponses(kitResponses(), describeTrailsAt(regional("cloudtrail"), trail))
	if statusDenied {
		responses = append([]collectortest.Response{cloudTrailDenied("aws.cloudtrail.GetTrailStatus", map[string]any{"Name": arn})}, responses...)
	} else {
		responses = append(responses, trailStatusAt(regional("cloudtrail"), arn, true))
	}
	if selectorsDenied {
		responses = append([]collectortest.Response{cloudTrailDenied("aws.cloudtrail.GetEventSelectors", map[string]any{"TrailName": arn})}, responses...)
	}
	res := runKit(t, kitConfig(), kitSecrets(), responses)
	var doc struct {
		Accounts []struct {
			AccountSecurity struct {
				CloudTrail orgTrailValues `json:"cloudtrail"`
			} `json:"account_security"`
		} `json:"accounts"`
	}
	decodeArtifact(t, res, awsPath, &doc)
	ct := doc.Accounts[0].AccountSecurity.CloudTrail
	if len(ct.Trails) != 1 {
		t.Fatalf("trails = %+v, want 1", ct.Trails)
	}
	return ct
}

// A member account may be kept from reading its organization's trail, so a
// denied read of that trail counts it as logging. The organization trail
// that the account owns gets no such inference.
func TestCloudTrail_DeniedReadOfOrganizationTrail(t *testing.T) {
	ownTrailARN := "arn:aws:cloudtrail:us-east-1:" + kitAccountID + ":trail/org-trail"
	for _, tc := range []struct {
		name                          string
		arn                           string
		statusDenied, selectorsDenied bool
		wantInferred                  bool
	}{
		{"own trail, status denied", ownTrailARN, true, false, false},
		{"own trail, event selectors denied", ownTrailARN, false, true, false},
		{"member account, status denied", orgTrailARN, true, false, true},
		{"member account, event selectors denied", orgTrailARN, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct := runOrganizationTrail(t, tc.arn, tc.statusDenied, tc.selectorsDenied)
			if tc.statusDenied && ct.Trails[0].TrailStatusInferred != tc.wantInferred {
				t.Errorf("trail_status_inferred = %v, want %v", ct.Trails[0].TrailStatusInferred, tc.wantInferred)
			}
			logging := ct.Enabled != nil && *ct.Enabled && ct.OrganizationTrailEnabled != nil && *ct.OrganizationTrailEnabled
			if logging != tc.wantInferred {
				t.Errorf("enabled = %s, organization_trail_enabled = %s, want both true only for a member account", showBool(ct.Enabled), showBool(ct.OrganizationTrailEnabled))
			}
		})
	}
}
