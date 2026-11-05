package aws

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/locktivity/epack/componentsdk"
)

// inspectorStatusClient answers BatchGetAccountStatus with body.
func inspectorStatusClient(t *testing.T, body string) *AWSClient {
	t.Helper()
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.URL.Path != "/status/batch/get" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     http.StatusText(http.StatusOK),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
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

// A scan type counts as on only when Inspector itself is on for the account.
// An account missing from the answer, or listed as failed, is an error.
func TestGetInspectorAccountStatus(t *testing.T) {
	const account = "111122223333"
	for _, tc := range []struct {
		name     string
		body     string
		want     map[string]bool
		wantCode componentsdk.Code
	}{
		{
			name: "on with ECR scanning off",
			body: `{"accounts":[{"accountId":"111122223333","state":{"status":"ENABLED"},"resourceState":{"ec2":{"status":"ENABLED"},"ecr":{"status":"DISABLED"},"lambda":{"status":"ENABLED"}}}],"failedAccounts":[]}`,
			want: map[string]bool{InspectorEC2Instance: true, InspectorECRImage: false, InspectorLambdaFunction: true},
		},
		{
			name: "suspended",
			body: `{"accounts":[{"accountId":"111122223333","state":{"status":"SUSPENDED"},"resourceState":{"ec2":{"status":"ENABLED"},"ecr":{"status":"ENABLED"},"lambda":{"status":"ENABLED"}}}],"failedAccounts":[]}`,
			want: map[string]bool{InspectorEC2Instance: false, InspectorECRImage: false, InspectorLambdaFunction: false},
		},
		{
			name:     "denied",
			body:     `{"accounts":[],"failedAccounts":[{"accountId":"111122223333","errorCode":"ACCESS_DENIED","errorMessage":"denied"}]}`,
			wantCode: componentsdk.CodePermissionDenied,
		},
		{
			name:     "another account only",
			body:     `{"accounts":[{"accountId":"444455556666","state":{"status":"ENABLED"},"resourceState":{"ec2":{"status":"ENABLED"},"ecr":{"status":"ENABLED"}}}],"failedAccounts":[]}`,
			wantCode: componentsdk.CodeInvalidResponse,
		},
	} {
		status, err := inspectorStatusClient(t, tc.body).GetInspectorAccountStatus(context.Background(), "us-east-1", account)
		if tc.wantCode != "" {
			if got := componentsdk.Classify(err); got != tc.wantCode {
				t.Errorf("%s: error %v classified %s, want %s", tc.name, err, got, tc.wantCode)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		for resourceType, want := range tc.want {
			if status.ScanEnabled[resourceType] != want {
				t.Errorf("%s: %s scanning on = %t, want %t", tc.name, resourceType, status.ScanEnabled[resourceType], want)
			}
		}
	}
}

// coverageEntry is one entry of Inspector's coverage. A resource has an entry
// for each scan type that covers it.
type coverageEntry struct {
	resourceType string
	resourceID   string
	scanType     string
	statusCode   string
}

// coverageClient answers ListCoverageStatistics from entries for account, with
// the counts grouped by resource type. It applies the request's EQUALS and
// NOT_EQUALS filters. The values of one field are alternatives, and every
// field has to match.
func coverageClient(t *testing.T, account string, entries []coverageEntry) *AWSClient {
	t.Helper()
	type stringFilter struct {
		Comparison string `json:"comparison"`
		Value      string `json:"value"`
	}
	return testClient(func(r *http.Request, body string) (string, string) {
		if r.URL.Path != "/coverage/statistics/list" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var req struct {
			FilterCriteria map[string][]stringFilter `json:"filterCriteria"`
			GroupBy        string                    `json:"groupBy"`
		}
		if err := json.Unmarshal([]byte(body), &req); err != nil {
			t.Fatalf("request body %q: %v", body, err)
		}
		if req.GroupBy != "RESOURCE_TYPE" {
			t.Errorf("groupBy = %q, want RESOURCE_TYPE", req.GroupBy)
		}
		matches := func(field, got string) bool {
			filters := req.FilterCriteria[field]
			if len(filters) == 0 {
				return true
			}
			for _, f := range filters {
				if (f.Comparison == "EQUALS" && f.Value == got) || (f.Comparison == "NOT_EQUALS" && f.Value != got) {
					return true
				}
			}
			return false
		}
		counts := map[string]int{}
		for _, e := range entries {
			if matches("accountId", account) && matches("resourceType", e.resourceType) &&
				matches("scanStatusCode", e.statusCode) && matches("scanType", e.scanType) {
				counts[e.resourceType]++
			}
		}
		keys := make([]string, 0, len(counts))
		for k := range counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		type group struct {
			Count    int    `json:"count"`
			GroupKey string `json:"groupKey"`
		}
		var out struct {
			CountsByGroup []group `json:"countsByGroup"`
			TotalCounts   int     `json:"totalCounts"`
		}
		for _, k := range keys {
			out.CountsByGroup = append(out.CountsByGroup, group{Count: counts[k], GroupKey: k})
			out.TotalCounts += counts[k]
		}
		raw, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		return "application/json", string(raw)
	})
}

// A Lambda function with code scanning on has a PACKAGE entry and a CODE
// entry in Inspector's coverage. It is one function and counts once.
func TestCountInspectorCoverageCountsEachLambdaFunctionOnce(t *testing.T) {
	const account = "111122223333"
	client := coverageClient(t, account, []coverageEntry{
		{InspectorLambdaFunction, "fn-a", "PACKAGE", "ACTIVE"},
		{InspectorLambdaFunction, "fn-a", "CODE", "ACTIVE"},
		{InspectorLambdaFunction, "fn-b", "PACKAGE", "ACTIVE"},
		{InspectorLambdaFunction, "fn-b", "CODE", "ACTIVE"},
		{InspectorLambdaFunction, "fn-c", "PACKAGE", "ACTIVE"},
		{InspectorLambdaFunction, "fn-d", "PACKAGE", "INACTIVE"},
	})

	counts, err := client.CountInspectorCoverage(context.Background(), "us-east-1", account, true)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := counts[InspectorLambdaFunction], 3; got != want {
		t.Errorf("active Lambda functions = %d, want %d (fn-a, fn-b, fn-c, each once)", got, want)
	}
}

// With one coverage entry for each resource, the counts follow the scan
// status for each resource type.
func TestCountInspectorCoverageByResourceType(t *testing.T) {
	const account = "111122223333"
	client := coverageClient(t, account, []coverageEntry{
		{InspectorLambdaFunction, "fn-a", "PACKAGE", "ACTIVE"},
		{InspectorLambdaFunction, "fn-b", "PACKAGE", "ACTIVE"},
		{InspectorLambdaFunction, "fn-c", "PACKAGE", "INACTIVE"},
		{InspectorEC2Instance, "i-1", "PACKAGE", "ACTIVE"},
		{InspectorEC2Instance, "i-2", "PACKAGE", "ACTIVE"},
		{InspectorEC2Instance, "i-3", "PACKAGE", "INACTIVE"},
		{InspectorECRImage, "img-1", "PACKAGE", "ACTIVE"},
		{InspectorECRImage, "img-2", "PACKAGE", "INACTIVE"},
	})

	active, err := client.CountInspectorCoverage(context.Background(), "us-east-1", account, true)
	if err != nil {
		t.Fatal(err)
	}
	all, err := client.CountInspectorCoverage(context.Background(), "us-east-1", account, false)
	if err != nil {
		t.Fatal(err)
	}

	for resourceType, want := range map[string]int{InspectorLambdaFunction: 2, InspectorEC2Instance: 2, InspectorECRImage: 1} {
		if active[resourceType] != want {
			t.Errorf("active %s = %d, want %d", resourceType, active[resourceType], want)
		}
	}
	for resourceType, want := range map[string]int{InspectorLambdaFunction: 3, InspectorEC2Instance: 3, InspectorECRImage: 2} {
		if all[resourceType] != want {
			t.Errorf("all %s = %d, want %d", resourceType, all[resourceType], want)
		}
	}
}
