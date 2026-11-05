package aws

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// listFindingsCriteria are the findingCriteria the ListFindings API reference
// lists, apart from the resource.* and service.action.* fields. The GuardDuty
// filter guide lists service.additionalInfo.sample among the fields that work
// only in suppression rules.
var listFindingsCriteria = map[string]bool{
	"accountId": true, "region": true, "confidence": true, "id": true,
	"service.additionalInfo.threatListName": true, "service.archived": true,
	"service.ebsVolumeScanDetails.scanId": true, "service.resourceRole": true,
	"severity": true, "type": true, "updatedAt": true,
}

func listFindingsAccepts(key string) bool {
	return listFindingsCriteria[key] || strings.HasPrefix(key, "resource.") || strings.HasPrefix(key, "service.action.")
}

// guardDutyListFindingsClient answers one region's GuardDuty with one enabled
// detector and no findings. ListFindings fails with a 400 for a criterion
// listFindingsAccepts does not accept.
func guardDutyListFindingsClient(t *testing.T) *AWSClient {
	t.Helper()
	reply := func(r *http.Request, status int, body string) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Status:     http.StatusText(status),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    r,
		}, nil
	}
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/detector":
			return reply(r, 200, `{"detectorIds":["det1"]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/detector/det1":
			return reply(r, 200, `{"status":"ENABLED","findingPublishingFrequency":"SIX_HOURS","features":[]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/detector/det1/findings":
			var req struct {
				FindingCriteria struct {
					Criterion map[string]json.RawMessage `json:"criterion"`
				} `json:"findingCriteria"`
			}
			raw, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(raw, &req); err != nil {
				return nil, err
			}
			for key := range req.FindingCriteria.Criterion {
				if !listFindingsAccepts(key) {
					return reply(r, 400, `{"message":"invalid criterion `+key+`","__type":"BadRequestException"}`)
				}
			}
			return reply(r, 200, `{"findingIds":[]}`)
		}
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		return reply(r, 404, `{}`)
	})
	cfg := aws.Config{
		Region:      DefaultRegionAWS,
		Credentials: credentials.NewStaticCredentialsProvider("AKIDKITEXAMPLE", "kit-secret", ""),
		HTTPClient:  &http.Client{Transport: rt},
	}
	return newAWSClient(cfg, "", Options{})
}

func TestListGuardDutyDetectors_CountsUseListFindingsCriteria(t *testing.T) {
	detectors, err := guardDutyListFindingsClient(t).ListGuardDutyDetectors(context.Background(), "us-east-1", "111122223333")
	if err != nil {
		t.Fatal(err)
	}
	if len(detectors) != 1 {
		t.Fatalf("detectors = %d, want 1", len(detectors))
	}
	if err := detectors[0].FindingsErr; err != nil {
		t.Errorf("high or critical count failed: %v", err)
	}
	if err := detectors[0].StaleFindingsErr; err != nil {
		t.Errorf("stale count failed: %v", err)
	}
}

func TestListGuardDutyFindings_UsesListFindingsCriteria(t *testing.T) {
	if _, _, err := guardDutyListFindingsClient(t).ListGuardDutyFindings(context.Background(), "us-east-1", "det1", "111122223333", 5000); err != nil {
		t.Errorf("listing findings failed: %v", err)
	}
}

// GetFindings returns a finding's additionalInfo as a type and a JSON value.
// A generated sample finding has "sample": true in that value.
func TestGuardDutySampleInfo(t *testing.T) {
	for value, want := range map[string]bool{
		`{"threatListName":"GeneratedFindingThreatListName","sample":true}`: true,
		`{"threatListName":"ProofPoint"}`:                                   false,
		`{"sample":false}`:                                                  false,
		``:                                                                  false,
	} {
		if got := guardDutySampleInfo(value); got != want {
			t.Errorf("guardDutySampleInfo(%q) = %v, want %v", value, got, want)
		}
	}
}
