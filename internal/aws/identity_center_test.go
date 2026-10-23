package aws

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// roundTripFunc answers a test client's requests.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// testClient returns a client in us-east-1 whose every call gets answer's
// content type and body for the request and the body it sent.
func testClient(answer func(r *http.Request, body string) (contentType, payload string)) *AWSClient {
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		contentType, payload := answer(r, string(raw))
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     http.Header{"Content-Type": []string{contentType}},
			Body:       io.NopCloser(strings.NewReader(payload)),
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

const jsonContentType = "application/x-amz-json-1.1"

func TestListIdentityCenterInstances_PagesAndKeepsStatusAndOwner(t *testing.T) {
	var hosts []string
	client := testClient(func(r *http.Request, body string) (string, string) {
		hosts = append(hosts, r.URL.Host)
		if strings.Contains(body, `"NextToken":"page-2"`) {
			return jsonContentType, `{"Instances":[{"InstanceArn":"arn:aws:sso:::instance/ssoins-2222333344445555","IdentityStoreId":"d-2222","OwnerAccountId":"111122223333","Status":"CREATE_IN_PROGRESS"}]}`
		}
		return jsonContentType, `{"Instances":[{"InstanceArn":"arn:aws:sso:::instance/ssoins-1111222233334444","IdentityStoreId":"d-1111","OwnerAccountId":"999988887777","Status":"ACTIVE"}],"NextToken":"page-2"}`
	})

	instances, err := client.ListIdentityCenterInstances(context.Background(), "eu-west-1")
	if err != nil {
		t.Fatal(err)
	}
	want := []IdentityCenterInstance{
		{InstanceARN: "arn:aws:sso:::instance/ssoins-1111222233334444", IdentityStoreID: "d-1111", Region: "eu-west-1", Status: "ACTIVE", OwnerAccountID: "999988887777"},
		{InstanceARN: "arn:aws:sso:::instance/ssoins-2222333344445555", IdentityStoreID: "d-2222", Region: "eu-west-1", Status: "CREATE_IN_PROGRESS", OwnerAccountID: "111122223333"},
	}
	if len(instances) != len(want) {
		t.Fatalf("instances = %+v, want both pages", instances)
	}
	for i := range want {
		if instances[i] != want[i] {
			t.Errorf("instance %d = %+v, want %+v", i, instances[i], want[i])
		}
	}
	for _, host := range hosts {
		if !strings.Contains(host, "eu-west-1") {
			t.Errorf("called %s, want the region the listing was asked for", host)
		}
	}
}

func TestListIdentityCenterInstances_NoInstanceIsEmpty(t *testing.T) {
	client := testClient(func(*http.Request, string) (string, string) { return jsonContentType, `{}` })

	instances, err := client.ListIdentityCenterInstances(context.Background(), DefaultRegionAWS)
	if err != nil {
		t.Fatal(err)
	}
	if instances == nil || len(instances) != 0 {
		t.Errorf("instances = %#v, want an empty list", instances)
	}
}

// An external ID is set by an identity provider's user provisioning. Only
// whether a user has one is kept: neither the ID nor its issuer.
func TestListIdentityStoreUsers_KeepsExternalIDPresenceOnly(t *testing.T) {
	client := testClient(func(*http.Request, string) (string, string) {
		return jsonContentType, `{"Users":[` +
			`{"IdentityStoreId":"d-1111","UserId":"u-1","UserName":"dana","ExternalIds":[{"Issuer":"https://scim.idp.example/v2","Id":"00udana0001"}]},` +
			`{"IdentityStoreId":"d-1111","UserId":"u-2","UserName":"eli","ExternalIds":[]},` +
			`{"IdentityStoreId":"d-1111","UserId":"u-3","UserName":"fay"}]}`
	})

	users, err := client.ListIdentityStoreUsers(context.Background(), DefaultRegionAWS, "d-1111")
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 3 {
		t.Fatalf("users = %+v, want 3", users)
	}
	for i, want := range []bool{true, false, false} {
		if users[i].HasExternalID != want {
			t.Errorf("%s HasExternalID = %v, want %v", users[i].UserName, users[i].HasExternalID, want)
		}
	}
}

func TestListIdentityCenterPermissionSetARNs_Pages(t *testing.T) {
	client := testClient(func(_ *http.Request, body string) (string, string) {
		if strings.Contains(body, `"NextToken":"page-2"`) {
			return jsonContentType, `{"PermissionSets":["arn:aws:sso:::permissionSet/ssoins-1/ps-2"]}`
		}
		return jsonContentType, `{"PermissionSets":["arn:aws:sso:::permissionSet/ssoins-1/ps-1"],"NextToken":"page-2"}`
	})

	arns, err := client.ListIdentityCenterPermissionSetARNs(context.Background(), DefaultRegionAWS, "arn:aws:sso:::instance/ssoins-1111222233334444")
	if err != nil {
		t.Fatal(err)
	}
	if len(arns) != 2 || arns[0] != "arn:aws:sso:::permissionSet/ssoins-1/ps-1" || arns[1] != "arn:aws:sso:::permissionSet/ssoins-1/ps-2" {
		t.Errorf("arns = %v, want both pages", arns)
	}
}

// queryAction returns the action and fields of a Query protocol call's body.
func queryAction(t *testing.T, body string) url.Values {
	t.Helper()
	form, err := url.ParseQuery(body)
	if err != nil {
		t.Fatalf("parsing the request body %q: %v", body, err)
	}
	return form
}
