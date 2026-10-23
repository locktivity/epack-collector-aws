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
	idstoretypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
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

// The issuer SCIM provisioning records on a user's external ID, and one a
// directory sync might set instead.
const (
	scimIssuer      = "arn:aws:identitystore::111122223333:identitystore/d-1111111111/provisioningtenant/a1b2c3d4-5678-90ab-cdef-111111111111"
	directoryIssuer = "arn:aws:ds:us-east-1:111122223333:directory/d-2222222222"
)

// Only an external ID from SCIM provisioning marks a user as coming from an
// external identity provider. Neither the ID nor its issuer is kept.
func TestListIdentityStoreUsers_KeepsSCIMExternalIDPresenceOnly(t *testing.T) {
	client := testClient(func(*http.Request, string) (string, string) {
		return jsonContentType, `{"Users":[` +
			`{"IdentityStoreId":"d-1111111111","UserId":"u-1","UserName":"dana","ExternalIds":[{"Issuer":"` + scimIssuer + `","Id":"00udana0001"}]},` +
			`{"IdentityStoreId":"d-1111111111","UserId":"u-2","UserName":"eli","ExternalIds":[{"Issuer":"` + directoryIssuer + `","Id":"S-1-5-21-1001"}]},` +
			`{"IdentityStoreId":"d-1111111111","UserId":"u-3","UserName":"fay","ExternalIds":[]},` +
			`{"IdentityStoreId":"d-1111111111","UserId":"u-4","UserName":"gus"}]}`
	})

	users, err := client.ListIdentityStoreUsers(context.Background(), DefaultRegionAWS, "d-1111111111")
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 4 {
		t.Fatalf("users = %+v, want 4", users)
	}
	for i, want := range []bool{true, false, false, false} {
		if users[i].HasExternalID != want {
			t.Errorf("%s HasExternalID = %v, want %v", users[i].UserName, users[i].HasExternalID, want)
		}
	}
}

func TestHasSCIMExternalID(t *testing.T) {
	ids := func(issuers ...string) []idstoretypes.ExternalId {
		out := make([]idstoretypes.ExternalId, 0, len(issuers))
		for _, issuer := range issuers {
			out = append(out, idstoretypes.ExternalId{Issuer: aws.String(issuer), Id: aws.String("kit-id")})
		}
		return out
	}
	cases := []struct {
		name string
		ids  []idstoretypes.ExternalId
		want bool
	}{
		{"a SCIM provisioning tenant", ids(scimIssuer), true},
		{"a SCIM provisioning tenant in upper case", ids(strings.ToUpper(scimIssuer)), true},
		{"a SCIM provisioning tenant in another partition", ids(strings.Replace(scimIssuer, "arn:aws:", "arn:aws-us-gov:", 1)), true},
		{"an issuer a directory sync might set", ids(directoryIssuer), false},
		{"the identity store without a provisioning tenant", ids("arn:aws:identitystore::111122223333:identitystore/d-1111111111"), false},
		{"an identity provider's own URL", ids("https://scim.idp.example/v2/provisioningtenant/1111"), false},
		{"an empty issuer", ids(""), false},
		{"no issuer", []idstoretypes.ExternalId{{Id: aws.String("kit-id")}}, false},
		{"no external IDs", nil, false},
		{"one of each", ids(directoryIssuer, scimIssuer), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasSCIMExternalID(tc.ids); got != tc.want {
				t.Errorf("hasSCIMExternalID = %v, want %v", got, tc.want)
			}
		})
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
