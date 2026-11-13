package collector

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// simContractItems names, for each driven call whose answer is a list, the
// path to the list's items, which the contract compares by count.
var simContractItems = map[string][]string{
	"aws.ec2.DescribeSecurityGroups":         {"DescribeSecurityGroupsResponse", "securityGroupInfo", "item"},
	"aws.s3.ListBuckets":                     {"ListAllMyBucketsResult", "Buckets", "Bucket"},
	"aws.cloudtrail.DescribeTrails":          {"trailList"},
	"aws.identitystore.ListUsers":            {"Users"},
	"aws.identitystore.ListGroups":           {"Groups"},
	"aws.identitystore.ListGroupMemberships": {"GroupMemberships"},
	"aws.iam.ListMFADevices":                 {"ListMFADevicesResponse", "ListMFADevicesResult", "MFADevices", "member"},
	"aws.iam.ListSAMLProviders":              {"ListSAMLProvidersResponse", "ListSAMLProvidersResult", "SAMLProviderList", "member"},
	"aws.iam.ListRoles":                      {"ListRolesResponse", "ListRolesResult", "Roles", "member"},
	"aws.kms.ListKeys":                       {"Keys"},
	"aws.rds.DescribeDBInstances":            {"DescribeDBInstancesResponse", "DescribeDBInstancesResult", "DBInstances", "DBInstance"},
}

// simContractOptions line the simulator's answers up with the recording's.
// The vocabulary fields are the ones the roster decides, whose values the
// simulator must spell as AWS does.
var simContractOptions = collectortest.CompareOptions{
	Vocabulary: []string{
		"[].groupName[]",
		"[].ipPermissions[].item[].ipProtocol[]",
		"[].ipPermissions[].item[].fromPort[]",
		"[].ipPermissions[].item[].toPort[]",
		"[].ipPermissions[].item[].ipRanges[].item[].cidrIp[]",
		"[].ipPermissions[].item[].ipv6Ranges[].item[].cidrIpv6[]",
		"[].Name[]", "[].BucketRegion[]",
		"[].Name", "[].HomeRegion", "[].IsMultiRegionTrail", "[].HasCustomEventSelectors", "[].IncludeGlobalServiceEvents", "[].S3BucketName",
		"IsLogging",
		"PublicAccessBlockConfiguration.BlockPublicAcls[]", "PublicAccessBlockConfiguration.IgnorePublicAcls[]",
		"PublicAccessBlockConfiguration.BlockPublicPolicy[]", "PublicAccessBlockConfiguration.RestrictPublicBuckets[]",
		"Error.Code[]",
		"ServerSideEncryptionConfiguration.Rule[].ApplyServerSideEncryptionByDefault[].SSEAlgorithm[]",
		"ServerSideEncryptionConfiguration.Rule[].BucketKeyEnabled[]",
		"LocationConstraint.#text",
		"[].UserName", "[].DisplayName", "[].UserStatus",
		"[].UserName[]",
		"[].user", "[].password_enabled", "[].mfa_active", "[].access_key_1_active", "[].access_key_2_active", "[].cert_1_active", "[].cert_2_active",
		"AccountMFAEnabled", "AccountPasswordPresent", "AccountAccessKeysPresent", "AccountSigningCertificatesPresent", "Users", "MFADevicesInUse",
		"GetCallerIdentityResponse.GetCallerIdentityResult[].Account[]",
	},
}

// simContractKnown lists the ways the simulator is known to differ from
// the recording, as each difference's String, with why it is left.
var simContractKnown = map[string]string{
	"POST iam.amazonaws.com/GetAccountSummary AccountPasswordPresent: values (recorded 1, simulated 0)":         simRootPassword,
	"POST iam.amazonaws.com/GetCredentialReport [].password_enabled: values (recorded true, simulated nothing)": simRootPassword,
}

// simRootPassword says why the root user's password differs.
const simRootPassword = "The roster gives the root user no login, and the sandbox's root user has a password. Root has MFA, so no derived value turns on it."

// TestSimulatorMatchesRecording compares the simulator's answers for the
// sandbox roster with the recording, so the simulator cannot drift from
// AWS unseen: a field, type, vocabulary value or count it gets wrong
// fails here, in the change that brings a new recording. Only the calls
// the roster drives are compared, since the rest are the recording's. A
// Query or JSON protocol call is lined up by its operation and the fields
// of its request, as all of a service's calls go to one URL. A list's
// items are compared by count, and the credential report and account
// summary by their rows and entries.
func TestSimulatorMatchesRecording(t *testing.T) {
	isolateAWSEnvironment(t)
	rec := loadSimRecording(t)
	r := simBase(t)
	keep := func(responses []collectortest.Response, rewrite func(collectortest.Response) collectortest.Response) []collectortest.Response {
		var out []collectortest.Response
		for _, resp := range responses {
			if !simDriven[resp.Operation] && !simDriven[resp.Operation+"/"+simPathPrefix(resp)] && !strings.HasPrefix(resp.Operation, "aws.s3.") {
				continue
			}
			out = append(out, simContractForm(t, rewrite(resp)))
		}
		return out
	}
	sim := newAWSSim(t, r, rec, rec.at)
	recorded := keep(rec.responses, func(resp collectortest.Response) collectortest.Response {
		return (&awsSim{account: &r.Cloud.Accounts[0]}).rewrite(resp)
	})
	simulated := keep(sim, func(resp collectortest.Response) collectortest.Response { return resp })
	seen := map[string]bool{}
	for _, d := range collectortest.CompareResponses(recorded, simulated, simContractOptions) {
		if d.Kind == collectortest.OnlySimulated {
			continue
		}
		seen[d.String()] = true
		if why, known := simContractKnown[d.String()]; known {
			t.Logf("known: %s (%s)", d, why)
			continue
		}
		t.Errorf("%s", d)
	}
	for _, d := range slices.Sorted(maps.Keys(simContractKnown)) {
		if !seen[d] {
			t.Errorf("listed as known, but the simulator now matches the recording: %s", d)
		}
	}
}

// simContractForm gives a response the URL and body the contract lines it
// up by.
func simContractForm(t *testing.T, r collectortest.Response) collectortest.Response {
	t.Helper()
	u, err := url.Parse(r.URL)
	if err != nil {
		t.Fatal(err)
	}
	var request map[string]any
	_ = json.Unmarshal([]byte(r.RequestBody), &request)
	if !strings.HasPrefix(r.Operation, "aws.s3.") && !strings.HasPrefix(r.Operation, "aws.s3control.") {
		u.Path = strings.TrimSuffix(u.Path, "/") + "/" + actionOf(r.Operation)
		q := url.Values{}
		for k, v := range request {
			if k != "Action" && k != "Version" {
				q.Set(k, fmt.Sprint(v))
			}
		}
		u.RawQuery = q.Encode()
	}
	r.URL = u.String()
	var body map[string]any
	if err := json.Unmarshal([]byte(r.Body), &body); err != nil {
		return r
	}
	switch path, ok := simContractItems[r.Operation]; {
	case r.Operation == "aws.iam.GetCredentialReport":
		r.Body = simJSON(simReportRows(t, body))
	case r.Operation == "aws.iam.GetAccountSummary":
		entries := map[string]any{}
		for _, e := range simFirst(body, "GetAccountSummaryResponse", "GetAccountSummaryResult", "SummaryMap")["entry"].([]any) {
			m := e.(map[string]any)
			entries[m["key"].([]any)[0].(string)] = m["value"].([]any)[0]
		}
		r.Body = simJSON(entries)
	case ok:
		r.Body = simJSON(simContractList(body, path))
	}
	return r
}

// simContractList returns the items of the list at path, none when an
// element on the way is empty, as AWS sends an empty list.
func simContractList(body map[string]any, path []string) []any {
	node := any(body)
	for i, name := range path {
		m, ok := node.(map[string]any)
		if !ok {
			return []any{}
		}
		node = m[name]
		if list, ok := node.([]any); ok && i < len(path)-1 {
			if len(list) == 0 {
				return []any{}
			}
			node = list[0]
		}
	}
	items, _ := node.([]any)
	return simNonNil(items)
}

// simReportRows reads a credential report's CSV into one object a row.
func simReportRows(t *testing.T, body map[string]any) []any {
	t.Helper()
	content := simFirst(body, "GetCredentialReportResponse", "GetCredentialReportResult")["Content"]
	if list, ok := content.([]any); ok {
		content = list[0]
	}
	raw, err := base64.StdEncoding.DecodeString(content.(string))
	if err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var rows []any
	for _, record := range records[1:] {
		row := map[string]any{}
		for i, column := range records[0] {
			row[column] = record[i]
		}
		rows = append(rows, row)
	}
	return rows
}
