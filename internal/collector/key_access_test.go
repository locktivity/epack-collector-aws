package collector

import (
	"context"
	"errors"
	"testing"

	"github.com/locktivity/epack/componentsdk"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

// The policy documents the evaluator tests read, as AWS writes the managed
// ones.
const (
	adminDocument     = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	denyAllDocument   = `{"Version":"2012-10-17","Statement":{"Sid":"DenyEverything","Effect":"Deny","Action":"*","Resource":"*"}}`
	powerUserDocument = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:*","organizations:*","account:*"],"Resource":"*"},` +
		`{"Effect":"Allow","Action":["iam:CreateServiceLinkedRole","iam:ListRoles","organizations:DescribeOrganization"],"Resource":"*"}]}`
	readDocument  = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:Get*","s3:List*","ec2:Describe*","dynamodb:Query"],"Resource":"*"}]}`
	writeDocument = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::northwind-app/*"}]}`
)

func statementsOf(t *testing.T, documents ...string) []policyStatement {
	t.Helper()
	var out []policyStatement
	for _, d := range documents {
		statements, err := parsePolicy(d)
		if err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		out = append(out, statements...)
	}
	return out
}

// sourceDeny is the usual deny of every action from outside sources, and
// sourceAllow an allow of every action from inside them.
func sourceDeny(sources string) string {
	return `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"NotIpAddress":{"aws:SourceIp":` + sources + `}}}}`
}

func sourceAllow(sources string) string {
	return `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":` + sources + `}}}}`
}

// conditional is a statement of effect over every action and resource with
// condition.
func conditional(effect, condition string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"` + effect + `","Action":"*","Resource":"*","Condition":` + condition + `}]}`
}

// Full access is an allow of every action on every resource that no deny
// takes back. A key can write with full access or any allow of an action
// that is not read-only. A deny of everything with no condition leaves it
// nothing, and an IP limit, by a deny from outside a set of addresses or a
// source condition on every allow, keeps full access from being
// unrestricted. A set with 0.0.0.0/0 or ::/0 in it limits nothing.
func TestEvaluateKeyPolicies(t *testing.T) {
	for _, tc := range []struct {
		name                string
		documents           []string
		readOnly            bool
		unrestricted, write bool
	}{
		{"administrator", []string{adminDocument}, false, true, true},
		{"read-only actions", []string{readDocument}, false, false, false},
		{"AWS managed read-only policy", nil, true, false, false},
		{"write on one bucket", []string{writeDocument}, false, false, true},
		{"every action but IAM", []string{powerUserDocument}, false, false, true},
		{"service wildcard", []string{`{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`}, false, false, true},
		{"no policy", nil, false, false, false},
		{"deny of everything", []string{adminDocument, denyAllDocument}, false, false, false},
		{"deny of IAM", []string{adminDocument, `{"Statement":{"Effect":"Deny","Action":"iam:*","Resource":"*"}}`}, false, false, true},
		{"deny with a condition not evaluated", []string{adminDocument, conditional("Deny", `{"StringNotEquals":{"aws:RequestedRegion":"us-east-1"}}`)}, false, false, true},
		{"allow with a condition not evaluated", []string{conditional("Allow", `{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}`)}, false, true, true},
		{"deny from outside a set", []string{adminDocument, sourceDeny(`["10.0.0.0/8","192.0.2.0/24"]`)}, false, false, true},
		{"allow from inside a set", []string{sourceAllow(`"10.0.0.0/8"`)}, false, false, true},
		{"deny from outside every address", []string{adminDocument, sourceDeny(`["10.0.0.0/8","0.0.0.0/0"]`)}, false, true, true},
		{"allow from inside every address", []string{sourceAllow(`["::/0"]`)}, false, true, true},
		{"one allow from anywhere", []string{sourceAllow(`"10.0.0.0/8"`), readDocument}, false, true, true},
		{"read-only policy beside a limited allow", []string{sourceAllow(`"10.0.0.0/8"`)}, true, true, true},
		{"allow only with MFA", []string{conditional("Allow", `{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`)}, false, false, false},
		{"allow only with recent MFA", []string{conditional("Allow", `{"NumericLessThan":{"aws:MultiFactorAuthAge":3600}}`)}, false, false, false},
		{"allow with MFA if present", []string{conditional("Allow", `{"BoolIfExists":{"aws:MultiFactorAuthPresent":true}}`)}, false, true, true},
		{"deny without MFA if present", []string{adminDocument, conditional("Deny", `{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}`)}, false, false, false},
		{"deny without MFA", []string{adminDocument, conditional("Deny", `{"Bool":{"aws:MultiFactorAuthPresent":"false"}}`)}, false, true, true},
		{"deny when MFA age is absent", []string{adminDocument, conditional("Deny", `{"Null":{"aws:MultiFactorAuthAge":"true"}}`)}, false, false, false},
		{"deny of nothing", []string{adminDocument, `{"Statement":{"Effect":"Deny","NotAction":"*","Resource":"*"}}`}, false, true, true},
		{"allow on some resources", []string{`{"Statement":{"Effect":"Allow","Action":"*","NotResource":"arn:aws:s3:::audit-logs/*"}}`}, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := evaluateKeyPolicies(statementsOf(t, tc.documents...), tc.readOnly)
			if got.unrestricted() != tc.unrestricted || got.write != tc.write {
				t.Errorf("unrestricted %t, write %t; want %t and %t", got.unrestricted(), got.write, tc.unrestricted, tc.write)
			}
		})
	}
}

// An action is read-only when its name after the service prefix starts with
// a read verb before any wildcard, in any case.
func TestWrites(t *testing.T) {
	for action, want := range map[string]bool{
		"s3:GetObject": false, "s3:Get*": false, "ec2:describeinstances": false, "dynamodb:BatchGetItem": false,
		"cloudtrail:LookupEvents": false, "aws-portal:ViewBilling": false,
		"s3:*": true, "*": true, "s3:G*": true, "iam:PassRole": true, "s3:*Object": true, "sqs:ReceiveMessage": true,
	} {
		if got := writes(action); got != want {
			t.Errorf("writes(%q) = %t, want %t", action, got, want)
		}
	}
}

// A document that does not follow the policy grammar is an invalid
// response.
func TestParsePolicy_Invalid(t *testing.T) {
	if _, err := parsePolicy(`{"Statement":"everything"}`); componentsdk.Classify(err) != componentsdk.CodeInvalidResponse {
		t.Errorf("err = %v, want an invalid response", err)
	}
}

// fakeKeyPolicies answers the admin check's listings from fakeAdminPolicies
// and the documents and boundaries from maps, and counts the document reads.
type fakeKeyPolicies struct {
	fakeAdminPolicies
	managed, userInline, groupInline map[string]string
	boundary                         map[string]string
	fail                             map[string]error
	reads                            map[string]int
}

func (f *fakeKeyPolicies) read(key string, documents map[string]string) (string, error) {
	if f.reads == nil {
		f.reads = map[string]int{}
	}
	f.reads[key]++
	if err := f.fail[key]; err != nil {
		return "", err
	}
	return documents[key], nil
}

func (f *fakeKeyPolicies) GetPolicyDocument(_ context.Context, arn string) (string, error) {
	return f.read(arn, f.managed)
}

func (f *fakeKeyPolicies) GetUserPolicyDocument(_ context.Context, user, name string) (string, error) {
	return f.read(user+"/"+name, f.userInline)
}

func (f *fakeKeyPolicies) GetGroupPolicyDocument(_ context.Context, group, name string) (string, error) {
	return f.read(group+"/"+name, f.groupInline)
}

func (f *fakeKeyPolicies) GetUserPermissionsBoundary(_ context.Context, user string) (string, error) {
	if err := f.fail["boundary/"+user]; err != nil {
		return "", err
	}
	return f.boundary[user], nil
}

func keyAccessFrom(client iamPolicyClient, report *aws.CredentialReport) iamKeyAccess {
	c := newTestCollector(Config{})
	return collectKeyAccess(newIAMPolicies(context.Background(), client, c.policiesWarn("111122223333")), report)
}

const (
	kitAdminARN    = "arn:aws:iam::aws:policy/AdministratorAccess"
	kitPowerARN    = "arn:aws:iam::aws:policy/PowerUserAccess"
	kitDeployARN   = "arn:aws:iam::111122223333:policy/deploy"
	readOnlyGovARN = "arn:aws-us-gov:iam::aws:policy/ReadOnlyAccess"
)

// Each key counts by its user's policies: attached to the user or a group,
// at their default version, and inline. The root user's keys are
// unrestricted and can write. A read-only AWS managed policy is not read,
// and each document is read once however many users have it.
func TestCollectKeyAccess(t *testing.T) {
	client := &fakeKeyPolicies{
		fakeAdminPolicies: fakeAdminPolicies{
			user: map[string][]string{
				"admin":    {kitAdminARN},
				"reader":   {readOnlyGovARN},
				"deployer": {kitDeployARN},
				"office":   {kitAdminARN},
			},
			userInline: map[string][]string{"office": {"office-only"}},
			groupsOf:   map[string][]string{"locked": {"no-access"}, "power": {"developers"}, "power2": {"developers"}},
			group:      map[string][]string{"no-access": {kitAdminARN}, "developers": {kitPowerARN}},
			groupInline: map[string][]string{
				"no-access": {"deny-all"},
			},
		},
		managed: map[string]string{kitAdminARN: adminDocument, kitPowerARN: powerUserDocument, kitDeployARN: writeDocument},
		userInline: map[string]string{
			"office/office-only": sourceDeny(`"203.0.113.0/24"`),
		},
		groupInline: map[string]string{"no-access/deny-all": denyAllDocument},
	}
	report := reportOf(
		aws.CredentialReportUser{User: "admin", AccessKey1Active: true, AccessKey2Active: true},
		aws.CredentialReportUser{User: "reader", AccessKey1Active: true},
		aws.CredentialReportUser{User: "deployer", AccessKey2Active: true},
		aws.CredentialReportUser{User: "office", AccessKey1Active: true},
		aws.CredentialReportUser{User: "locked", AccessKey1Active: true},
		aws.CredentialReportUser{User: "power", AccessKey1Active: true},
		aws.CredentialReportUser{User: "power2", AccessKey1Active: true},
		aws.CredentialReportUser{User: "no-keys", PasswordEnabled: true},
	)
	report.Users[0].AccessKey1Active = true

	got := keyAccessFrom(client, report)

	// root's key and admin's two are unrestricted. office's key has full
	// access from one range only.
	if !got.read || got.unrestricted != 3 || got.unknownUnrestricted != 0 {
		t.Errorf("unrestricted %d, unknown %d; want 3 and 0", got.unrestricted, got.unknownUnrestricted)
	}
	// Every key but reader's and locked's can write.
	if got.write != 7 || got.unknownWrite != 0 || got.err != nil {
		t.Errorf("write %d, unknown %d, err %v; want 7, 0, and none", got.write, got.unknownWrite, got.err)
	}
	if client.reads[readOnlyGovARN] != 0 {
		t.Error("ReadOnlyAccess was read")
	}
	for key, n := range client.reads {
		if n != 1 {
			t.Errorf("%s read %d times, want once", key, n)
		}
	}
}

// A user with a permissions boundary has its keys left unknown on a value
// its identity policies allow, since the boundary may take it back, and
// known on one they do not allow. A failed read leaves the user's keys
// unknown unless the policies read decide: a deny of everything decides
// both, and a deny that takes back full access decides that the key is not
// unrestricted. The first failure is the reason, ahead of a boundary.
func TestCollectKeyAccess_UnknownKeys(t *testing.T) {
	denied := componentsdk.CodeError(componentsdk.CodePermissionDenied, errors.New("AccessDenied"))
	client := &fakeKeyPolicies{
		fakeAdminPolicies: fakeAdminPolicies{
			user: map[string][]string{
				"bounded-admin":  {kitAdminARN},
				"bounded-reader": {readOnlyGovARN},
				"bounded-power":  {kitPowerARN},
				"unread":         {kitDeployARN},
				"denied-locked":  {kitDeployARN},
				"denied-narrow":  {kitDeployARN},
			},
			userInline: map[string][]string{"denied-locked": {"deny-all"}, "denied-narrow": {"no-iam"}},
		},
		managed: map[string]string{kitAdminARN: adminDocument, kitPowerARN: powerUserDocument},
		userInline: map[string]string{
			"denied-locked/deny-all": denyAllDocument,
			"denied-narrow/no-iam":   `{"Statement":{"Effect":"Deny","Action":"iam:*","Resource":"*"}}`,
		},
		boundary: map[string]string{
			"bounded-admin": "arn:aws:iam::111122223333:policy/boundary", "bounded-reader": "arn:aws:iam::111122223333:policy/boundary",
			"bounded-power": "arn:aws:iam::111122223333:policy/boundary",
		},
		fail: map[string]error{kitDeployARN: denied},
	}

	bounded := keyAccessFrom(client, reportOf(
		aws.CredentialReportUser{User: "bounded-admin", AccessKey1Active: true},
		aws.CredentialReportUser{User: "bounded-reader", AccessKey1Active: true},
		aws.CredentialReportUser{User: "bounded-power", AccessKey1Active: true},
	))
	if bounded.unrestricted != 0 || bounded.unknownUnrestricted != 1 || bounded.write != 0 || bounded.unknownWrite != 2 {
		t.Errorf("unrestricted %d (%d unknown), write %d (%d unknown); want 0 (1) and 0 (2)",
			bounded.unrestricted, bounded.unknownUnrestricted, bounded.write, bounded.unknownWrite)
	}
	if !errors.Is(bounded.err, errBoundaryNotEvaluated) {
		t.Errorf("err = %v, want the boundary's", bounded.err)
	}

	failed := keyAccessFrom(client, reportOf(
		aws.CredentialReportUser{User: "bounded-admin", AccessKey1Active: true},
		aws.CredentialReportUser{User: "unread", AccessKey1Active: true},
		aws.CredentialReportUser{User: "denied-locked", AccessKey1Active: true},
		aws.CredentialReportUser{User: "denied-narrow", AccessKey1Active: true},
	))
	if failed.unrestricted != 0 || failed.unknownUnrestricted != 2 || failed.write != 0 || failed.unknownWrite != 3 {
		t.Errorf("unrestricted %d (%d unknown), write %d (%d unknown); want 0 (2) and 0 (3)",
			failed.unrestricted, failed.unknownUnrestricted, failed.write, failed.unknownWrite)
	}
	if !errors.Is(failed.err, denied) {
		t.Errorf("err = %v, want the denial", failed.err)
	}
}

// Without the credential report there are no keys to evaluate.
func TestCollectKeyAccess_NoReport(t *testing.T) {
	if keyAccessFrom(&fakeKeyPolicies{}, nil).read {
		t.Error("read = true without a credential report")
	}
}
