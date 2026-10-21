package collector

import (
	"errors"
	"net/http"
	"testing"

	"github.com/aws/smithy-go"
	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

const kitCaller = "User: arn:aws:sts::111122223333:assumed-role/epack-collector/kit is not authorized to perform: "

func TestPermissionOptions(t *testing.T) {
	denied := func(message string) error {
		return componentsdk.CodeError(componentsdk.CodePermissionDenied, &smithy.GenericAPIError{Code: "AccessDenied", Message: message})
	}
	cases := []struct {
		name        string
		err         error
		warning     string
		missingPerm string
	}{
		{
			name:        "no identity-based policy allows it",
			err:         denied(kitCaller + "iam:ListRoles on resource: * because no identity-based policy allows the iam:ListRoles action"),
			warning:     "Allow iam:ListRoles in the collector's IAM policy.",
			missingPerm: "iam:ListRoles",
		},
		{
			name:        "no reason given",
			err:         denied(kitCaller + "iam:ListRoles on resource: *"),
			warning:     "Allow iam:ListRoles in the collector's IAM policy.",
			missingPerm: "iam:ListRoles",
		},
		{
			name:        "no service control policy allows it",
			err:         denied(kitCaller + "guardduty:ListDetectors because no service control policy allows the guardduty:ListDetectors action"),
			warning:     "Allow guardduty:ListDetectors in the organization's service control policies.",
			missingPerm: "guardduty:ListDetectors",
		},
		{
			name:        "no permissions boundary allows it",
			err:         denied(kitCaller + "kms:ListKeys because no permissions boundary allows the kms:ListKeys action"),
			warning:     "Allow kms:ListKeys in the collector's permissions boundary.",
			missingPerm: "kms:ListKeys",
		},
		{
			name:        "a kind of policy named as AWS names it",
			err:         denied(kitCaller + "ssm:DescribeParameters because no VPC endpoint policy allows the ssm:DescribeParameters action"),
			warning:     "Allow ssm:DescribeParameters in the VPC endpoint policy.",
			missingPerm: "ssm:DescribeParameters",
		},
		{
			name:    "explicit deny in a service control policy",
			err:     denied(kitCaller + "ec2:DescribeFlowLogs with an explicit deny in a service control policy: arn:aws:organizations::111122223333:policy/o-exampleorgid/service_control_policy/p-examplepolicyid"),
			warning: "A service control policy denies ec2:DescribeFlowLogs, and an explicit deny overrides any allow.",
		},
		{
			name:    "explicit deny in a permissions boundary",
			err:     denied(kitCaller + "s3:GetBucketPolicy on resource: \"arn:aws:s3:::northwind-logs\" with an explicit deny in a permissions boundary"),
			warning: "A permissions boundary denies s3:GetBucketPolicy, and an explicit deny overrides any allow.",
		},
		{name: "denied without an action", err: denied("Access Denied")},
		{name: "not a denial", err: componentsdk.CodeError(componentsdk.CodeVendorError, errors.New(kitCaller+"iam:ListRoles"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &componentsdk.Recorder{}
			rec.NotCollected(componentsdk.Location{Path: awsPath, Pointer: "/accounts/0/iam/roles"}, tc.err, permissionOptions(tc.err)...)
			g := rec.Gaps()[0]
			if g.Warning != tc.warning || g.MissingPermission != tc.missingPerm {
				t.Errorf("warning %q, missing permission %q; want %q, %q", g.Warning, g.MissingPermission, tc.warning, tc.missingPerm)
			}
		})
	}
}

// iamDenied answers an IAM call as AWS does when the collector's policy
// refuses it, with message's account of why after the action.
func iamDenied(op, action, why string) collectortest.Response {
	return collectortest.Response{
		Operation: op, Method: http.MethodPost, URL: kitIAMURL, Status: http.StatusForbidden, Header: xmlHeader(),
		Body: "<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>" + kitCaller + action + " on resource: * " + why +
			"</Message></Error><RequestId>kit-request</RequestId></ErrorResponse>",
	}
}

// A gap AWS denied names the call it denied, the IAM action to allow, and
// where, and the normalized value copied from it carries the same.
func TestDeniedGapsNameTheirCallAndPermission(t *testing.T) {
	isolateAWSEnvironment(t)
	res := runKit(t, kitConfig(), kitSecrets(), replaceResponses(kitResponses(),
		iamDenied("aws.iam.GenerateCredentialReport", "iam:GenerateCredentialReport", "because no identity-based policy allows the iam:GenerateCredentialReport action"),
		iamDenied("aws.iam.GetAccountPasswordPolicy", "iam:GetAccountPasswordPolicy", "with an explicit deny in a service control policy"),
	))
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	for _, at := range []struct{ path, pointer string }{
		{awsPath, "/accounts/0/iam/mfa_enabled"},
		{awsPath, "/accounts/0/iam/mfa_enabled_user_count"},
		{cloudPosturePath, "/accounts/0/iam/mfa_coverage_pct"},
	} {
		g := gapAt(res, at.path, at.pointer)
		switch {
		case g == nil:
			t.Errorf("%s %s: no gap", at.path, at.pointer)
		case g.Code != componentsdk.CodePermissionDenied || g.Operation != "aws.iam.GenerateCredentialReport" || g.Call == 0:
			t.Errorf("%s %s: code %s, operation %q, call %d; want permission_denied naming a GenerateCredentialReport call", at.path, at.pointer, g.Code, g.Operation, g.Call)
		case g.MissingPermission != "iam:GenerateCredentialReport" || g.Warning != "Allow iam:GenerateCredentialReport in the collector's IAM policy.":
			t.Errorf("%s %s: missing permission %q, warning %q", at.path, at.pointer, g.MissingPermission, g.Warning)
		}
	}
	g := gapAt(res, awsPath, "/accounts/0/iam/password_policy")
	switch {
	case g == nil:
		t.Fatal("password_policy: no gap")
	case g.Operation != "aws.iam.GetAccountPasswordPolicy" || g.Call == 0:
		t.Errorf("password_policy: operation %q, call %d; want a GetAccountPasswordPolicy call", g.Operation, g.Call)
	case g.MissingPermission != "" || g.Warning != "A service control policy denies iam:GetAccountPasswordPolicy, and an explicit deny overrides any allow.":
		t.Errorf("password_policy: missing permission %q, warning %q; want the deny named and no permission to grant", g.MissingPermission, g.Warning)
	}
	for _, g := range res.Result.Gaps {
		if g.Operation == "" || g.Call == 0 {
			t.Errorf("the gap at %s %s names no call", g.Path, g.Pointer)
		}
	}
}
