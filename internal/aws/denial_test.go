package aws

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aws/smithy-go"
)

func TestDenialOf(t *testing.T) {
	const user = "User: arn:aws:sts::111122223333:assumed-role/epack-collector/1761040000000000000"
	cases := []struct {
		name    string
		message string
		want    Denial
		ok      bool
	}{
		{
			name:    "no identity-based policy allows it",
			message: user + " is not authorized to perform: iam:GenerateCredentialReport on resource: * because no identity-based policy allows the iam:GenerateCredentialReport action",
			want:    Denial{Action: "iam:GenerateCredentialReport", NotAllowedBy: "identity-based policy"},
			ok:      true,
		},
		{
			name:    "no service control policy allows it",
			message: user + " is not authorized to perform: guardduty:ListDetectors because no service control policy allows the guardduty:ListDetectors action",
			want:    Denial{Action: "guardduty:ListDetectors", NotAllowedBy: "service control policy"},
			ok:      true,
		},
		{
			name:    "explicit deny in a service control policy",
			message: user + " is not authorized to perform: ec2:DescribeFlowLogs with an explicit deny in a service control policy",
			want:    Denial{Action: "ec2:DescribeFlowLogs", ExplicitIn: "a service control policy"},
			ok:      true,
		},
		{
			name:    "explicit deny naming the policy",
			message: user + " is not authorized to perform: s3:GetBucketPolicy on resource: \"arn:aws:s3:::northwind-logs\" with an explicit deny in a service control policy: arn:aws:organizations::111122223333:policy/o-exampleorgid/service_control_policy/p-examplepolicyid",
			want:    Denial{Action: "s3:GetBucketPolicy", ExplicitIn: "a service control policy"},
			ok:      true,
		},
		{
			name:    "explicit deny in a permissions boundary",
			message: user + " is not authorized to perform: kms:DescribeKey on resource: arn:aws:kms:us-east-1:111122223333:key/1234abcd with an explicit deny in a permissions boundary",
			want:    Denial{Action: "kms:DescribeKey", ExplicitIn: "a permissions boundary"},
			ok:      true,
		},
		{
			name:    "explicit deny in an identity-based policy",
			message: user + " is not authorized to perform: iam:ListRoles on resource: * with an explicit deny in an identity-based policy",
			want:    Denial{Action: "iam:ListRoles", ExplicitIn: "an identity-based policy"},
			ok:      true,
		},
		{
			name:    "EC2's sentence first",
			message: "You are not authorized to perform this operation. " + user + " is not authorized to perform: ec2:DescribeVpcs because no identity-based policy allows the ec2:DescribeVpcs action",
			want:    Denial{Action: "ec2:DescribeVpcs", NotAllowedBy: "identity-based policy"},
			ok:      true,
		},
		{
			name:    "no reason given",
			message: user + " is not authorized to perform: iam:GetAccountSummary on resource: *",
			want:    Denial{Action: "iam:GetAccountSummary"},
			ok:      true,
		},
		{name: "no action named", message: "Access Denied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := fmt.Errorf("listing: %w", &smithy.GenericAPIError{Code: "AccessDenied", Message: tc.message})
			got, ok := DenialOf(err)
			if ok != tc.ok || got != tc.want {
				t.Errorf("DenialOf() = %+v, %t; want %+v, %t", got, ok, tc.want, tc.ok)
			}
		})
	}
	if _, ok := DenialOf(errors.New("not authorized to perform: iam:ListUsers")); ok {
		t.Error("an error that is not AWS's named a denial")
	}
}
