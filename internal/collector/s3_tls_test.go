package collector

import "testing"

// The canonical enforcement statement, as AWS documents it and Terraform
// modules generate it.
const canonicalDeny = `{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyInsecureTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::intake", "arn:aws:s3:::intake/*"],
    "Condition": {"Bool": {"aws:SecureTransport": "false"}}
  }]
}`

func TestClassifyTransportEnforcement(t *testing.T) {
	tests := []struct {
		name     string
		document string
		want     string
	}{
		{name: "canonical deny", document: canonicalDeny, want: tlsEnforcementEnforced},
		{
			name: "resource wildcard",
			document: `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*",
				"Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`,
			want: tlsEnforcementEnforced,
		},
		{
			name: "principal as AWS map with star",
			document: `{"Statement":[{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"s3:*",
				"Resource":["arn:aws:s3:::intake","arn:aws:s3:::intake/*"],
				"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`,
			want: tlsEnforcementEnforced,
		},
		{
			name: "bare boolean false and lowercase operator",
			document: `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*",
				"Resource":["arn:aws:s3:::intake","arn:aws:s3:::intake/*"],
				"Condition":{"bool":{"AWS:SecureTransport":false}}}]}`,
			want: tlsEnforcementEnforced,
		},
		{
			name: "BoolIfExists is equivalent because the key always exists",
			document: `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*",
				"Resource":["arn:aws:s3:::intake","arn:aws:s3:::intake/*"],
				"Condition":{"BoolIfExists":{"aws:SecureTransport":"false"}}}]}`,
			want: tlsEnforcementEnforced,
		},
		{
			name: "single statement object rather than array",
			document: `{"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:*",
				"Resource":["arn:aws:s3:::intake","arn:aws:s3:::intake/*"],
				"Condition":{"Bool":{"aws:SecureTransport":"false"}}}}`,
			want: tlsEnforcementEnforced,
		},
		{
			name: "gov-cloud partition matches by suffix",
			document: `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*",
				"Resource":["arn:aws-us-gov:s3:::intake","arn:aws-us-gov:s3:::intake/*"],
				"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`,
			want: tlsEnforcementEnforced,
		},
		{
			name: "objects-only resource leaves bucket operations uncovered",
			document: `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*",
				"Resource":"arn:aws:s3:::intake/*",
				"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`,
			want: tlsEnforcementPartial,
		},
		{
			name: "action subset covers only some requests",
			document: `{"Statement":[{"Effect":"Deny","Principal":"*","Action":["s3:GetObject","s3:PutObject"],
				"Resource":["arn:aws:s3:::intake","arn:aws:s3:::intake/*"],
				"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`,
			want: tlsEnforcementPartial,
		},
		{
			name: "scoped principal covers only one caller",
			document: `{"Statement":[{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::755677838352:role/battery-service-role"},"Action":"s3:*",
				"Resource":["arn:aws:s3:::intake","arn:aws:s3:::intake/*"],
				"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`,
			want: tlsEnforcementPartial,
		},
		{
			name: "an extra condition narrows the deny",
			document: `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*",
				"Resource":["arn:aws:s3:::intake","arn:aws:s3:::intake/*"],
				"Condition":{"Bool":{"aws:SecureTransport":"false"},"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`,
			want: tlsEnforcementPartial,
		},
		{
			name: "NotAction form is never conclusive",
			document: `{"Statement":[{"Effect":"Deny","Principal":"*","NotAction":"s3:ListBucket",
				"Resource":["arn:aws:s3:::intake","arn:aws:s3:::intake/*"],
				"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`,
			want: tlsEnforcementPartial,
		},
		{
			name: "deny scoped to a different bucket's resources",
			document: `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*",
				"Resource":["arn:aws:s3:::other","arn:aws:s3:::other/*"],
				"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`,
			want: tlsEnforcementPartial,
		},
		{
			name: "allow with the transport condition enforces nothing",
			document: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject",
				"Resource":"arn:aws:s3:::intake/*",
				"Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`,
			want: tlsEnforcementNone,
		},
		{
			name: "deny of secure transport is pathological, not enforcement",
			document: `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*",
				"Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`,
			want: tlsEnforcementNone,
		},
		{
			name: "policy with only unrelated statements",
			document: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::755677838352:role/battery-service-role"},
				"Action":"s3:PutObject","Resource":"arn:aws:s3:::intake/*"}]}`,
			want: tlsEnforcementNone,
		},
		{name: "malformed document", document: `{"Statement":[`, want: tlsEnforcementUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyTransportEnforcement(tt.document, "intake"); got != tt.want {
				t.Fatalf("classifyTransportEnforcement() = %q, want %q", got, tt.want)
			}
		})
	}
}

// A conclusive statement anywhere in the policy wins even when partial ones
// precede it.
func TestClassifyTransportEnforcementConclusiveBeatsPartial(t *testing.T) {
	document := `{"Statement":[
		{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::intake/*",
		 "Condition":{"Bool":{"aws:SecureTransport":"false"}}},
		{"Effect":"Deny","Principal":"*","Action":"s3:*",
		 "Resource":["arn:aws:s3:::intake","arn:aws:s3:::intake/*"],
		 "Condition":{"Bool":{"aws:SecureTransport":"false"}}}
	]}`

	if got := classifyTransportEnforcement(document, "intake"); got != tlsEnforcementEnforced {
		t.Fatalf("classifyTransportEnforcement() = %q, want enforced", got)
	}
}
