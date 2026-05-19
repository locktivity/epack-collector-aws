package collector

import (
	"testing"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

func TestSSMParameterToRow_AuditOmitsInternalFields(t *testing.T) {
	modified := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	in := aws.SSMParameter{
		Name:             "/prod/db/host",
		Type:             "String",
		DataType:         "text",
		Version:          7,
		Tier:             "Standard",
		Description:      "Postgres prod host endpoint",
		KMSKeyARN:        "alias/aws/ssm",
		LastModifiedDate: &modified,
		LastModifiedUser: "arn:aws:iam::123:user/alice",
	}
	row := ssmParameterToRow(in, "us-east-1", "123", componentsdk.LevelAudit)

	if row.Name != "/prod/db/host" || row.Region != "us-east-1" {
		t.Errorf("audit base fields mis-projected: %+v", row)
	}
	if row.ARN != "arn:aws:ssm:us-east-1:123:parameter/prod/db/host" {
		t.Errorf("ARN mis-constructed: %q", row.ARN)
	}
	if row.LastModifiedDate != "2026-05-14T10:00:00Z" {
		t.Errorf("expected RFC3339 last_modified_date, got %q", row.LastModifiedDate)
	}
	// String type → HasCustomerKMS is false regardless of KMSKeyARN.
	if row.HasCustomerKMS {
		t.Errorf("HasCustomerKMS should be false for non-SecureString")
	}
	// Internal-only fields must be omitted at audit level.
	if row.Description != "" || row.KMSKeyARN != "" {
		t.Errorf("audit-level row must omit Description / KMSKeyARN: %+v", row)
	}
}

func TestSSMParameterToRow_LegacyNameNoLeadingSlash(t *testing.T) {
	// Pre-2017 parameters could have names without leading slashes.
	in := aws.SSMParameter{Name: "legacy"}
	row := ssmParameterToRow(in, "us-east-1", "123", componentsdk.LevelAudit)
	if row.ARN != "arn:aws:ssm:us-east-1:123:parameter/legacy" {
		t.Errorf("legacy-name ARN should prepend /: got %q", row.ARN)
	}
}

func TestSSMParameterToRow_SecureStringCustomerKMS(t *testing.T) {
	in := aws.SSMParameter{
		Name:      "/prod/api/key",
		Type:      "SecureString",
		KMSKeyARN: "arn:aws:kms:us-east-1:123:key/abc-def-123",
	}
	row := ssmParameterToRow(in, "us-east-1", "123", componentsdk.LevelAudit)
	if !row.HasCustomerKMS {
		t.Errorf("SecureString with customer KMS ARN should set HasCustomerKMS=true")
	}
}

func TestSSMParameterToRow_SecureStringAWSManaged(t *testing.T) {
	in := aws.SSMParameter{
		Name:      "/prod/api/key",
		Type:      "SecureString",
		KMSKeyARN: "alias/aws/ssm",
	}
	row := ssmParameterToRow(in, "us-east-1", "123", componentsdk.LevelAudit)
	if row.HasCustomerKMS {
		t.Errorf("SecureString with alias/aws/ssm should set HasCustomerKMS=false")
	}
}

func TestSSMParameterToRow_InternalPopulatesDescriptionAndKMSARN(t *testing.T) {
	in := aws.SSMParameter{
		Name:        "/prod/api/key",
		Type:        "SecureString",
		Description: "Stripe production API key",
		KMSKeyARN:   "arn:aws:kms:us-east-1:123:key/abc",
	}
	row := ssmParameterToRow(in, "us-east-1", "123", componentsdk.LevelInternal)
	if row.Description != "Stripe production API key" {
		t.Errorf("internal must populate Description, got %q", row.Description)
	}
	if row.KMSKeyARN != "arn:aws:kms:us-east-1:123:key/abc" {
		t.Errorf("internal must populate KMSKeyARN, got %q", row.KMSKeyARN)
	}
}

func TestIsCustomerKMS(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "empty (AWS default)", in: "", want: false},
		{name: "AWS-managed alias", in: "alias/aws/ssm", want: false},
		{name: "AWS-managed alias (other)", in: "alias/aws/s3", want: false},
		{name: "customer alias", in: "alias/my-key", want: true},
		{name: "customer key ARN", in: "arn:aws:kms:us-east-1:123:key/abc", want: true},
		{name: "customer key UUID", in: "abc-def-123", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCustomerKMS(tt.in); got != tt.want {
				t.Errorf("isCustomerKMS(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestMergeSSMParametersMetrics_SumsAggregatesAndConcatsParameters(t *testing.T) {
	a := SSMParametersMetrics{
		ParameterCount:                       3,
		SecureStringCount:                    1,
		SecureStringsWithoutCustomerKMSCount: 1,
		Parameters:                           []SSMParameterRow{{Name: "/east-1"}, {Name: "/east-2"}},
	}
	b := SSMParametersMetrics{
		ParameterCount:                       5,
		SecureStringCount:                    3,
		SecureStringsWithoutCustomerKMSCount: 0,
		Parameters:                           []SSMParameterRow{{Name: "/west-1"}},
	}
	got := mergeSSMParametersMetrics(a, b)
	if got.ParameterCount != 8 {
		t.Errorf("ParameterCount: expected 8, got %d", got.ParameterCount)
	}
	if got.SecureStringCount != 4 {
		t.Errorf("SecureStringCount: expected 4, got %d", got.SecureStringCount)
	}
	if got.SecureStringsWithoutCustomerKMSCount != 1 {
		t.Errorf("SecureStringsWithoutCustomerKMSCount: expected 1, got %d", got.SecureStringsWithoutCustomerKMSCount)
	}
	if len(got.Parameters) != 3 {
		t.Errorf("expected 3 parameters after merge, got %d", len(got.Parameters))
	}
}
