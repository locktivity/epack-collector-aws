package collector

import (
	"testing"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

func TestLambdaFunctionToRow_AuditOmitsInternalFields(t *testing.T) {
	modified := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	in := aws.LambdaFunction{
		Name:          "my-fn",
		ARN:           "arn:aws:lambda:us-east-1:123:function:my-fn",
		Runtime:       "python3.12",
		MemorySize:    256,
		Timeout:       30,
		CodeSize:      4096,
		LastModified:  &modified,
		RoleARN:       "arn:aws:iam::123:role/lambda-exec",
		KMSKeyARN:     "arn:aws:kms:us-east-1:123:key/abc",
		HasVPCConfig:  true,
		LayerARNs:     []string{"arn:aws:lambda:us-east-1:123:layer:foo:1"},
		Architectures: []string{"arm64"},
		PackageType:   "Zip",
		DeadLetterARN: "arn:aws:sqs:us-east-1:123:dlq",
		EnvVarNames:   []string{"DATABASE_URL", "API_KEY_NAME"},
	}
	row := lambdaFunctionToRow(in, "us-east-1", componentsdk.LevelAudit)
	if row.Region != "us-east-1" || row.Runtime != "python3.12" {
		t.Errorf("audit base fields mis-projected: %+v", row)
	}
	if row.LastModified != "2026-05-14T10:00:00Z" {
		t.Errorf("expected RFC3339 last_modified, got %q", row.LastModified)
	}
	if row.ARN != "" || row.RoleARN != "" || row.KMSKeyARN != "" {
		t.Errorf("audit-level row must omit internal-only ARNs: %+v", row)
	}
	if len(row.EnvVarNames) != 0 || len(row.LayerARNs) != 0 || len(row.Architectures) != 0 {
		t.Errorf("audit-level row must omit internal-only slices: %+v", row)
	}
}

func TestLambdaFunctionToRow_InternalPopulatesAllFields(t *testing.T) {
	in := aws.LambdaFunction{
		Name:          "my-fn",
		ARN:           "arn:aws:lambda:us-east-1:123:function:my-fn",
		Runtime:       "python3.12",
		RoleARN:       "arn:aws:iam::123:role/lambda-exec",
		KMSKeyARN:     "arn:aws:kms:us-east-1:123:key/abc",
		LayerARNs:     []string{"arn:aws:lambda:us-east-1:123:layer:foo:1"},
		Architectures: []string{"arm64"},
		PackageType:   "Image",
		DeadLetterARN: "arn:aws:sqs:us-east-1:123:dlq",
		EnvVarNames:   []string{"DATABASE_URL"},
	}
	row := lambdaFunctionToRow(in, "us-east-1", componentsdk.LevelInternal)
	if row.ARN == "" || row.RoleARN == "" || row.KMSKeyARN == "" {
		t.Errorf("internal-level row must populate ARNs: %+v", row)
	}
	if row.PackageType != "Image" {
		t.Errorf("PackageType mis-projected, got %q", row.PackageType)
	}
	if len(row.Architectures) != 1 || row.Architectures[0] != "arm64" {
		t.Errorf("Architectures mis-projected: %+v", row.Architectures)
	}
	if len(row.EnvVarNames) != 1 || row.EnvVarNames[0] != "DATABASE_URL" {
		t.Errorf("EnvVarNames mis-projected: %+v", row.EnvVarNames)
	}
}

func TestLambdaFunctionToRow_FlagsDeprecatedRuntime(t *testing.T) {
	row := lambdaFunctionToRow(aws.LambdaFunction{Name: "old", Runtime: "nodejs14.x"}, "us-east-1", componentsdk.LevelAudit)
	if !row.DeprecatedRuntime {
		t.Errorf("expected nodejs14.x to be flagged as deprecated")
	}

	row = lambdaFunctionToRow(aws.LambdaFunction{Name: "current", Runtime: "python3.12"}, "us-east-1", componentsdk.LevelAudit)
	if row.DeprecatedRuntime {
		t.Errorf("expected python3.12 NOT to be flagged as deprecated")
	}
}

func TestLambdaFunctionToRow_DefensiveCopyOnSlices(t *testing.T) {
	envs := []string{"DATABASE_URL"}
	in := aws.LambdaFunction{Name: "fn", EnvVarNames: envs}
	row := lambdaFunctionToRow(in, "us-east-1", componentsdk.LevelInternal)
	envs[0] = "mutated"
	if row.EnvVarNames[0] == "mutated" {
		t.Errorf("lambdaFunctionToRow did not defensively copy EnvVarNames")
	}
}

func TestMergeLambdaMetrics_SumsAggregatesAndConcatsFunctions(t *testing.T) {
	a := LambdaMetrics{
		FunctionCount:          3,
		DeprecatedRuntimeCount: 1,
		PublicFunctionURLCount: 0,
		Functions:              []LambdaFunctionRow{{Name: "east-1"}, {Name: "east-2"}},
	}
	b := LambdaMetrics{
		FunctionCount:          5,
		DeprecatedRuntimeCount: 2,
		PublicFunctionURLCount: 1,
		Functions:              []LambdaFunctionRow{{Name: "west-1"}},
	}
	got := mergeLambdaMetrics(a, b)
	if got.FunctionCount != 8 {
		t.Errorf("FunctionCount: expected 8, got %d", got.FunctionCount)
	}
	if got.DeprecatedRuntimeCount != 3 {
		t.Errorf("DeprecatedRuntimeCount: expected 3, got %d", got.DeprecatedRuntimeCount)
	}
	if got.PublicFunctionURLCount != 1 {
		t.Errorf("PublicFunctionURLCount: expected 1, got %d", got.PublicFunctionURLCount)
	}
	if len(got.Functions) != 3 {
		t.Errorf("expected 3 functions after merge, got %d", len(got.Functions))
	}
	if got.Functions[0].Name != "east-1" || got.Functions[2].Name != "west-1" {
		t.Errorf("merge did not preserve insertion order: %+v", got.Functions)
	}
}
