package collector

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
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
		PublicFunctionURLCount: intPtr(0),
		Functions:              []LambdaFunctionRow{{Name: "east-1"}, {Name: "east-2"}},
	}
	b := LambdaMetrics{
		FunctionCount:          5,
		DeprecatedRuntimeCount: 2,
		PublicFunctionURLCount: intPtr(1),
		Functions:              []LambdaFunctionRow{{Name: "west-1"}},
	}
	got := mergeLambdaMetrics(a, b)
	if got.FunctionCount != 8 {
		t.Errorf("FunctionCount: expected 8, got %d", got.FunctionCount)
	}
	if got.DeprecatedRuntimeCount != 3 {
		t.Errorf("DeprecatedRuntimeCount: expected 3, got %d", got.DeprecatedRuntimeCount)
	}
	if !pctIs(got.PublicFunctionURLCount, 1) {
		t.Errorf("PublicFunctionURLCount: expected 1, got %s", showPct(got.PublicFunctionURLCount))
	}
	// A count no region read stays unset rather than becoming 0.
	if got := mergeLambdaMetrics(LambdaMetrics{}, LambdaMetrics{}); got.PublicFunctionURLCount != nil {
		t.Errorf("PublicFunctionURLCount: expected unset when no region read it, got %s", showPct(got.PublicFunctionURLCount))
	}
	if len(got.Functions) != 3 {
		t.Errorf("expected 3 functions after merge, got %d", len(got.Functions))
	}
	if got.Functions[0].Name != "east-1" || got.Functions[2].Name != "west-1" {
		t.Errorf("merge did not preserve insertion order: %+v", got.Functions)
	}
}

// The deprecated runtimes follow AWS's table of deprecated runtimes, and the
// supported ones are not flagged.
func TestLambdaFunctionToRow_DeprecatedRuntimes(t *testing.T) {
	for runtime, want := range map[string]bool{
		"nodejs16.x": true, "python3.8": true, "java8": true, "dotnet6": true, "go1.x": true,
		"dotnet7": true, "provided": true, "nodejs18.x": true, "python3.9": true,
		"python3.12": false, "nodejs22.x": false, "java21": false, "provided.al2023": false, "dotnet8": false, "ruby3.3": false,
	} {
		row := lambdaFunctionToRow(aws.LambdaFunction{Name: "fn", Runtime: runtime}, "us-east-1", componentsdk.LevelAudit)
		if row.DeprecatedRuntime != want || DeprecatedLambdaRuntimes[runtime] != want {
			t.Errorf("%s: deprecated_runtime = %v, want %v", runtime, row.DeprecatedRuntime, want)
		}
	}
}

// A function can have a URL on its unpublished version and on each alias,
// and it is publicly invokable when any of them authenticates nobody.
func TestCollectLambdaMetrics_PublicURLOnAnyConfig(t *testing.T) {
	url := func(qualifier, authType string) map[string]any {
		arn := "arn:aws:lambda:us-east-1:111122223333:function:" + kitFunctionName
		if qualifier != "" {
			arn += ":" + qualifier
		}
		return map[string]any{
			"FunctionUrl": fmt.Sprintf("https://%s-%s.lambda-url.us-east-1.on.aws/", kitFunctionName, authType), "FunctionArn": arn,
			"AuthType": authType, "CreationTime": "2025-01-01T00:00:00Z", "LastModifiedTime": "2025-01-01T00:00:00Z",
		}
	}
	for _, tc := range []struct {
		name     string
		configs  []any
		public   int
		authType string
	}{
		{"one IAM URL", []any{url("", "AWS_IAM")}, 0, "AWS_IAM"},
		{"public URL listed first", []any{url("prod", "NONE"), url("", "AWS_IAM")}, 1, "NONE"},
		{"public URL on an alias listed second", []any{url("", "AWS_IAM"), url("prod", "NONE")}, 1, "NONE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lambda := runOutput(t, replaceResponses(kitResponses(),
				restResponse("aws.lambda.ListFunctionUrlConfigs", http.MethodGet, "https://lambda.us-east-1.amazonaws.com/2021-10-31/functions/"+kitFunctionName+"/urls", 0,
					kitJSON(map[string]any{"FunctionUrlConfigs": tc.configs})))).Accounts[0].Lambda
			if !pctIs(lambda.PublicFunctionURLCount, tc.public) || len(lambda.Functions) != 1 || lambda.Functions[0].FunctionURLAuthType != tc.authType {
				t.Errorf("public_function_url_count = %s, functions = %+v; want %d and auth type %s", showPct(lambda.PublicFunctionURLCount), lambda.Functions, tc.public, tc.authType)
			}
		})
	}
}

// runWithGaps runs the kit's account with config and responses and returns
// the run and its decoded detailed artifact.
func runWithGaps(t *testing.T, config map[string]any, responses []collectortest.Response) (componentsdk.InProcessResult, Output) {
	t.Helper()
	isolateAWSEnvironment(t)
	res := runKit(t, config, kitSecrets(), responses)
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	var out Output
	decodeArtifact(t, res, awsPath, &out)
	if len(out.Accounts) != 1 {
		t.Fatalf("accounts = %d, want 1", len(out.Accounts))
	}
	return res, out
}

// kitFunctionWith is the kit's one function as ListFunctions lists it, with
// mutate applied.
func kitFunctionWith(mutate func(fn map[string]any)) collectortest.Response {
	fn := map[string]any{
		"FunctionName": kitFunctionName, "FunctionArn": "arn:aws:lambda:us-east-1:111122223333:function:" + kitFunctionName,
		"Runtime": "nodejs22.x", "Role": "arn:aws:iam::111122223333:role/northwind-api", "MemorySize": 512, "Timeout": 30,
		"CodeSize": 123456, "PackageType": "Zip", "Architectures": []string{"arm64"}, "LastModified": "2025-11-15T10:00:00.000+0000",
		"KMSKeyArn": "arn:aws:kms:us-east-1:111122223333:key/" + kitKMSKeyID,
	}
	mutate(fn)
	return restResponse("aws.lambda.ListFunctions", http.MethodGet, "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions", 0, kitJSON(map[string]any{"Functions": []any{fn}}))
}

// lambdaNotFound answers a Lambda call as AWS does when its subject does not
// exist.
func lambdaNotFound(op, target string) collectortest.Response {
	return collectortest.Response{
		Operation: op, Method: http.MethodGet, URL: target, Status: http.StatusNotFound,
		Header: http.Header{"Content-Type": []string{"application/json"}, "X-Amzn-Errortype": []string{"ResourceNotFoundException"}},
		Body:   kitJSON(map[string]any{"Type": "User", "Message": "The resource you requested does not exist."}),
	}
}

// When Lambda cannot decrypt a function's environment variables, it returns
// the error in their place. env_var_names is then left out.
func TestCollectLambdaMetrics_EnvVarNamesLeftOutWhenUnreadable(t *testing.T) {
	for _, tc := range []struct {
		name        string
		environment map[string]any
		want        []string
		gap         bool
	}{
		{"unreadable", map[string]any{"Error": map[string]any{
			"ErrorCode": "AccessDeniedException", "Message": "Lambda was unable to decrypt the environment variables because KMS access was denied.",
		}}, nil, true},
		{"readable", map[string]any{"Variables": map[string]string{"TABLE_NAME": "orders", "STAGE": "prod"}}, []string{"STAGE", "TABLE_NAME"}, false},
		{"no variables", nil, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, out := runWithGaps(t, kitConfig(), replaceResponses(kitResponses(), kitFunctionWith(func(fn map[string]any) {
				if tc.environment != nil {
					fn["Environment"] = tc.environment
				}
			})))
			fns := out.Accounts[0].Lambda.Functions
			if len(fns) != 1 || fmt.Sprint(fns[0].EnvVarNames) != fmt.Sprint(tc.want) {
				t.Fatalf("functions = %+v, want one with env_var_names %v", fns, tc.want)
			}
			if gap := gapAt(res, awsPath, "/accounts/0/lambda/functions/0/env_var_names"); (gap != nil) != tc.gap {
				t.Errorf("gap at env_var_names = %+v, want one: %v", gap, tc.gap)
			}
		})
	}
}

// GetPolicy without a qualifier reads only the unqualified function's policy.
// A function whose only policy is on an alias has a resource policy. The
// kit's function has its policy on its prod alias.
func TestCollectLambdaMetrics_ResourcePolicyOnAnAlias(t *testing.T) {
	const fnURL = "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/" + kitFunctionName
	const policy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"apigateway.amazonaws.com"},"Action":"lambda:InvokeFunction"}]}`
	for _, tc := range []struct {
		name      string
		responses []collectortest.Response
		want      bool
	}{
		{"on an alias only", kitResponses(), true},
		{"on the function", replaceResponses(kitResponses(),
			restResponse("aws.lambda.GetPolicy", http.MethodGet, fnURL+"/policy", 0, kitJSON(map[string]any{"Policy": policy, "RevisionId": "kit-revision"})),
			restResponse("aws.lambda.ListAliases", http.MethodGet, fnURL+"/aliases", 0, kitJSON(map[string]any{"Aliases": []any{}}))), true},
		{"nowhere", replaceResponses(kitResponses(),
			restResponse("aws.lambda.ListAliases", http.MethodGet, fnURL+"/aliases", 0, kitJSON(map[string]any{"Aliases": []any{}}))), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, out := runWithGaps(t, kitConfig(), tc.responses)
			if fns := out.Accounts[0].Lambda.Functions; len(fns) != 1 || fns[0].HasResourcePolicy != tc.want {
				t.Errorf("functions = %+v, want has_resource_policy %v", fns, tc.want)
			}
			if gap := gapAt(res, awsPath, "/accounts/0/lambda/functions/0/has_resource_policy"); gap != nil {
				t.Errorf("unexpected gap at has_resource_policy: %+v", gap)
			}
		})
	}
}
