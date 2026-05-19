package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/smithy-go"
)

// parseLambdaTime parses Lambda's LastModified format. AWS returns it as
// "2024-05-14T10:00:00.000+0000" — not quite RFC3339 (trailing offset is
// "+0000" instead of "Z" or "+00:00"). Try the documented format first, then
// fall back to RFC3339Nano for forward compatibility if AWS ever fixes it.
func parseLambdaTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05.000-0700",
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

// ListLambdaFunctions returns all Lambda functions in the given region. Env
// var VALUES are explicitly dropped at this SDK→struct boundary; only the
// names are surfaced so secret material cannot leak into the artifact.
func (c *AWSClient) ListLambdaFunctions(ctx context.Context, region string) ([]LambdaFunction, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := lambda.NewFromConfig(cfg)

	var functions []LambdaFunction
	paginator := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing lambda functions in %s: %w", region, err)
		}
		for _, f := range out.Functions {
			functions = append(functions, projectLambdaFunction(f))
		}
	}
	return functions, nil
}

func projectLambdaFunction(f lambdatypes.FunctionConfiguration) LambdaFunction {
	row := LambdaFunction{
		Name:        aws.ToString(f.FunctionName),
		ARN:         aws.ToString(f.FunctionArn),
		Runtime:     string(f.Runtime),
		MemorySize:  int(aws.ToInt32(f.MemorySize)),
		Timeout:     int(aws.ToInt32(f.Timeout)),
		PackageType: string(f.PackageType),
		CodeSize:    f.CodeSize,
		RoleARN:     aws.ToString(f.Role),
		KMSKeyARN:   aws.ToString(f.KMSKeyArn),
	}

	for _, a := range f.Architectures {
		row.Architectures = append(row.Architectures, string(a))
	}
	for _, layer := range f.Layers {
		row.LayerARNs = append(row.LayerARNs, aws.ToString(layer.Arn))
	}
	if f.VpcConfig != nil && (len(f.VpcConfig.SubnetIds) > 0 || len(f.VpcConfig.SecurityGroupIds) > 0) {
		row.HasVPCConfig = true
	}
	if f.DeadLetterConfig != nil {
		row.DeadLetterARN = aws.ToString(f.DeadLetterConfig.TargetArn)
	}
	if f.Environment != nil && len(f.Environment.Variables) > 0 {
		// KEYS ONLY. Values intentionally discarded — see type doc.
		names := make([]string, 0, len(f.Environment.Variables))
		for k := range f.Environment.Variables {
			names = append(names, k)
		}
		sort.Strings(names) // stable order for diffing across packs
		row.EnvVarNames = names
	}
	if ts := f.LastModified; ts != nil && *ts != "" {
		if parsed := parseLambdaTime(*ts); parsed != nil {
			row.LastModified = parsed
		}
	}
	return row
}

// LambdaFunctionHasResourcePolicy returns true if the function has a
// resource-based policy attached. GetPolicy returns ResourceNotFoundException
// when no policy exists; that's the most common case and is treated as a clean
// "no policy" rather than an error.
func (c *AWSClient) LambdaFunctionHasResourcePolicy(ctx context.Context, region, functionName string) (bool, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := lambda.NewFromConfig(cfg)

	_, err := client.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: aws.String(functionName)})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "ResourceNotFoundException" {
			return false, nil
		}
		return false, fmt.Errorf("getting policy for lambda %s: %w", functionName, err)
	}
	return true, nil
}

// LambdaFunctionURLAuthType returns whether the function has any function URLs
// configured and the auth type of the first one. Functions with no URLs return
// (false, "", nil). AuthType "NONE" indicates a publicly invokable URL — the
// posture-relevant case.
func (c *AWSClient) LambdaFunctionURLAuthType(ctx context.Context, region, functionName string) (bool, string, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := lambda.NewFromConfig(cfg)

	out, err := client.ListFunctionUrlConfigs(ctx, &lambda.ListFunctionUrlConfigsInput{
		FunctionName: aws.String(functionName),
	})
	if err != nil {
		return false, "", fmt.Errorf("listing function urls for %s: %w", functionName, err)
	}
	if len(out.FunctionUrlConfigs) == 0 {
		return false, "", nil
	}
	return true, string(out.FunctionUrlConfigs[0].AuthType), nil
}
