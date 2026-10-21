package collector

import (
	"context"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// collectLambdaMetrics collects Lambda posture for a single region. At audit
// level or higher, per-function follow-up calls (GetPolicy, ListFunctionUrlConfigs)
// populate the corresponding flags; a failure of either leaves those flags
// out with a warning.
func (c *Collector) collectLambdaMetrics(ctx context.Context, client *aws.AWSClient, region, accountID string, level componentsdk.Level) (*LambdaMetrics, error) {
	functions, err := client.ListLambdaFunctions(ctx, region)
	if err != nil {
		return nil, err
	}

	out := &LambdaMetrics{
		FunctionCount: len(functions),
	}
	for _, f := range functions {
		if DeprecatedLambdaRuntimes[f.Runtime] {
			out.DeprecatedRuntimeCount++
		}
	}

	if !level.AtLeast(componentsdk.LevelAudit) {
		return out, nil
	}

	publicURLs := 0
	out.Functions = make([]LambdaFunctionRow, 0, len(functions))
	for _, f := range functions {
		row := lambdaFunctionToRow(f, region, level)

		hasPolicy, err := client.LambdaFunctionHasResourcePolicy(ctx, region, f.Name)
		if err != nil {
			c.warn("account %s region %s lambda %s: failed to get resource policy: %v", accountID, region, f.Name, err)
			row.missing.add(err, "has_resource_policy")
		} else {
			row.HasResourcePolicy = hasPolicy
		}

		hasURL, authType, err := client.LambdaFunctionURLAuthType(ctx, region, f.Name)
		if err != nil {
			c.warn("account %s region %s lambda %s: failed to get function URL config: %v", accountID, region, f.Name, err)
			row.missing.add(err, "has_function_url", "function_url_auth_type")
			out.missing.addPartial(err, 1, "public_function_url_count")
		} else {
			row.HasFunctionURL = hasURL
			row.FunctionURLAuthType = authType
			if hasURL && authType == "NONE" {
				publicURLs++
			}
		}

		out.Functions = append(out.Functions, row)
	}
	out.PublicFunctionURLCount = &publicURLs

	return out, nil
}

// lambdaFunctionToRow projects an aws.LambdaFunction onto its audit-level row.
// Internal-level fields (role/KMS/layers/env var KEYS/architectures/package_type)
// are populated when level >= internal — no extra API calls; we already have
// the data from the ListFunctions response.
func lambdaFunctionToRow(f aws.LambdaFunction, region string, level componentsdk.Level) LambdaFunctionRow {
	row := LambdaFunctionRow{
		Name:              f.Name,
		Region:            region,
		Runtime:           f.Runtime,
		MemorySize:        f.MemorySize,
		Timeout:           f.Timeout,
		CodeSize:          f.CodeSize,
		HasVPCConfig:      f.HasVPCConfig,
		DeprecatedRuntime: DeprecatedLambdaRuntimes[f.Runtime],
	}
	if f.LastModified != nil {
		row.LastModified = f.LastModified.UTC().Format(time.RFC3339)
	}
	if level.AtLeast(componentsdk.LevelInternal) {
		row.ARN = f.ARN
		row.RoleARN = f.RoleARN
		row.KMSKeyARN = f.KMSKeyARN
		row.PackageType = f.PackageType
		row.DeadLetterARN = f.DeadLetterARN
		if len(f.Architectures) > 0 {
			row.Architectures = append([]string(nil), f.Architectures...)
		}
		if len(f.LayerARNs) > 0 {
			row.LayerARNs = append([]string(nil), f.LayerARNs...)
		}
		if len(f.EnvVarNames) > 0 {
			row.EnvVarNames = append([]string(nil), f.EnvVarNames...)
		}
	}
	return row
}

// mergeLambdaMetrics combines per-region results into a single fleet-wide
// metric block. Trust aggregates sum directly; audit rows concatenate. The
// cap is applied by the caller after all regions have been merged.
func mergeLambdaMetrics(a, b LambdaMetrics) LambdaMetrics {
	merged := LambdaMetrics{
		FunctionCount:          a.FunctionCount + b.FunctionCount,
		DeprecatedRuntimeCount: a.DeprecatedRuntimeCount + b.DeprecatedRuntimeCount,
		PublicFunctionURLCount: sumCounts(a.PublicFunctionURLCount, b.PublicFunctionURLCount),
		Functions:              append(append([]LambdaFunctionRow(nil), a.Functions...), b.Functions...),
		missing:                a.missing,
	}
	merged.missing.merge(b.missing)
	return merged
}
