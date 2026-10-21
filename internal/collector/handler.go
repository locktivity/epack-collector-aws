package collector

import (
	"context"
	"time"

	"github.com/locktivity/epack-collector-aws/docs/schema"
	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// Spec describes the collector to componentsdk.RunCollector.
func Spec(version, commit string) componentsdk.CollectorSpec {
	return componentsdk.CollectorSpec{
		Name:        "aws",
		Version:     version,
		Commit:      commit,
		Description: "Collects AWS account security posture metrics",
		Timeout:     10 * time.Minute,
		Schemas:     map[string][]byte{awsPath: schema.V1},
		TraceMap:    schema.TraceMap,
	}
}

// Run is the collector's handler. It fails only for invalid configuration or
// a failed sign-in, and otherwise emits what it collected with a gap recorded
// for each value it could not read.
func Run(ctx componentsdk.CollectorContext) error {
	cfg := ctx.Config()
	config := Config{
		AuthMode: getString(cfg, "auth_mode"),
		Regions:  getStringSlice(cfg, "regions"),
		Accounts: accountsFromConfig(cfg),
		OIDC: aws.OIDCEnv{
			RequestURL:   ctx.Secret(aws.GitHubTokenRequestURLEnv),
			RequestToken: ctx.Secret(aws.GitHubTokenRequestTokenEnv),
			TokenFile:    ctx.Secret(aws.WebIdentityTokenFileEnv),
		},
		Recorder:   componentsdk.Records(ctx),
		Now:        func() time.Time { return componentsdk.Now(ctx).UTC() },
		Wait:       func(_ context.Context, d time.Duration) error { return componentsdk.Wait(ctx, d) },
		OnStatus:   ctx.Status,
		OnProgress: ctx.Progress,
	}
	var tokenHosts []string
	if host := config.OIDC.CredentialHost(); host != "" {
		tokenHosts = append(tokenHosts, host)
	}
	config.HTTPClient = componentsdk.NewHTTPClient(ctx, aws.HTTPOptions(tokenHosts...))

	c, err := New(config)
	if err != nil {
		return componentsdk.NewConfigError("creating collector: %v", err)
	}
	output, err := c.Collect(ctx.Context(), ctx.Level())
	if err != nil {
		return err
	}
	return ctx.Emit(c.Artifacts(output))
}

// accountsFromConfig reads the accounts to collect: the accounts list, or a
// single role_arn, or none, which collects the default credentials' account.
func accountsFromConfig(cfg map[string]any) []AccountConfig {
	if accounts, ok := cfg["accounts"].([]any); ok && len(accounts) > 0 {
		var out []AccountConfig
		for _, acct := range accounts {
			if acctMap, ok := acct.(map[string]any); ok {
				out = append(out, AccountConfig{
					RoleARN:    getString(acctMap, "role_arn"),
					ExternalID: getString(acctMap, "external_id"),
					Label:      getString(acctMap, "label"),
				})
			}
		}
		return out
	}
	if roleARN := getString(cfg, "role_arn"); roleARN != "" {
		return []AccountConfig{{
			RoleARN:    roleARN,
			ExternalID: getString(cfg, "external_id"),
			Label:      getString(cfg, "label"),
		}}
	}
	return nil
}

func getString(cfg map[string]any, key string) string {
	if cfg == nil {
		return ""
	}
	if v, ok := cfg[key].(string); ok {
		return v
	}
	return ""
}

func getStringSlice(cfg map[string]any, key string) []string {
	if cfg == nil {
		return nil
	}
	if v, ok := cfg[key].([]any); ok {
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// Artifacts returns the detailed and normalized artifacts for output. Every
// value a gap covers is left out of the detailed artifact, and each
// normalized value derived from one is left out with the same gap.
func (c *Collector) Artifacts(output *Output) []componentsdk.CollectedArtifact {
	normalized := c.cloudPosture(output)
	// The literal holds output itself because epack sdk map reads the
	// artifact's type from it to trace each field to the code that sets it.
	detailed := componentsdk.CollectedArtifact{Data: output, Path: awsPath}
	if doc, err := c.gaps.leaveOutCovered(awsPath, output); err == nil {
		detailed.Data = doc
	}
	return []componentsdk.CollectedArtifact{
		detailed,
		{
			Data:   normalized,
			Schema: cloudPostureSchema,
			Path:   cloudPosturePath,
		},
	}
}
