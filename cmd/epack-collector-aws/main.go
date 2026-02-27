// epack-collector-aws collects AWS account security posture.
//
// This binary is designed to be executed by the epack collector runner.
// It uses the epack Component SDK for protocol compliance.
package main

import (
	"github.com/locktivity/epack-collector-aws/internal/collector"
	"github.com/locktivity/epack/componentsdk"
)

// Version is set at build time via -ldflags
var Version = "dev"

func main() {
	componentsdk.RunCollector(componentsdk.CollectorSpec{
		Name:        "aws",
		Version:     Version,
		Description: "Collects AWS account security posture metrics",
	}, run)
}

func run(ctx componentsdk.CollectorContext) error {
	// Build config from SDK context
	cfg := ctx.Config()
	config := collector.Config{
		Regions:    getStringSlice(cfg, "regions"),
		OnStatus:   ctx.Status,
		OnProgress: ctx.Progress,
	}

	// Parse account configuration - supports three modes:
	// 1. accounts array (multi-account)
	// 2. role_arn (single account with assume role)
	// 3. neither (use default credential chain)
	if accounts, ok := cfg["accounts"].([]any); ok && len(accounts) > 0 {
		for _, acct := range accounts {
			if acctMap, ok := acct.(map[string]any); ok {
				config.Accounts = append(config.Accounts, collector.AccountConfig{
					RoleARN:    getString(acctMap, "role_arn"),
					ExternalID: getString(acctMap, "external_id"),
				})
			}
		}
	} else if roleARN := getString(cfg, "role_arn"); roleARN != "" {
		// Single account with assume role
		config.Accounts = []collector.AccountConfig{{
			RoleARN:    roleARN,
			ExternalID: getString(cfg, "external_id"),
		}}
	}
	// If no accounts specified, collector will use default credentials

	// Create collector and collect posture
	c, err := collector.New(config)
	if err != nil {
		return componentsdk.NewConfigError("creating collector: %v", err)
	}

	output, err := c.Collect(ctx.Context())
	if err != nil {
		return componentsdk.NewNetworkError("collecting posture: %v", err)
	}

	// Emit the collected data (SDK handles protocol envelope)
	return ctx.Emit(output)
}

// getString safely extracts a string from config map
func getString(cfg map[string]any, key string) string {
	if cfg == nil {
		return ""
	}
	if v, ok := cfg[key].(string); ok {
		return v
	}
	return ""
}

// getStringSlice safely extracts a string slice from config map
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
