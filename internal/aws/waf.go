package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

const (
	WAFScopeRegional   = "REGIONAL"
	WAFScopeCloudFront = "CLOUDFRONT"

	// CLOUDFRONT-scope web ACLs are a global resource that the service only
	// answers for from us-east-1, regardless of where the collector runs.
	wafCloudFrontRegion = "us-east-1"
)

// WebACL is one WAFv2 web ACL: its rules, logging state, and (for the
// REGIONAL scope) the load balancers it protects.
type WebACL struct {
	Name          string
	Arn           string
	Scope         string // REGIONAL, CLOUDFRONT
	Region        string // empty for CLOUDFRONT scope
	DefaultAction string // allow, block

	Rules []WebACLRule

	// AssociatedALBArns holds the application load balancers this REGIONAL
	// web ACL protects. CLOUDFRONT-scope associations live on the
	// distribution side and are joined by the caller.
	AssociatedALBArns []string

	// LoggingEvaluated distinguishes "logging is off" from "the logging
	// configuration could not be read".
	LoggingEvaluated      bool
	LoggingEnabled        bool
	LoggingDestinationArn string
}

// WebACLRule is one rule's enforcement posture.
type WebACLRule struct {
	Name     string
	Priority int32

	// Action is block, allow, count, captcha, or challenge. Managed rule
	// groups carry managed (group runs its own actions) or count (group
	// overridden to count-only).
	Action string

	IsRateBased      bool
	RateLimit        int64  // requests per 5 minutes, rate-based rules only
	AggregateKeyType string // IP, FORWARDED_IP, CUSTOM_KEYS, CONSTANT

	ManagedRuleGroupName string
}

// ListWebACLs returns the web ACLs for one scope with their rules resolved.
// For the CLOUDFRONT scope the region argument is ignored and us-east-1 is
// used, as the service requires.
func (c *AWSClient) ListWebACLs(ctx context.Context, scope, region string) ([]WebACL, error) {
	client := c.wafClient(scope, region)
	summaries, err := listWebACLSummaries(ctx, client, scope)
	if err != nil {
		return nil, err
	}

	var out []WebACL
	for _, summary := range summaries {
		acl, err := buildWebACL(ctx, client, summary, scope, region)
		if err != nil {
			return nil, err
		}
		out = append(out, acl)
	}
	return out, nil
}

func (c *AWSClient) wafClient(scope, region string) *wafv2.Client {
	cfg := c.cfg.Copy()
	if scope == WAFScopeCloudFront {
		cfg.Region = wafCloudFrontRegion
	} else {
		cfg.Region = region
	}
	return wafv2.NewFromConfig(cfg)
}

func listWebACLSummaries(ctx context.Context, client *wafv2.Client, scope string) ([]wafv2types.WebACLSummary, error) {
	var summaries []wafv2types.WebACLSummary
	input := &wafv2.ListWebACLsInput{Scope: wafv2types.Scope(scope)}
	for {
		page, err := client.ListWebACLs(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("listing %s web ACLs: %w", scope, err)
		}
		summaries = append(summaries, page.WebACLs...)
		if aws.ToString(page.NextMarker) == "" {
			return summaries, nil
		}
		input.NextMarker = page.NextMarker
	}
}

// buildWebACL resolves one summary into a full row. Unreadable rules or
// associations fail the listing; the logging read degrades to unevaluated
// instead, so a missing logging permission never fails the region.
func buildWebACL(ctx context.Context, client *wafv2.Client, summary wafv2types.WebACLSummary, scope, region string) (WebACL, error) {
	acl := WebACL{
		Name:  aws.ToString(summary.Name),
		Arn:   aws.ToString(summary.ARN),
		Scope: scope,
	}
	if scope == WAFScopeRegional {
		acl.Region = region
	}

	detail, err := client.GetWebACL(ctx, &wafv2.GetWebACLInput{
		Id:    summary.Id,
		Name:  summary.Name,
		Scope: wafv2types.Scope(scope),
	})
	if err != nil {
		return WebACL{}, fmt.Errorf("reading web ACL %s: %w", acl.Name, err)
	}
	if detail.WebACL != nil {
		acl.DefaultAction = defaultActionName(detail.WebACL.DefaultAction)
		for _, rule := range detail.WebACL.Rules {
			acl.Rules = append(acl.Rules, webACLRule(rule))
		}
	}

	if scope == WAFScopeRegional {
		if acl.AssociatedALBArns, err = associatedALBArns(ctx, client, summary.ARN); err != nil {
			return WebACL{}, fmt.Errorf("listing resources for web ACL %s: %w", acl.Name, err)
		}
	}

	acl.LoggingEvaluated, acl.LoggingEnabled, acl.LoggingDestinationArn = loggingState(ctx, client, summary.ARN)
	return acl, nil
}

func defaultActionName(action *wafv2types.DefaultAction) string {
	switch {
	case action == nil:
		return ""
	case action.Block != nil:
		return "block"
	case action.Allow != nil:
		return "allow"
	}
	return ""
}

func associatedALBArns(ctx context.Context, client *wafv2.Client, arn *string) ([]string, error) {
	resources, err := client.ListResourcesForWebACL(ctx, &wafv2.ListResourcesForWebACLInput{
		WebACLArn:    arn,
		ResourceType: wafv2types.ResourceTypeApplicationLoadBalancer,
	})
	if err != nil {
		return nil, err
	}
	return resources.ResourceArns, nil
}

// loggingState reads best effort: a missing configuration means logging is
// off, and any other failure leaves the state unevaluated rather than
// failing the caller.
func loggingState(ctx context.Context, client *wafv2.Client, arn *string) (evaluated, enabled bool, destination string) {
	logging, err := client.GetLoggingConfiguration(ctx, &wafv2.GetLoggingConfigurationInput{ResourceArn: arn})
	switch {
	case err == nil:
		if logging.LoggingConfiguration != nil && len(logging.LoggingConfiguration.LogDestinationConfigs) > 0 {
			return true, true, logging.LoggingConfiguration.LogDestinationConfigs[0]
		}
		return true, false, ""
	case isWAFNonexistent(err):
		return true, false, ""
	}
	return false, false, ""
}

func webACLRule(rule wafv2types.Rule) WebACLRule {
	out := WebACLRule{
		Name:     aws.ToString(rule.Name),
		Priority: rule.Priority,
	}

	if rule.Action != nil {
		switch {
		case rule.Action.Block != nil:
			out.Action = "block"
		case rule.Action.Allow != nil:
			out.Action = "allow"
		case rule.Action.Count != nil:
			out.Action = "count"
		case rule.Action.Captcha != nil:
			out.Action = "captcha"
		case rule.Action.Challenge != nil:
			out.Action = "challenge"
		}
	}
	if rule.OverrideAction != nil {
		switch {
		case rule.OverrideAction.Count != nil:
			out.Action = "count"
		case rule.OverrideAction.None != nil:
			out.Action = "managed"
		}
	}

	if rule.Statement != nil {
		if rate := rule.Statement.RateBasedStatement; rate != nil {
			out.IsRateBased = true
			out.RateLimit = aws.ToInt64(rate.Limit)
			out.AggregateKeyType = string(rate.AggregateKeyType)
		}
		if managed := rule.Statement.ManagedRuleGroupStatement; managed != nil {
			out.ManagedRuleGroupName = aws.ToString(managed.Name)
		}
	}
	return out
}

func isWAFNonexistent(err error) bool {
	var nonexistent *wafv2types.WAFNonexistentItemException
	return errors.As(err, &nonexistent)
}
