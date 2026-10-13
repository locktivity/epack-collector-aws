package aws

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventbridgetypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
)

// GuardDutyNotificationRule is an EventBridge rule on the default bus whose
// event pattern selects GuardDuty findings, together with where its targets
// point. GuardDuty delivers findings by publishing events to the default bus
// in the detector's region; rules like these are the only routing out of it.
//
// TargetsByKind counts every target. TopicARNs additionally names the SNS
// targets so callers can resolve subscriber reach; other target kinds
// (lambda, event_bus, api_destination, sqs) are counted but not named, since
// delivery beyond the invocation is not observable from configuration.
type GuardDutyNotificationRule struct {
	Name            string
	Enabled         bool
	FiltersSeverity bool
	TopicARNs       []string
	TargetsByKind   map[string]int
}

// ListGuardDutyNotificationRules returns the default-bus EventBridge rules in
// a region whose event pattern selects GuardDuty findings.
func (c *AWSClient) ListGuardDutyNotificationRules(ctx context.Context, region string) ([]GuardDutyNotificationRule, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := eventbridge.NewFromConfig(cfg)

	rules := []GuardDutyNotificationRule{}
	var nextToken *string
	for {
		page, err := client.ListRules(ctx, &eventbridge.ListRulesInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("listing EventBridge rules in %s: %w", region, err)
		}
		for _, r := range page.Rules {
			matches, filtersSeverity := matchesGuardDutyFindings(aws.ToString(r.EventPattern))
			if !matches {
				continue
			}
			rule := GuardDutyNotificationRule{
				Name:            aws.ToString(r.Name),
				Enabled:         r.State != eventbridgetypes.RuleStateDisabled,
				FiltersSeverity: filtersSeverity,
				TargetsByKind:   map[string]int{},
			}
			if err := c.resolveRuleTargets(ctx, client, region, &rule); err != nil {
				return nil, err
			}
			rules = append(rules, rule)
		}
		if page.NextToken == nil || *page.NextToken == "" {
			return rules, nil
		}
		nextToken = page.NextToken
	}
}

func (c *AWSClient) resolveRuleTargets(ctx context.Context, client *eventbridge.Client, region string, rule *GuardDutyNotificationRule) error {
	var nextToken *string
	for {
		page, err := client.ListTargetsByRule(ctx, &eventbridge.ListTargetsByRuleInput{
			Rule:      aws.String(rule.Name),
			NextToken: nextToken,
		})
		if err != nil {
			return fmt.Errorf("listing targets for EventBridge rule %s in %s: %w", rule.Name, region, err)
		}
		for _, t := range page.Targets {
			arn := aws.ToString(t.Arn)
			rule.TargetsByKind[eventTargetKind(arn)]++
			if isSNSTopicARN(arn) {
				rule.TopicARNs = append(rule.TopicARNs, arn)
			}
		}
		if page.NextToken == nil || *page.NextToken == "" {
			return nil
		}
		nextToken = page.NextToken
	}
}

// matchesGuardDutyFindings reports whether an EventBridge event pattern
// selects GuardDuty findings, and whether it further filters on severity.
// Matching is by literal string: a source entry of "aws.guardduty" or a
// detail-type entry of "GuardDuty Finding" (either alone selects finding
// events). Prefix/wildcard matcher objects that would also select findings
// are not recognised, so an exotic pattern under-reports as no routing
// rather than over-reporting coverage that may not exist.
func matchesGuardDutyFindings(pattern string) (matches, filtersSeverity bool) {
	if pattern == "" {
		return false, false
	}
	var parsed struct {
		Source     []any          `json:"source"`
		DetailType []any          `json:"detail-type"`
		Detail     map[string]any `json:"detail"`
	}
	if err := json.Unmarshal([]byte(pattern), &parsed); err != nil {
		return false, false
	}
	if !containsLiteral(parsed.Source, "aws.guardduty") && !containsLiteral(parsed.DetailType, "GuardDuty Finding") {
		return false, false
	}
	_, filtersSeverity = parsed.Detail["severity"]
	return true, filtersSeverity
}

func containsLiteral(entries []any, want string) bool {
	for _, e := range entries {
		if s, ok := e.(string); ok && s == want {
			return true
		}
	}
	return false
}

// eventTargetKind buckets a target ARN by the service that receives the
// event. event_bus (another bus, often another account's) and
// api_destination (an external HTTPS endpoint) are both arn:aws:events
// resources, so they are told apart by resource prefix.
func eventTargetKind(arn string) string {
	switch {
	case isSNSTopicARN(arn):
		return "sns"
	case containsSegment(arn, ":lambda:"):
		return "lambda"
	case containsSegment(arn, ":events:") && containsSegment(arn, ":event-bus/"):
		return "event_bus"
	case containsSegment(arn, ":events:") && containsSegment(arn, ":api-destination/"):
		return "api_destination"
	case containsSegment(arn, ":sqs:"):
		return "sqs"
	default:
		return "other"
	}
}
