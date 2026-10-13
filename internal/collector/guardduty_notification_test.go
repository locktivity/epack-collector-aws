package collector

import (
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

func snsRule(enabled bool, topicARNs ...string) aws.GuardDutyNotificationRule {
	kinds := map[string]int{}
	if len(topicARNs) > 0 {
		kinds["sns"] = len(topicARNs)
	}
	return aws.GuardDutyNotificationRule{Name: "guardduty-findings", Enabled: enabled, TopicARNs: topicARNs, TargetsByKind: kinds}
}

// A rule that exists but tells nobody is the case this surface exists to
// catch, so each way the chain breaks is asserted separately.
func TestRuleReachesSubscriber(t *testing.T) {
	const arn = "arn:aws:sns:us-east-1:123456789012:security-alerts"

	tests := []struct {
		name  string
		rule  aws.GuardDutyNotificationRule
		reach map[string]*aws.SNSTopicSubscribers
		want  bool
	}{
		{
			name:  "enabled rule, topic attached, subscriber confirmed",
			rule:  snsRule(true, arn),
			reach: map[string]*aws.SNSTopicSubscribers{arn: topic(arn, 1, 0)},
			want:  true,
		},
		{
			name:  "disabled rule routes nothing",
			rule:  snsRule(false, arn),
			reach: map[string]*aws.SNSTopicSubscribers{arn: topic(arn, 1, 0)},
			want:  false,
		},
		{
			name: "lambda-only rule cannot be verified end to end",
			rule: aws.GuardDutyNotificationRule{Enabled: true, TargetsByKind: map[string]int{"lambda": 1}},
			want: false,
		},
		{
			name:  "topic exists but has no subscribers",
			rule:  snsRule(true, arn),
			reach: map[string]*aws.SNSTopicSubscribers{arn: topic(arn, 0, 0)},
			want:  false,
		},
		{
			name:  "subscribers are all unconfirmed, so nothing is delivered",
			rule:  snsRule(true, arn),
			reach: map[string]*aws.SNSTopicSubscribers{arn: topic(arn, 0, 2)},
			want:  false,
		},
		{
			name:  "one of several topics reaching someone is enough",
			rule:  snsRule(true, "arn:aws:sns:us-east-1:1:dead", arn),
			reach: map[string]*aws.SNSTopicSubscribers{"arn:aws:sns:us-east-1:1:dead": topic("dead", 0, 0), arn: topic(arn, 2, 0)},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ruleReachesSubscriber(tt.rule, tt.reach); got != tt.want {
				t.Fatalf("ruleReachesSubscriber() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRuleRouted(t *testing.T) {
	tests := []struct {
		name string
		rule aws.GuardDutyNotificationRule
		want bool
	}{
		{
			name: "any target kind counts as routed",
			rule: aws.GuardDutyNotificationRule{Enabled: true, TargetsByKind: map[string]int{"event_bus": 1}},
			want: true,
		},
		{
			name: "no targets is not routed",
			rule: aws.GuardDutyNotificationRule{Enabled: true, TargetsByKind: map[string]int{}},
			want: false,
		},
		{
			name: "disabled is not routed regardless of targets",
			rule: aws.GuardDutyNotificationRule{Enabled: false, TargetsByKind: map[string]int{"sns": 2}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ruleRouted(tt.rule); got != tt.want {
				t.Fatalf("ruleRouted() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyGuardDutyNotificationScan(t *testing.T) {
	const arn = "arn:aws:sns:us-east-1:123456789012:security-alerts"

	var fn GuardDutyFindingNotification

	applyGuardDutyNotificationScan(&fn, guardDutyNotificationScan{
		evaluated:      true,
		rules:          []aws.GuardDutyNotificationRule{snsRule(true, arn)},
		reach:          map[string]*aws.SNSTopicSubscribers{arn: topic(arn, 3, 1)},
		adminAccountID: "999999999999",
	}, "us-east-1", true)

	applyGuardDutyNotificationScan(&fn, guardDutyNotificationScan{
		evaluated: true,
		rules:     []aws.GuardDutyNotificationRule{{Name: "to-central-bus", Enabled: true, TargetsByKind: map[string]int{"event_bus": 1}}},
		reach:     map[string]*aws.SNSTopicSubscribers{},
	}, "eu-west-1", true)

	applyGuardDutyNotificationScan(&fn, guardDutyNotificationScan{}, "ap-southeast-2", true)

	if fn.DetectorRegionsCount != 3 || fn.DetectorRegionsEvaluatedCount != 2 || fn.DetectorRegionsUnresolvedCount != 1 {
		t.Errorf("region counts = %d/%d/%d, want 3/2/1",
			fn.DetectorRegionsCount, fn.DetectorRegionsEvaluatedCount, fn.DetectorRegionsUnresolvedCount)
	}
	if fn.DetectorRegionsRoutedCount != 2 {
		t.Errorf("DetectorRegionsRoutedCount = %d, want 2 (the bus-forwarding region is routed)", fn.DetectorRegionsRoutedCount)
	}
	if fn.DetectorRegionsReachingSubscriberCount != 1 {
		t.Errorf("DetectorRegionsReachingSubscriberCount = %d, want 1", fn.DetectorRegionsReachingSubscriberCount)
	}
	if fn.RuleCount != 2 {
		t.Errorf("RuleCount = %d, want 2", fn.RuleCount)
	}
	if fn.SubscriptionsByProtocol["email"] != 4 {
		t.Errorf("SubscriptionsByProtocol = %v, want email 4", fn.SubscriptionsByProtocol)
	}
	if fn.SubscriptionsPendingConfirmationCount != 1 {
		t.Errorf("SubscriptionsPendingConfirmationCount = %d, want 1", fn.SubscriptionsPendingConfirmationCount)
	}
	if fn.AdministratorAccountID != "999999999999" {
		t.Errorf("AdministratorAccountID = %q, want 999999999999", fn.AdministratorAccountID)
	}
	if len(fn.Rules) != 2 {
		t.Fatalf("len(Rules) = %d, want 2", len(fn.Rules))
	}
	if fn.Rules[0].Region != "us-east-1" || !fn.Rules[0].ReachesSubscriber {
		t.Errorf("Rules[0] = %+v, want us-east-1 reaching", fn.Rules[0])
	}
	if fn.Rules[1].Region != "eu-west-1" || fn.Rules[1].ReachesSubscriber {
		t.Errorf("Rules[1] = %+v, want eu-west-1 not reaching", fn.Rules[1])
	}
}

func TestApplyGuardDutyNotificationScanTrustLevelSkipsRows(t *testing.T) {
	const arn = "arn:aws:sns:us-east-1:123456789012:security-alerts"

	var fn GuardDutyFindingNotification
	applyGuardDutyNotificationScan(&fn, guardDutyNotificationScan{
		evaluated: true,
		rules:     []aws.GuardDutyNotificationRule{snsRule(true, arn)},
		reach:     map[string]*aws.SNSTopicSubscribers{arn: topic(arn, 1, 0)},
	}, "us-east-1", false)

	if fn.Rules != nil {
		t.Errorf("Rules = %v, want nil at trust level", fn.Rules)
	}
	if fn.DetectorRegionsReachingSubscriberCount != 1 {
		t.Errorf("DetectorRegionsReachingSubscriberCount = %d, want 1", fn.DetectorRegionsReachingSubscriberCount)
	}
}

func TestGuardDutyNotificationRuleToRowMarksUnresolvedTopics(t *testing.T) {
	const resolved = "arn:aws:sns:us-east-1:123456789012:security-alerts"
	const unresolved = "arn:aws:sns:us-east-1:123456789012:opaque"

	row := guardDutyNotificationRuleToRow(
		snsRule(true, resolved, unresolved),
		"us-east-1",
		map[string]*aws.SNSTopicSubscribers{resolved: topic(resolved, 2, 0)},
	)

	if len(row.Topics) != 2 {
		t.Fatalf("len(Topics) = %d, want 2", len(row.Topics))
	}
	if row.Topics[0].Unresolved || row.Topics[0].ConfirmedSubscriptionCount != 2 {
		t.Errorf("Topics[0] = %+v, want resolved with 2 confirmed", row.Topics[0])
	}
	if !row.Topics[1].Unresolved {
		t.Errorf("Topics[1] = %+v, want unresolved", row.Topics[1])
	}
	if !row.ReachesSubscriber {
		t.Error("ReachesSubscriber = false, want true via the resolved topic")
	}
}
