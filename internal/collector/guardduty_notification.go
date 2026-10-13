package collector

import (
	"context"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

// guardDutyNotificationScan holds one detector region's finding-routing
// results: matching rules and, for their SNS targets, subscriber reach.
// evaluated is false when the rule listing itself failed, which the
// aggregates report as unresolved rather than unrouted.
type guardDutyNotificationScan struct {
	evaluated        bool
	rules            []aws.GuardDutyNotificationRule
	reach            map[string]*aws.SNSTopicSubscribers
	topicsUnresolved int
	adminAccountID   string
}

// scanGuardDutyNotificationRegion resolves how findings leave one region.
// Runs only for regions with a detector: findings publish to the default bus
// of the region that raised them, so rules elsewhere route nothing.
func (c *Collector) scanGuardDutyNotificationRegion(ctx context.Context, client *aws.AWSClient, region, accountID, detectorID string) guardDutyNotificationScan {
	var s guardDutyNotificationScan

	adminID, err := client.GetGuardDutyAdministratorAccount(ctx, region, detectorID)
	if err != nil {
		c.warn("account %s region %s: failed to read GuardDuty administrator account: %v", accountID, region, err)
	}
	s.adminAccountID = adminID

	s.rules, err = client.ListGuardDutyNotificationRules(ctx, region)
	if err != nil {
		c.warn("account %s region %s: failed to list GuardDuty notification rules: %v", accountID, region, err)
		return s
	}
	s.evaluated = true

	// One lookup per distinct topic, not per rule: rules commonly share one.
	s.reach = map[string]*aws.SNSTopicSubscribers{}
	for _, rule := range s.rules {
		for _, topic := range rule.TopicARNs {
			if _, seen := s.reach[topic]; seen {
				continue
			}
			subs, subErr := client.GetSNSTopicSubscribers(ctx, region, topic)
			if subErr != nil {
				c.warn("account %s region %s: failed to read SNS subscribers: %v", accountID, region, subErr)
				s.topicsUnresolved++
				continue
			}
			s.reach[topic] = subs
		}
	}
	return s
}

// applyGuardDutyNotificationScan folds one detector region's scan into the
// account summary, appending audit rows when includeRows is set.
func applyGuardDutyNotificationScan(fn *GuardDutyFindingNotification, s guardDutyNotificationScan, region string, includeRows bool) {
	fn.DetectorRegionsCount++
	if fn.AdministratorAccountID == "" {
		fn.AdministratorAccountID = s.adminAccountID
	}
	if !s.evaluated {
		fn.DetectorRegionsUnresolvedCount++
		return
	}
	fn.DetectorRegionsEvaluatedCount++
	fn.RuleCount += len(s.rules)
	fn.TopicsUnresolvedCount += s.topicsUnresolved

	regionRouted, regionReaches := false, false
	for _, rule := range s.rules {
		if ruleRouted(rule) {
			regionRouted = true
		}
		if ruleReachesSubscriber(rule, s.reach) {
			regionReaches = true
		}
	}
	if regionRouted {
		fn.DetectorRegionsRoutedCount++
	}
	if regionReaches {
		fn.DetectorRegionsReachingSubscriberCount++
	}

	for _, subs := range s.reach {
		fn.SubscriptionsPendingConfirmationCount += subs.PendingConfirmation
		for protocol, count := range subs.ByProtocol {
			if fn.SubscriptionsByProtocol == nil {
				fn.SubscriptionsByProtocol = map[string]int{}
			}
			fn.SubscriptionsByProtocol[protocol] += count
		}
	}

	if includeRows {
		for _, rule := range s.rules {
			fn.Rules = append(fn.Rules, guardDutyNotificationRuleToRow(rule, region, s.reach))
		}
	}
}

// ruleRouted reports whether the rule sends findings anywhere at all:
// enabled, with at least one target of any kind.
func ruleRouted(rule aws.GuardDutyNotificationRule) bool {
	if !rule.Enabled {
		return false
	}
	for _, count := range rule.TargetsByKind {
		if count > 0 {
			return true
		}
	}
	return false
}

// ruleReachesSubscriber reports whether the rule would actually notify a
// person or system: enabled, an SNS target, and that topic holding at least
// one confirmed subscriber.
func ruleReachesSubscriber(rule aws.GuardDutyNotificationRule, reach map[string]*aws.SNSTopicSubscribers) bool {
	if !rule.Enabled {
		return false
	}
	for _, topic := range rule.TopicARNs {
		if subs, ok := reach[topic]; ok && subs.Confirmed > 0 {
			return true
		}
	}
	return false
}

func guardDutyNotificationRuleToRow(rule aws.GuardDutyNotificationRule, region string, reach map[string]*aws.SNSTopicSubscribers) GuardDutyNotificationRuleRow {
	row := GuardDutyNotificationRuleRow{
		Name:              rule.Name,
		Region:            region,
		Enabled:           rule.Enabled,
		FiltersSeverity:   rule.FiltersSeverity,
		TargetsByKind:     rule.TargetsByKind,
		ReachesSubscriber: ruleReachesSubscriber(rule, reach),
	}
	for _, topic := range rule.TopicARNs {
		subs, ok := reach[topic]
		if !ok {
			row.Topics = append(row.Topics, GuardDutyNotificationTopicRow{TopicARN: topic, Unresolved: true})
			continue
		}
		row.Topics = append(row.Topics, GuardDutyNotificationTopicRow{
			TopicARN:                              topic,
			SubscriptionsByProtocol:               subs.ByProtocol,
			ConfirmedSubscriptionCount:            subs.Confirmed,
			SubscriptionsPendingConfirmationCount: subs.PendingConfirmation,
		})
	}
	return row
}
