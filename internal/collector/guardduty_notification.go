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

	// adminErr, rulesErr, and unresolved are why the administrator, the
	// rules, and each topic's subscribers could not be read.
	adminErr   error
	rulesErr   error
	unresolved map[string]error
}

// scanGuardDutyNotificationRegion resolves how findings leave one region.
// Runs only for regions with a detector: findings publish to the default bus
// of the region that raised them, so rules elsewhere route nothing.
func (c *Collector) scanGuardDutyNotificationRegion(ctx context.Context, client *aws.AWSClient, region, accountID, detectorID string) guardDutyNotificationScan {
	var s guardDutyNotificationScan

	adminID, err := client.GetGuardDutyAdministratorAccount(ctx, region, detectorID)
	if err != nil {
		c.warn("account %s region %s: failed to read GuardDuty administrator account: %v", accountID, region, err)
		s.adminErr = err
	}
	s.adminAccountID = adminID

	s.rules, err = client.ListGuardDutyNotificationRules(ctx, region)
	if err != nil {
		c.warn("account %s region %s: failed to list GuardDuty notification rules: %v", accountID, region, err)
		s.rulesErr = err
		return s
	}
	s.evaluated = true

	// One lookup per distinct topic, not per rule: rules commonly share one.
	s.reach = map[string]*aws.SNSTopicSubscribers{}
	s.unresolved = map[string]error{}
	for _, rule := range s.rules {
		for _, topic := range rule.TopicARNs {
			if _, seen := s.reach[topic]; seen {
				continue
			}
			if _, failed := s.unresolved[topic]; failed {
				continue
			}
			subs, subErr := client.GetSNSTopicSubscribers(ctx, region, topic)
			if subErr != nil {
				c.warn("account %s region %s: failed to read SNS subscribers: %v", accountID, region, subErr)
				s.topicsUnresolved++
				s.unresolved[topic] = subErr
				continue
			}
			s.reach[topic] = subs
		}
	}
	return s
}

// applyGuardDutyNotificationScan folds one detector region's scan into the
// account summary, appending audit rows when includeRows is set. What a
// failed read leaves unknown goes into missing, by field under the GuardDuty
// status.
func applyGuardDutyNotificationScan(fn *GuardDutyFindingNotification, missing *unread, s guardDutyNotificationScan, region string, includeRows bool) {
	fn.DetectorRegionsCount++
	if fn.AdministratorAccountID == "" {
		fn.AdministratorAccountID = s.adminAccountID
		missing.add(s.adminErr, "finding_notification/administrator_account_id")
	}
	if !s.evaluated {
		fn.DetectorRegionsUnresolvedCount++
		missing.addPartial(s.rulesErr, 1, "finding_notification/rule_count", "finding_notification/detector_regions_routed_count",
			"finding_notification/detector_regions_reaching_subscriber_count", "finding_notification/subscriptions_by_protocol",
			"finding_notification/subscriptions_pending_confirmation_count")
		if includeRows {
			missing.add(s.rulesErr, "finding_notification/rules")
		}
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
	if firstErr := firstTopicError(s); firstErr != nil {
		missing.addPartial(firstErr, len(s.unresolved), "finding_notification/subscriptions_by_protocol", "finding_notification/subscriptions_pending_confirmation_count")
		if !regionReaches {
			missing.addPartial(firstErr, len(s.unresolved), "finding_notification/detector_regions_reaching_subscriber_count")
		}
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
			row := guardDutyNotificationRuleToRow(rule, region, s.reach)
			for _, topic := range rule.TopicARNs {
				if err, failed := s.unresolved[topic]; failed {
					row.missing.add(err, "topics")
					if !row.ReachesSubscriber && rule.Enabled {
						row.missing.add(err, "reaches_subscriber")
					}
					break
				}
			}
			fn.Rules = append(fn.Rules, row)
		}
	}
}

// firstTopicError is the failure for the first topic, in rule order, whose
// subscribers could not be read.
func firstTopicError(s guardDutyNotificationScan) error {
	for _, rule := range s.rules {
		for _, topic := range rule.TopicARNs {
			if err, failed := s.unresolved[topic]; failed {
				return err
			}
		}
	}
	return nil
}

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
