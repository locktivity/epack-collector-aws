package collector

import (
	"context"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// collectMonitoringMetrics collects alarm definitions for a region and resolves
// how far each alarm's notification actually travels.
//
// An alarm existing does not mean anyone is told. Four things break the chain
// independently: actions disabled, no notification action, a topic with no
// subscribers, or subscribers stuck at PendingConfirmation. The aggregate that
// answers the question is AlarmsReachingSubscriberCount, which counts only
// alarms whose chain is unbroken end to end.
func (c *Collector) collectMonitoringMetrics(ctx context.Context, client *aws.AWSClient, region, accountID string, level componentsdk.Level) (*MonitoringMetrics, error) {
	alarms, err := client.ListCloudWatchAlarms(ctx, region)
	if err != nil {
		return nil, err
	}

	out := &MonitoringMetrics{AlarmCount: len(alarms)}
	if len(alarms) == 0 {
		return out, nil
	}

	// One lookup per distinct topic, not per alarm: alarms commonly share one.
	reach := map[string]*aws.SNSTopicSubscribers{}
	for _, alarm := range alarms {
		for _, topic := range alarm.NotificationTopics {
			if _, seen := reach[topic]; seen {
				continue
			}
			subs, subErr := client.GetSNSTopicSubscribers(ctx, region, topic)
			if subErr != nil {
				c.warn("account %s region %s: failed to read SNS subscribers: %v", accountID, region, subErr)
				out.TopicsUnresolvedCount++
				continue
			}
			reach[topic] = subs
		}
	}

	out.NotificationTopicCount = len(reach)
	for _, subs := range reach {
		if out.SubscriptionsByProtocol == nil {
			out.SubscriptionsByProtocol = map[string]int{}
		}
		for protocol, count := range subs.ByProtocol {
			out.SubscriptionsByProtocol[protocol] += count
		}
		out.SubscriptionsPendingConfirmationCount += subs.PendingConfirmation
		if subs.Confirmed == 0 {
			out.TopicsWithoutConfirmedSubscriberCount++
		}
	}

	for _, alarm := range alarms {
		if !alarm.ActionsEnabled {
			out.AlarmsWithActionsDisabledCount++
		}
		if len(alarm.NotificationTopics) == 0 {
			out.AlarmsWithoutNotificationCount++
		}
		if alarm.StateValue == "INSUFFICIENT_DATA" {
			out.AlarmsInsufficientDataCount++
		}
		if alarmReachesSubscriber(alarm, reach) {
			out.AlarmsReachingSubscriberCount++
		}
	}

	if !level.AtLeast(componentsdk.LevelAudit) {
		return out, nil
	}

	out.Alarms = make([]CloudWatchAlarmRow, 0, len(alarms))
	for _, alarm := range alarms {
		out.Alarms = append(out.Alarms, cloudWatchAlarmToRow(alarm, region, reach))
	}
	return out, nil
}

// alarmReachesSubscriber reports whether the alarm would actually notify a
// person or system: actions on, a notification topic, and that topic holding at
// least one confirmed subscriber.
func alarmReachesSubscriber(alarm aws.CloudWatchAlarm, reach map[string]*aws.SNSTopicSubscribers) bool {
	if !alarm.ActionsEnabled {
		return false
	}
	for _, topic := range alarm.NotificationTopics {
		if subs, ok := reach[topic]; ok && subs.Confirmed > 0 {
			return true
		}
	}
	return false
}

func cloudWatchAlarmToRow(alarm aws.CloudWatchAlarm, region string, reach map[string]*aws.SNSTopicSubscribers) CloudWatchAlarmRow {
	row := CloudWatchAlarmRow{
		Name:               alarm.Name,
		Region:             region,
		Namespace:          alarm.Namespace,
		MetricName:         alarm.MetricName,
		ComparisonOperator: alarm.ComparisonOperator,
		Threshold:          alarm.Threshold,
		EvaluationPeriods:  alarm.EvaluationPeriods,
		ActionsEnabled:     alarm.ActionsEnabled,
		StateValue:         alarm.StateValue,
		NotificationTopics: len(alarm.NotificationTopics),
		ReachesSubscriber:  alarmReachesSubscriber(alarm, reach),
		OtherActionCount:   alarm.OtherActionCount,
	}
	return row
}

// mergeMonitoringMetrics combines per-region results. Trust aggregates sum;
// audit rows concatenate.
func mergeMonitoringMetrics(a, b MonitoringMetrics) MonitoringMetrics {
	merged := MonitoringMetrics{
		AlarmCount:                            a.AlarmCount + b.AlarmCount,
		AlarmsWithActionsDisabledCount:        a.AlarmsWithActionsDisabledCount + b.AlarmsWithActionsDisabledCount,
		AlarmsWithoutNotificationCount:        a.AlarmsWithoutNotificationCount + b.AlarmsWithoutNotificationCount,
		AlarmsInsufficientDataCount:           a.AlarmsInsufficientDataCount + b.AlarmsInsufficientDataCount,
		AlarmsReachingSubscriberCount:         a.AlarmsReachingSubscriberCount + b.AlarmsReachingSubscriberCount,
		NotificationTopicCount:                a.NotificationTopicCount + b.NotificationTopicCount,
		TopicsWithoutConfirmedSubscriberCount: a.TopicsWithoutConfirmedSubscriberCount + b.TopicsWithoutConfirmedSubscriberCount,
		TopicsUnresolvedCount:                 a.TopicsUnresolvedCount + b.TopicsUnresolvedCount,
		SubscriptionsPendingConfirmationCount: a.SubscriptionsPendingConfirmationCount + b.SubscriptionsPendingConfirmationCount,
		Alarms:                                append(append([]CloudWatchAlarmRow(nil), a.Alarms...), b.Alarms...),
	}
	for _, src := range []map[string]int{a.SubscriptionsByProtocol, b.SubscriptionsByProtocol} {
		for protocol, count := range src {
			if merged.SubscriptionsByProtocol == nil {
				merged.SubscriptionsByProtocol = map[string]int{}
			}
			merged.SubscriptionsByProtocol[protocol] += count
		}
	}
	return merged
}
