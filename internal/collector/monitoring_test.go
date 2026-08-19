package collector

import (
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

func topic(arn string, confirmed, pending int) *aws.SNSTopicSubscribers {
	return &aws.SNSTopicSubscribers{
		TopicARN:            arn,
		ByProtocol:          map[string]int{"email": confirmed + pending},
		Confirmed:           confirmed,
		PendingConfirmation: pending,
	}
}

// An alarm that fires and tells nobody is the case this surface exists to
// catch, so each way the chain breaks is asserted separately.
func TestAlarmReachesSubscriber(t *testing.T) {
	const arn = "arn:aws:sns:us-east-1:123456789012:alerts"

	tests := []struct {
		name  string
		alarm aws.CloudWatchAlarm
		reach map[string]*aws.SNSTopicSubscribers
		want  bool
	}{
		{
			name:  "actions on, topic attached, subscriber confirmed",
			alarm: aws.CloudWatchAlarm{ActionsEnabled: true, NotificationTopics: []string{arn}},
			reach: map[string]*aws.SNSTopicSubscribers{arn: topic(arn, 1, 0)},
			want:  true,
		},
		{
			name:  "actions disabled means the alarm evaluates and does nothing",
			alarm: aws.CloudWatchAlarm{ActionsEnabled: false, NotificationTopics: []string{arn}},
			reach: map[string]*aws.SNSTopicSubscribers{arn: topic(arn, 1, 0)},
			want:  false,
		},
		{
			name:  "no notification action at all",
			alarm: aws.CloudWatchAlarm{ActionsEnabled: true},
			reach: map[string]*aws.SNSTopicSubscribers{},
			want:  false,
		},
		{
			name:  "topic exists but has no subscribers",
			alarm: aws.CloudWatchAlarm{ActionsEnabled: true, NotificationTopics: []string{arn}},
			reach: map[string]*aws.SNSTopicSubscribers{arn: topic(arn, 0, 0)},
			want:  false,
		},
		{
			name:  "subscribers are all unconfirmed, so nothing is delivered",
			alarm: aws.CloudWatchAlarm{ActionsEnabled: true, NotificationTopics: []string{arn}},
			reach: map[string]*aws.SNSTopicSubscribers{arn: topic(arn, 0, 3)},
			want:  false,
		},
		{
			name:  "one of several topics reaching someone is enough",
			alarm: aws.CloudWatchAlarm{ActionsEnabled: true, NotificationTopics: []string{"arn:aws:sns:us-east-1:1:dead", arn}},
			reach: map[string]*aws.SNSTopicSubscribers{"arn:aws:sns:us-east-1:1:dead": topic("dead", 0, 0), arn: topic(arn, 2, 0)},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := alarmReachesSubscriber(tt.alarm, tt.reach); got != tt.want {
				t.Fatalf("alarmReachesSubscriber() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMergeMonitoringMetricsSumsAcrossRegions(t *testing.T) {
	a := MonitoringMetrics{
		AlarmCount:                    3,
		AlarmsReachingSubscriberCount: 2,
		SubscriptionsByProtocol:       map[string]int{"email": 2},
		Alarms:                        []CloudWatchAlarmRow{{Name: "a", Region: "us-east-1"}},
	}
	b := MonitoringMetrics{
		AlarmCount:                    1,
		AlarmsReachingSubscriberCount: 0,
		SubscriptionsByProtocol:       map[string]int{"email": 1, "https": 1},
		Alarms:                        []CloudWatchAlarmRow{{Name: "b", Region: "eu-west-1"}},
	}

	got := mergeMonitoringMetrics(a, b)

	if got.AlarmCount != 4 {
		t.Errorf("AlarmCount = %d, want 4", got.AlarmCount)
	}
	if got.AlarmsReachingSubscriberCount != 2 {
		t.Errorf("AlarmsReachingSubscriberCount = %d, want 2", got.AlarmsReachingSubscriberCount)
	}
	if got.SubscriptionsByProtocol["email"] != 3 || got.SubscriptionsByProtocol["https"] != 1 {
		t.Errorf("SubscriptionsByProtocol = %v, want email 3 and https 1", got.SubscriptionsByProtocol)
	}
	if len(got.Alarms) != 2 {
		t.Errorf("len(Alarms) = %d, want 2", len(got.Alarms))
	}
}
