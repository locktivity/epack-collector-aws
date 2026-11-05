package collector

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	smithycbor "github.com/aws/smithy-go/encoding/cbor"
	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
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

// alarmTransport returns the responses of the services the monitoring
// surface calls, from the alarm list and the per-topic SNS results a test
// sets. Any other call fails the test.
type alarmTransport struct {
	t      *testing.T
	alarms smithycbor.List
	topics map[string]topicAnswer
	groups []any
}

// topicAnswer is the ListSubscriptionsByTopic result for one topic.
type topicAnswer struct {
	status        int    // 0 means 200
	errorCode     string // set with a non-200 status
	subscriptions []topicSubscription
}

type topicSubscription struct {
	arn      string
	protocol string
}

func (a *alarmTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	a.t.Helper()
	raw, _ := io.ReadAll(req.Body)
	host := req.URL.Host
	switch {
	case strings.HasPrefix(host, "monitoring."):
		body := smithycbor.Encode(smithycbor.Map{"MetricAlarms": a.alarms, "CompositeAlarms": smithycbor.List{}})
		return &http.Response{
			StatusCode: 200, Request: req, Body: io.NopCloser(strings.NewReader(string(body))),
			Header: http.Header{"Content-Type": []string{"application/cbor"}, "Smithy-Protocol": []string{"rpc-v2-cbor"}},
		}, nil
	case strings.HasPrefix(host, "sns."):
		form, _ := url.ParseQuery(string(raw))
		topic := form.Get("TopicArn")
		answer, ok := a.topics[topic]
		if !ok {
			a.t.Errorf("unexpected SNS call for topic %q", topic)
			answer = topicAnswer{status: 404, errorCode: "NotFound"}
		}
		if answer.status != 0 && answer.status != 200 {
			xml := "<ErrorResponse xmlns=\"http://sns.amazonaws.com/doc/2010-03-31/\"><Error><Type>Sender</Type><Code>" + answer.errorCode +
				"</Code><Message>kit</Message></Error><RequestId>kit-request</RequestId></ErrorResponse>"
			return &http.Response{StatusCode: answer.status, Request: req, Body: io.NopCloser(strings.NewReader(xml)), Header: xmlHeader()}, nil
		}
		var members strings.Builder
		for _, s := range answer.subscriptions {
			fmt.Fprintf(&members, "<member><SubscriptionArn>%s</SubscriptionArn><Owner>123456789012</Owner><Protocol>%s</Protocol>"+
				"<Endpoint>redacted</Endpoint><TopicArn>%s</TopicArn></member>", s.arn, s.protocol, topic)
		}
		xml := "<ListSubscriptionsByTopicResponse xmlns=\"http://sns.amazonaws.com/doc/2010-03-31/\"><ListSubscriptionsByTopicResult><Subscriptions>" +
			members.String() + "</Subscriptions></ListSubscriptionsByTopicResult><ResponseMetadata><RequestId>kit-request</RequestId></ResponseMetadata></ListSubscriptionsByTopicResponse>"
		return &http.Response{StatusCode: 200, Request: req, Body: io.NopCloser(strings.NewReader(xml)), Header: xmlHeader()}, nil
	case strings.HasPrefix(host, "logs."):
		return &http.Response{
			StatusCode: 200, Request: req, Body: io.NopCloser(strings.NewReader(kitJSON(map[string]any{"logGroups": a.groups}))),
			Header: jsonHeader("application/x-amz-json-1.1"),
		}, nil
	}
	a.t.Errorf("unexpected call to %s", req.URL)
	return nil, fmt.Errorf("unexpected call to %s", req.URL)
}

func newTransportClient(t *testing.T, rt http.RoundTripper) *aws.AWSClient {
	t.Helper()
	useAccessKeys(t)
	client, err := aws.NewClient(context.Background(), aws.Options{HTTPClient: &http.Client{Transport: rt}})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// metricAlarm builds one metric alarm as DescribeAlarms returns it.
func metricAlarm(name string, actions ...string) smithycbor.Map {
	list := smithycbor.List{}
	for _, a := range actions {
		list = append(list, smithycbor.String(a))
	}
	return smithycbor.Map{
		"AlarmName": smithycbor.String(name), "MetricName": smithycbor.String("CPUUtilization"), "Namespace": smithycbor.String("AWS/EC2"),
		"ComparisonOperator": smithycbor.String("GreaterThanThreshold"), "Threshold": smithycbor.Float64(80), "EvaluationPeriods": smithycbor.Uint(3),
		"ActionsEnabled": smithycbor.Bool(true), "StateValue": smithycbor.String("OK"), "AlarmActions": list,
	}
}

func runMonitoring(t *testing.T, rt *alarmTransport, region string) *MonitoringMetrics {
	t.Helper()
	rt.t = t
	c := newTestCollector(Config{})
	got, err := c.collectMonitoringMetrics(context.Background(), newTransportClient(t, rt), region, "123456789012", componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("collectMonitoringMetrics: %v", err)
	}
	return got
}

// A topic ARN names its partition, such as arn:aws-us-gov or arn:aws-cn, and
// an alarm that notifies a confirmed subscriber reaches one in every
// partition.
func TestMonitoring_AlarmTopicsInEveryPartition(t *testing.T) {
	tests := []struct {
		name     string
		region   string
		topicARN string
	}{
		{name: "aws partition", region: "us-east-1", topicARN: "arn:aws:sns:us-east-1:123456789012:alerts"},
		{name: "aws-us-gov partition", region: "us-gov-west-1", topicARN: "arn:aws-us-gov:sns:us-gov-west-1:123456789012:alerts"},
		{name: "aws-cn partition", region: "cn-north-1", topicARN: "arn:aws-cn:sns:cn-north-1:123456789012:alerts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &alarmTransport{
				alarms: smithycbor.List{metricAlarm("cpu-high", tt.topicARN)},
				topics: map[string]topicAnswer{tt.topicARN: {subscriptions: []topicSubscription{
					{arn: tt.topicARN + ":6f1c2a3b-0000-4000-8000-000000000001", protocol: "email"},
				}}},
			}
			got := runMonitoring(t, rt, tt.region)

			if got.AlarmCount != 1 {
				t.Fatalf("AlarmCount = %d, want 1", got.AlarmCount)
			}
			if got.AlarmsWithoutNotificationCount != 0 {
				t.Errorf("AlarmsWithoutNotificationCount = %d, want 0: the alarm notifies %s", got.AlarmsWithoutNotificationCount, tt.topicARN)
			}
			if got.AlarmsReachingSubscriberCount != 1 {
				t.Errorf("AlarmsReachingSubscriberCount = %d, want 1: the topic has a confirmed subscriber", got.AlarmsReachingSubscriberCount)
			}
			if got.NotificationTopicCount != 1 {
				t.Errorf("NotificationTopicCount = %d, want 1", got.NotificationTopicCount)
			}
			if len(got.Alarms) != 1 {
				t.Fatalf("len(Alarms) = %d, want 1", len(got.Alarms))
			}
			row := got.Alarms[0]
			if row.NotificationTopics != 1 || row.OtherActionCount != 0 || !row.ReachesSubscriber {
				t.Errorf("row notification_topics=%d other_action_count=%d reaches_subscriber=%v; want 1, 0, true",
					row.NotificationTopics, row.OtherActionCount, row.ReachesSubscriber)
			}
		})
	}
}

// An anomaly detection alarm carries its metric in the Metrics array, where
// DescribeAlarms leaves MetricName and Namespace unset, and its row still
// names the one metric it watches.
func TestMonitoring_AnomalyDetectionAlarmNamesItsMetric(t *testing.T) {
	const topicARN = "arn:aws:sns:us-east-1:123456789012:alerts"

	anomaly := smithycbor.Map{
		"AlarmName": smithycbor.String("cpu-anomaly"), "ComparisonOperator": smithycbor.String("LessThanLowerOrGreaterThanUpperThreshold"),
		"ThresholdMetricId": smithycbor.String("t1"), "EvaluationPeriods": smithycbor.Uint(2),
		"ActionsEnabled": smithycbor.Bool(true), "StateValue": smithycbor.String("OK"),
		"AlarmActions": smithycbor.List{smithycbor.String(topicARN)},
		"Metrics": smithycbor.List{
			smithycbor.Map{"Id": smithycbor.String("m1"), "ReturnData": smithycbor.Bool(true), "MetricStat": smithycbor.Map{
				"Metric": smithycbor.Map{"MetricName": smithycbor.String("CPUUtilization"), "Namespace": smithycbor.String("AWS/EC2")},
				"Stat":   smithycbor.String("Average"), "Period": smithycbor.Uint(60),
			}},
			smithycbor.Map{"Id": smithycbor.String("t1"), "Expression": smithycbor.String("ANOMALY_DETECTION_BAND(m1, 3)")},
		},
	}

	tests := []struct {
		name          string
		alarm         smithycbor.Map
		wantMetric    string
		wantNamespace string
	}{
		{name: "alarm on a single metric", alarm: metricAlarm("cpu-high", topicARN), wantMetric: "CPUUtilization", wantNamespace: "AWS/EC2"},
		{name: "alarm on an anomaly detection band over one metric", alarm: anomaly, wantMetric: "CPUUtilization", wantNamespace: "AWS/EC2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &alarmTransport{
				alarms: smithycbor.List{tt.alarm},
				topics: map[string]topicAnswer{topicARN: {subscriptions: []topicSubscription{{arn: topicARN + ":6f1c2a3b", protocol: "email"}}}},
			}
			got := runMonitoring(t, rt, "us-east-1")
			if len(got.Alarms) != 1 {
				t.Fatalf("len(Alarms) = %d, want 1", len(got.Alarms))
			}
			row := got.Alarms[0]
			if row.MetricName != tt.wantMetric || row.Namespace != tt.wantNamespace {
				t.Errorf("metric_name=%q namespace=%q, want %q and %q", row.MetricName, row.Namespace, tt.wantMetric, tt.wantNamespace)
			}
		})
	}
}

// ListSubscriptionsByTopic fails with NotFound for a deleted topic, so an
// alarm that still names it reaches nobody. A denied read leaves the topic
// unknown.
func TestMonitoring_DeletedTopicNotifiesNobody(t *testing.T) {
	const topicARN = "arn:aws:sns:us-east-1:123456789012:retired-alerts"

	tests := []struct {
		name           string
		answer         topicAnswer
		wantUnresolved int
		wantNoSubs     int
	}{
		{name: "access denied leaves the topic unknown", answer: topicAnswer{status: 403, errorCode: "AuthorizationError"}, wantUnresolved: 1, wantNoSubs: 0},
		{name: "topic deleted", answer: topicAnswer{status: 404, errorCode: "NotFound"}, wantUnresolved: 0, wantNoSubs: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &alarmTransport{
				alarms: smithycbor.List{metricAlarm("cpu-high", topicARN)},
				topics: map[string]topicAnswer{topicARN: tt.answer},
			}
			got := runMonitoring(t, rt, "us-east-1")
			if got.AlarmsReachingSubscriberCount != 0 {
				t.Errorf("AlarmsReachingSubscriberCount = %d, want 0", got.AlarmsReachingSubscriberCount)
			}
			if got.TopicsUnresolvedCount != tt.wantUnresolved {
				t.Errorf("TopicsUnresolvedCount = %d, want %d", got.TopicsUnresolvedCount, tt.wantUnresolved)
			}
			if got.TopicsWithoutConfirmedSubscriberCount != tt.wantNoSubs {
				t.Errorf("TopicsWithoutConfirmedSubscriberCount = %d, want %d", got.TopicsWithoutConfirmedSubscriberCount, tt.wantNoSubs)
			}
			if hasUnread(got.missing, "alarms_reaching_subscriber_count", 1) != (tt.wantUnresolved == 1) {
				t.Errorf("alarms_reaching_subscriber_count marked unknown = %v, want %v", tt.wantUnresolved != 1, tt.wantUnresolved == 1)
			}
		})
	}
}

// promQLAlarm builds one PromQL alarm as DescribeAlarms returns it. Its
// evaluation parameters are in EvaluationCriteria and EvaluationInterval, so
// it has no metric, comparison operator, threshold or evaluation periods.
func promQLAlarm(name string, actions ...string) smithycbor.Map {
	list := smithycbor.List{}
	for _, a := range actions {
		list = append(list, smithycbor.String(a))
	}
	return smithycbor.Map{
		"AlarmName": smithycbor.String(name), "ActionsEnabled": smithycbor.Bool(true), "StateValue": smithycbor.String("OK"), "AlarmActions": list,
		"EvaluationCriteria": smithycbor.Map{"PromQLCriteria": smithycbor.Map{
			"Query": smithycbor.String("avg(cpu_utilization_percent) > 80"), "PendingPeriod": smithycbor.Uint(300), "RecoveryPeriod": smithycbor.Uint(120),
		}},
		"EvaluationInterval": smithycbor.Uint(30),
	}
}

// An alarm that uses EvaluationCriteria has no EvaluationPeriods, whose
// minimum is 1, so its row leaves evaluation_periods out.
func TestMonitoring_PromQLAlarmHasNoEvaluationPeriods(t *testing.T) {
	const topicARN = "arn:aws:sns:us-east-1:123456789012:alerts"
	for _, tc := range []struct {
		name  string
		alarm smithycbor.Map
		want  string
	}{
		{"PromQL alarm", promQLAlarm("promql-cpu", topicARN), "<nil>"},
		{"static threshold alarm", metricAlarm("cpu-high", topicARN), "3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &alarmTransport{
				alarms: smithycbor.List{tc.alarm},
				topics: map[string]topicAnswer{topicARN: {subscriptions: []topicSubscription{{arn: topicARN + ":6f1c2a3b", protocol: "email"}}}},
			}
			got := runMonitoring(t, rt, "us-east-1")
			if len(got.Alarms) != 1 {
				t.Fatalf("len(Alarms) = %d, want 1", len(got.Alarms))
			}
			periods := "<nil>"
			if p := got.Alarms[0].EvaluationPeriods; p != nil {
				periods = fmt.Sprint(*p)
			}
			if periods != tc.want {
				t.Errorf("evaluation_periods = %s, want %s", periods, tc.want)
			}
		})
	}
}
