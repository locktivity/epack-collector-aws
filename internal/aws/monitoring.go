package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
)

// CloudWatchAlarm is an alarm definition: what triggers, and where the
// notification is sent. Only the SNS topic ARNs are kept from the actions;
// other action types are counted but not named.
type CloudWatchAlarm struct {
	Name               string
	MetricName         string
	Namespace          string
	ComparisonOperator string
	Threshold          *float64
	EvaluationPeriods  *int32 // nil for an alarm that uses EvaluationCriteria, such as a PromQL alarm
	ActionsEnabled     bool
	StateValue         string
	NotificationTopics []string
	OtherActionCount   int
}

// SNSTopicSubscribers summarises who a topic reaches, as counts only.
//
// Subscription endpoints are deliberately never returned. They are email
// addresses and phone numbers, and an HTTPS endpoint is routinely a Slack or
// PagerDuty webhook URL, which is a credential in its own right. Counts answer
// "is anyone actually reached" without any of that entering an artifact.
type SNSTopicSubscribers struct {
	TopicARN            string
	ByProtocol          map[string]int
	Confirmed           int
	PendingConfirmation int
}

// ListCloudWatchAlarms returns metric alarm definitions for a region.
func (c *AWSClient) ListCloudWatchAlarms(ctx context.Context, region string) ([]CloudWatchAlarm, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := cloudwatch.NewFromConfig(cfg)

	var alarms []CloudWatchAlarm
	paginator := cloudwatch.NewDescribeAlarmsPaginator(client, &cloudwatch.DescribeAlarmsInput{
		AlarmTypes: []types.AlarmType{types.AlarmTypeMetricAlarm},
	})
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing CloudWatch alarms in %s: %w", region, err)
		}
		for _, a := range out.MetricAlarms {
			alarm := CloudWatchAlarm{
				Name:               aws.ToString(a.AlarmName),
				MetricName:         aws.ToString(a.MetricName),
				Namespace:          aws.ToString(a.Namespace),
				ComparisonOperator: string(a.ComparisonOperator),
				Threshold:          a.Threshold,
				EvaluationPeriods:  a.EvaluationPeriods,
				ActionsEnabled:     aws.ToBool(a.ActionsEnabled),
				StateValue:         string(a.StateValue),
			}
			if alarm.MetricName == "" {
				alarm.Namespace, alarm.MetricName = singleAlarmMetric(a.Metrics)
			}
			for _, action := range a.AlarmActions {
				if isSNSTopicARN(action) {
					alarm.NotificationTopics = append(alarm.NotificationTopics, action)
					continue
				}
				alarm.OtherActionCount++
			}
			alarms = append(alarms, alarm)
		}
	}
	return alarms, nil
}

// singleAlarmMetric returns the namespace and name of the one metric an
// alarm's Metrics array reads, as for an anomaly detection band or a math
// expression over one metric. It returns empty strings when the array reads
// no metric or more than one.
func singleAlarmMetric(queries []types.MetricDataQuery) (namespace, name string) {
	found := 0
	for _, q := range queries {
		if q.MetricStat == nil || q.MetricStat.Metric == nil {
			continue
		}
		m := q.MetricStat.Metric
		if found > 0 && (aws.ToString(m.Namespace) != namespace || aws.ToString(m.MetricName) != name) {
			return "", ""
		}
		namespace, name = aws.ToString(m.Namespace), aws.ToString(m.MetricName)
		found++
	}
	return namespace, name
}

// GetSNSTopicSubscribers summarises a topic's subscriptions. See
// SNSTopicSubscribers for why endpoints are not returned. A topic that no
// longer exists has no subscribers, so a NotFound error reads as none.
func (c *AWSClient) GetSNSTopicSubscribers(ctx context.Context, region, topicARN string) (*SNSTopicSubscribers, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := sns.NewFromConfig(cfg)

	out := &SNSTopicSubscribers{TopicARN: topicARN, ByProtocol: map[string]int{}}
	paginator := sns.NewListSubscriptionsByTopicPaginator(client, &sns.ListSubscriptionsByTopicInput{
		TopicArn: aws.String(topicARN),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			var deleted *snstypes.NotFoundException
			if errors.As(err, &deleted) {
				return &SNSTopicSubscribers{TopicARN: topicARN, ByProtocol: map[string]int{}}, nil
			}
			return nil, fmt.Errorf("listing SNS subscriptions in %s: %w", region, err)
		}
		for _, sub := range page.Subscriptions {
			out.ByProtocol[aws.ToString(sub.Protocol)]++

			// AWS reports an unconfirmed subscription by putting a sentinel in
			// the ARN field rather than a real ARN. Those never deliver, so a
			// topic full of them reaches nobody.
			if aws.ToString(sub.SubscriptionArn) == "PendingConfirmation" {
				out.PendingConfirmation++
				continue
			}
			out.Confirmed++
		}
	}
	return out, nil
}

// isSNSTopicARN reports whether arn names an SNS topic in any partition,
// such as arn:aws:sns:, arn:aws-us-gov:sns: or arn:aws-cn:sns:.
func isSNSTopicARN(arn string) bool {
	parts := strings.Split(arn, ":")
	return len(parts) >= 6 && parts[0] == "arn" && parts[1] != "" && parts[2] == "sns"
}
