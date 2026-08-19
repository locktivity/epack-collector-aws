package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
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
	EvaluationPeriods  int32
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
				EvaluationPeriods:  aws.ToInt32(a.EvaluationPeriods),
				ActionsEnabled:     aws.ToBool(a.ActionsEnabled),
				StateValue:         string(a.StateValue),
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

// GetSNSTopicSubscribers summarises a topic's subscriptions. See
// SNSTopicSubscribers for why endpoints are not returned.
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

func isSNSTopicARN(arn string) bool {
	return len(arn) > 8 && arn[:8] == "arn:aws:" && containsSegment(arn, ":sns:")
}

func containsSegment(s, segment string) bool {
	for i := 0; i+len(segment) <= len(s); i++ {
		if s[i:i+len(segment)] == segment {
			return true
		}
	}
	return false
}
