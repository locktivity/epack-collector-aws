package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

// RDSEventSubscription is one event subscription's coverage and destination.
type RDSEventSubscription struct {
	ID      string
	Enabled bool

	// Empty means everything, twice over: an empty SourceType covers all
	// source types, and empty EventCategories covers all categories. The
	// common real-world configuration is exactly that, so absence must be
	// read as the broadest coverage rather than none.
	SourceType       string
	EventCategories  []string
	CoversAllSources bool

	TopicARN string
}

// ListRDSEventSubscriptions returns the region's event subscriptions.
func (c *AWSClient) ListRDSEventSubscriptions(ctx context.Context, region string) ([]RDSEventSubscription, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := rds.NewFromConfig(cfg)

	var subs []RDSEventSubscription
	paginator := rds.NewDescribeEventSubscriptionsPaginator(client, &rds.DescribeEventSubscriptionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing RDS event subscriptions in %s: %w", region, err)
		}
		for _, s := range page.EventSubscriptionsList {
			subs = append(subs, RDSEventSubscription{
				ID:               aws.ToString(s.CustSubscriptionId),
				Enabled:          aws.ToBool(s.Enabled),
				SourceType:       aws.ToString(s.SourceType),
				EventCategories:  s.EventCategoriesList,
				CoversAllSources: len(s.SourceIdsList) == 0,
				TopicARN:         aws.ToString(s.SnsTopicArn),
			})
		}
	}
	return subs, nil
}

// GetDBParameters returns the logging-relevant parameters of a parameter
// group. The API has no server-side name filter, so pages are scanned and only
// the parameters the classifier reads are kept.
func (c *AWSClient) GetDBParameters(ctx context.Context, region, groupName string) (map[string]string, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := rds.NewFromConfig(cfg)

	wanted := map[string]bool{
		"shared_preload_libraries": true,
		"log_statement":            true,
		"pgaudit.log":              true,
	}

	out := map[string]string{}
	paginator := rds.NewDescribeDBParametersPaginator(client, &rds.DescribeDBParametersInput{
		DBParameterGroupName: aws.String(groupName),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing parameters for %s in %s: %w", groupName, region, err)
		}
		for _, p := range page.Parameters {
			name := aws.ToString(p.ParameterName)
			if wanted[name] {
				out[name] = aws.ToString(p.ParameterValue)
			}
		}
	}
	return out, nil
}
