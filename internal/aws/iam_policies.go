package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// ListAttachedUserPolicyARNs returns the ARNs of the managed policies
// attached to an IAM user, every page of them.
func (c *AWSClient) ListAttachedUserPolicyARNs(ctx context.Context, userName string) ([]string, error) {
	paginator := iam.NewListAttachedUserPoliciesPaginator(iam.NewFromConfig(c.cfg), &iam.ListAttachedUserPoliciesInput{
		UserName: aws.String(userName),
	})
	var arns []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing the policies attached to IAM user %s: %w", userName, err)
		}
		for _, p := range page.AttachedPolicies {
			arns = append(arns, aws.ToString(p.PolicyArn))
		}
	}
	return arns, nil
}

// ListGroupsForUser returns the names of the IAM groups a user belongs to,
// every page of them.
func (c *AWSClient) ListGroupsForUser(ctx context.Context, userName string) ([]string, error) {
	paginator := iam.NewListGroupsForUserPaginator(iam.NewFromConfig(c.cfg), &iam.ListGroupsForUserInput{
		UserName: aws.String(userName),
	})
	var names []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing the groups of IAM user %s: %w", userName, err)
		}
		for _, g := range page.Groups {
			names = append(names, aws.ToString(g.GroupName))
		}
	}
	return names, nil
}

// ListAttachedGroupPolicyARNs returns the ARNs of the managed policies
// attached to an IAM group, every page of them.
func (c *AWSClient) ListAttachedGroupPolicyARNs(ctx context.Context, groupName string) ([]string, error) {
	paginator := iam.NewListAttachedGroupPoliciesPaginator(iam.NewFromConfig(c.cfg), &iam.ListAttachedGroupPoliciesInput{
		GroupName: aws.String(groupName),
	})
	var arns []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing the policies attached to IAM group %s: %w", groupName, err)
		}
		for _, p := range page.AttachedPolicies {
			arns = append(arns, aws.ToString(p.PolicyArn))
		}
	}
	return arns, nil
}
