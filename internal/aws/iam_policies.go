package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go/middleware"
	"github.com/locktivity/epack/componentsdk"
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

// ListUserPolicyNames returns the names of the inline policies embedded in
// an IAM user, every page of them.
func (c *AWSClient) ListUserPolicyNames(ctx context.Context, userName string) ([]string, error) {
	paginator := iam.NewListUserPoliciesPaginator(iam.NewFromConfig(c.cfg), &iam.ListUserPoliciesInput{
		UserName: aws.String(userName),
	})
	var names []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing the inline policies of IAM user %s: %w", userName, err)
		}
		names = append(names, page.PolicyNames...)
	}
	return names, nil
}

// ListGroupPolicyNames returns the names of the inline policies embedded in
// an IAM group, every page of them.
func (c *AWSClient) ListGroupPolicyNames(ctx context.Context, groupName string) ([]string, error) {
	paginator := iam.NewListGroupPoliciesPaginator(iam.NewFromConfig(c.cfg), &iam.ListGroupPoliciesInput{
		GroupName: aws.String(groupName),
	})
	var names []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing the inline policies of IAM group %s: %w", groupName, err)
		}
		names = append(names, page.PolicyNames...)
	}
	return names, nil
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

// GetPolicyDocument returns the document of the default version of the
// managed policy arn, URL-decoded. GetPolicy names the default version, and
// GetPolicyVersion returns its document.
func (c *AWSClient) GetPolicyDocument(ctx context.Context, arn string) (string, error) {
	client := iam.NewFromConfig(c.cfg)
	call := "reading managed policy " + arn
	policy, err := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(arn)})
	if err != nil {
		return "", fmt.Errorf("%s: %w", call, err)
	}
	if policy.Policy == nil || aws.ToString(policy.Policy.DefaultVersionId) == "" {
		return "", errMissing(policy.ResultMetadata, call, "DefaultVersionId")
	}
	version, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: aws.String(arn), VersionId: policy.Policy.DefaultVersionId})
	if err != nil {
		return "", fmt.Errorf("%s: %w", call, err)
	}
	if version.PolicyVersion == nil {
		return "", errMissing(version.ResultMetadata, call, "PolicyVersion")
	}
	return policyDocument(version.ResultMetadata, call, version.PolicyVersion.Document)
}

// GetUserPolicyDocument returns the document of the inline policy called
// policyName in the IAM user userName, URL-decoded.
func (c *AWSClient) GetUserPolicyDocument(ctx context.Context, userName, policyName string) (string, error) {
	call := fmt.Sprintf("reading inline policy %s of IAM user %s", policyName, userName)
	out, err := iam.NewFromConfig(c.cfg).GetUserPolicy(ctx, &iam.GetUserPolicyInput{UserName: aws.String(userName), PolicyName: aws.String(policyName)})
	if err != nil {
		return "", fmt.Errorf("%s: %w", call, err)
	}
	return policyDocument(out.ResultMetadata, call, out.PolicyDocument)
}

// GetGroupPolicyDocument returns the document of the inline policy called
// policyName in the IAM group groupName, URL-decoded.
func (c *AWSClient) GetGroupPolicyDocument(ctx context.Context, groupName, policyName string) (string, error) {
	call := fmt.Sprintf("reading inline policy %s of IAM group %s", policyName, groupName)
	out, err := iam.NewFromConfig(c.cfg).GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{GroupName: aws.String(groupName), PolicyName: aws.String(policyName)})
	if err != nil {
		return "", fmt.Errorf("%s: %w", call, err)
	}
	return policyDocument(out.ResultMetadata, call, out.PolicyDocument)
}

// GetUserPermissionsBoundary returns the ARN of the policy an IAM user has
// as its permissions boundary, or "" when it has none. GetUser is the call
// that returns it, since ListUsers leaves it out.
func (c *AWSClient) GetUserPermissionsBoundary(ctx context.Context, userName string) (string, error) {
	call := "reading IAM user " + userName
	out, err := iam.NewFromConfig(c.cfg).GetUser(ctx, &iam.GetUserInput{UserName: aws.String(userName)})
	if err != nil {
		return "", fmt.Errorf("%s: %w", call, err)
	}
	if out.User == nil {
		return "", errMissing(out.ResultMetadata, call, "User")
	}
	if out.User.PermissionsBoundary == nil {
		return "", nil
	}
	return aws.ToString(out.User.PermissionsBoundary.PermissionsBoundaryArn), nil
}

// policyDocument URL-decodes a policy document, which IAM returns encoded
// as RFC 3986 describes, and checks that it is JSON. meta is the output's
// ResultMetadata, so a document that is missing or not JSON names the call.
func policyDocument(meta middleware.Metadata, call string, document *string) (string, error) {
	if document == nil {
		return "", errMissing(meta, call, "PolicyDocument")
	}
	decoded, err := url.QueryUnescape(*document)
	if err != nil || !json.Valid([]byte(decoded)) {
		return "", inResponse(meta, componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("%s: the policy document is not URL-encoded JSON", call)))
	}
	return decoded, nil
}
