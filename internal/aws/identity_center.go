package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
)

// ListIdentityCenterInstances returns IdC instances in the given region.
// Returns an empty slice if IdC is not enabled in that region. There is at most
// one instance per account in any single region.
func (c *AWSClient) ListIdentityCenterInstances(ctx context.Context, region string) ([]IdentityCenterInstance, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := ssoadmin.NewFromConfig(cfg)

	out, err := client.ListInstances(ctx, &ssoadmin.ListInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("listing identity center instances: %w", err)
	}

	instances := make([]IdentityCenterInstance, 0, len(out.Instances))
	for _, inst := range out.Instances {
		instances = append(instances, IdentityCenterInstance{
			InstanceARN:     aws.ToString(inst.InstanceArn),
			IdentityStoreID: aws.ToString(inst.IdentityStoreId),
			Region:          region,
		})
	}
	return instances, nil
}

// ListIdentityCenterPermissionSets returns all permission sets on the given
// instance. When withInternalEnrichment is true, each row additionally carries
// the attached managed-policy ARNs and a HasInlinePolicy flag (policy contents
// are intentionally not fetched — they encode tenant-specific authorization
// logic and shouldn't land in evidence packs).
func (c *AWSClient) ListIdentityCenterPermissionSets(ctx context.Context, region, instanceARN string, withInternalEnrichment bool) ([]IdentityCenterPermissionSet, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := ssoadmin.NewFromConfig(cfg)

	arns, err := listAllPermissionSetARNs(ctx, client, instanceARN)
	if err != nil {
		return nil, err
	}
	if len(arns) == 0 {
		return []IdentityCenterPermissionSet{}, nil
	}

	out := make([]IdentityCenterPermissionSet, 0, len(arns))
	for _, arn := range arns {
		ps, err := describePermissionSetForAudit(ctx, client, instanceARN, arn)
		if err != nil {
			return nil, err
		}
		assigned, err := countAccountsForPermissionSet(ctx, client, instanceARN, arn)
		if err != nil {
			return nil, err
		}
		ps.AccountsAssignedCount = assigned

		mp, err := listManagedPoliciesForPermissionSet(ctx, client, instanceARN, arn)
		if err != nil {
			return nil, err
		}
		ps.ManagedPoliciesCount = len(mp)
		if withInternalEnrichment {
			ps.ManagedPolicyARNs = mp
			inlinePresent, err := permissionSetHasInlinePolicy(ctx, client, instanceARN, arn)
			if err != nil {
				return nil, err
			}
			ps.HasInlinePolicy = inlinePresent
		}
		out = append(out, ps)
	}
	return out, nil
}

func listAllPermissionSetARNs(ctx context.Context, client *ssoadmin.Client, instanceARN string) ([]string, error) {
	var arns []string
	var nextToken *string
	for {
		resp, err := client.ListPermissionSets(ctx, &ssoadmin.ListPermissionSetsInput{
			InstanceArn: aws.String(instanceARN),
			NextToken:   nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("listing permission sets: %w", err)
		}
		arns = append(arns, resp.PermissionSets...)
		if resp.NextToken == nil || *resp.NextToken == "" {
			return arns, nil
		}
		nextToken = resp.NextToken
	}
}

func describePermissionSetForAudit(ctx context.Context, client *ssoadmin.Client, instanceARN, psARN string) (IdentityCenterPermissionSet, error) {
	resp, err := client.DescribePermissionSet(ctx, &ssoadmin.DescribePermissionSetInput{
		InstanceArn:      aws.String(instanceARN),
		PermissionSetArn: aws.String(psARN),
	})
	if err != nil {
		return IdentityCenterPermissionSet{}, fmt.Errorf("describing permission set %s: %w", psARN, err)
	}
	ps := resp.PermissionSet
	if ps == nil {
		return IdentityCenterPermissionSet{ARN: psARN}, nil
	}
	return IdentityCenterPermissionSet{
		ARN:                    psARN,
		Name:                   aws.ToString(ps.Name),
		Description:            aws.ToString(ps.Description),
		SessionDurationISO8601: aws.ToString(ps.SessionDuration),
	}, nil
}

func countAccountsForPermissionSet(ctx context.Context, client *ssoadmin.Client, instanceARN, psARN string) (int, error) {
	var count int
	var nextToken *string
	for {
		resp, err := client.ListAccountsForProvisionedPermissionSet(ctx, &ssoadmin.ListAccountsForProvisionedPermissionSetInput{
			InstanceArn:      aws.String(instanceARN),
			PermissionSetArn: aws.String(psARN),
			NextToken:        nextToken,
		})
		if err != nil {
			return 0, fmt.Errorf("listing accounts for permission set %s: %w", psARN, err)
		}
		count += len(resp.AccountIds)
		if resp.NextToken == nil || *resp.NextToken == "" {
			return count, nil
		}
		nextToken = resp.NextToken
	}
}

func listManagedPoliciesForPermissionSet(ctx context.Context, client *ssoadmin.Client, instanceARN, psARN string) ([]string, error) {
	var arns []string
	var nextToken *string
	for {
		resp, err := client.ListManagedPoliciesInPermissionSet(ctx, &ssoadmin.ListManagedPoliciesInPermissionSetInput{
			InstanceArn:      aws.String(instanceARN),
			PermissionSetArn: aws.String(psARN),
			NextToken:        nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("listing managed policies for permission set %s: %w", psARN, err)
		}
		for _, p := range resp.AttachedManagedPolicies {
			arns = append(arns, aws.ToString(p.Arn))
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return arns, nil
		}
		nextToken = resp.NextToken
	}
}

func permissionSetHasInlinePolicy(ctx context.Context, client *ssoadmin.Client, instanceARN, psARN string) (bool, error) {
	resp, err := client.GetInlinePolicyForPermissionSet(ctx, &ssoadmin.GetInlinePolicyForPermissionSetInput{
		InstanceArn:      aws.String(instanceARN),
		PermissionSetArn: aws.String(psARN),
	})
	if err != nil {
		return false, fmt.Errorf("getting inline policy for permission set %s: %w", psARN, err)
	}
	return aws.ToString(resp.InlinePolicy) != "", nil
}

// ListIdentityStoreUsers returns all users in the identity store. Primary email
// is the entry marked Primary=true on the user (per SCIM); blank if no email
// is registered or none is marked primary.
func (c *AWSClient) ListIdentityStoreUsers(ctx context.Context, region, identityStoreID string) ([]IdentityStoreUser, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := identitystore.NewFromConfig(cfg)

	var users []IdentityStoreUser
	var nextToken *string
	for {
		resp, err := client.ListUsers(ctx, &identitystore.ListUsersInput{
			IdentityStoreId: aws.String(identityStoreID),
			NextToken:       nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("listing identity store users: %w", err)
		}
		for _, u := range resp.Users {
			user := IdentityStoreUser{
				UserID:      aws.ToString(u.UserId),
				UserName:    aws.ToString(u.UserName),
				DisplayName: aws.ToString(u.DisplayName),
			}
			for _, e := range u.Emails {
				if e.Primary {
					user.PrimaryEmail = aws.ToString(e.Value)
					break
				}
			}
			users = append(users, user)
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return users, nil
		}
		nextToken = resp.NextToken
	}
}

// ListIdentityStoreGroups returns all groups in the identity store. When
// withMemberCounts is true, ListGroupMemberships is called per group to compute
// MemberCount; otherwise MemberCount stays zero.
func (c *AWSClient) ListIdentityStoreGroups(ctx context.Context, region, identityStoreID string, withMemberCounts bool) ([]IdentityStoreGroup, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := identitystore.NewFromConfig(cfg)

	var groups []IdentityStoreGroup
	var nextToken *string
	for {
		resp, err := client.ListGroups(ctx, &identitystore.ListGroupsInput{
			IdentityStoreId: aws.String(identityStoreID),
			NextToken:       nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("listing identity store groups: %w", err)
		}
		for _, g := range resp.Groups {
			groups = append(groups, IdentityStoreGroup{
				GroupID:     aws.ToString(g.GroupId),
				DisplayName: aws.ToString(g.DisplayName),
				Description: aws.ToString(g.Description),
			})
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			break
		}
		nextToken = resp.NextToken
	}

	if !withMemberCounts {
		return groups, nil
	}

	for i := range groups {
		count, err := countGroupMembers(ctx, client, identityStoreID, groups[i].GroupID)
		if err != nil {
			return nil, err
		}
		groups[i].MemberCount = count
	}
	return groups, nil
}

func countGroupMembers(ctx context.Context, client *identitystore.Client, identityStoreID, groupID string) (int, error) {
	var count int
	var nextToken *string
	for {
		resp, err := client.ListGroupMemberships(ctx, &identitystore.ListGroupMembershipsInput{
			IdentityStoreId: aws.String(identityStoreID),
			GroupId:         aws.String(groupID),
			NextToken:       nextToken,
		})
		if err != nil {
			return 0, fmt.Errorf("listing memberships for group %s: %w", groupID, err)
		}
		count += len(resp.GroupMemberships)
		if resp.NextToken == nil || *resp.NextToken == "" {
			return count, nil
		}
		nextToken = resp.NextToken
	}
}
