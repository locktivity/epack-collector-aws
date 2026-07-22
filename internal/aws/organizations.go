package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
)

// ListOrganizationAccountIDs returns the IDs of every account in the AWS
// Organization this account belongs to.
//
// Used solely to classify cross-account role trust as inside or outside the
// customer's own organization. Only account IDs are retained; account names,
// emails, and statuses returned by the API are discarded here so they never
// reach the collector layer. The call succeeds only from the management
// account or a delegated administrator; member accounts get
// AccessDeniedException, which callers treat as "membership undeterminable",
// not an error.
func (c *AWSClient) ListOrganizationAccountIDs(ctx context.Context) ([]string, error) {
	client := organizations.NewFromConfig(c.cfg)

	accountIDs := []string{}
	var nextToken *string
	for {
		resp, err := client.ListAccounts(ctx, &organizations.ListAccountsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("listing organization accounts: %w", err)
		}
		for _, a := range resp.Accounts {
			accountIDs = append(accountIDs, aws.ToString(a.Id))
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return accountIDs, nil
		}
		nextToken = resp.NextToken
	}
}
