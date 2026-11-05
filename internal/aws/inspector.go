package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspectortypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/locktivity/epack/componentsdk"
)

// The resource types in Amazon Inspector's coverage and findings that the
// collector reads.
const (
	InspectorEC2Instance    = string(inspectortypes.ResourceTypeAwsEc2Instance)
	InspectorECRImage       = string(inspectortypes.ResourceTypeAwsEcrContainerImage)
	InspectorLambdaFunction = string(inspectortypes.ResourceTypeAwsLambdaFunction)
)

// InspectorAccountStatus is Amazon Inspector's status for one account in one
// region.
type InspectorAccountStatus struct {
	// Enabled is true when Inspector is ENABLED for the account.
	Enabled bool

	// ScanEnabled maps each resource type to whether Inspector is ENABLED for
	// the account and its scan type for that resource type is ENABLED too.
	ScanEnabled map[string]bool
}

// GetInspectorAccountStatus reads Amazon Inspector's status for the calling
// account in region. An account where Inspector was never turned on has the
// status DISABLED.
func (c *AWSClient) GetInspectorAccountStatus(ctx context.Context, region, accountID string) (InspectorAccountStatus, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	out, err := inspector2.NewFromConfig(cfg).BatchGetAccountStatus(ctx, &inspector2.BatchGetAccountStatusInput{})
	if err != nil {
		return InspectorAccountStatus{}, fmt.Errorf("reading the Inspector status in %s: %w", region, err)
	}
	for _, failed := range out.FailedAccounts {
		if aws.ToString(failed.AccountId) != accountID {
			continue
		}
		code := componentsdk.CodeVendorError
		if failed.ErrorCode == inspectortypes.ErrorCodeAccessDenied {
			code = componentsdk.CodePermissionDenied
		}
		return InspectorAccountStatus{}, inResponse(out.ResultMetadata, componentsdk.CodeError(code,
			fmt.Errorf("reading the Inspector status in %s: Inspector answered %s", region, failed.ErrorCode)))
	}
	for _, acct := range out.Accounts {
		if aws.ToString(acct.AccountId) != accountID {
			continue
		}
		if acct.State == nil {
			return InspectorAccountStatus{}, errMissing(out.ResultMetadata, "BatchGetAccountStatus", "state for the account")
		}
		status := InspectorAccountStatus{Enabled: acct.State.Status == inspectortypes.StatusEnabled, ScanEnabled: map[string]bool{}}
		var resources inspectortypes.ResourceState
		if acct.ResourceState != nil {
			resources = *acct.ResourceState
		}
		for resourceType, state := range map[string]*inspectortypes.State{
			InspectorEC2Instance:    resources.Ec2,
			InspectorECRImage:       resources.Ecr,
			InspectorLambdaFunction: resources.Lambda,
		} {
			status.ScanEnabled[resourceType] = status.Enabled && state != nil && state.Status == inspectortypes.StatusEnabled
		}
		return status, nil
	}
	return InspectorAccountStatus{}, errMissing(out.ResultMetadata, "BatchGetAccountStatus", "status for the account")
}

// CountInspectorCoverage counts the resources Amazon Inspector covers for
// accountID in region, by resource type, over every page of
// ListCoverageStatistics. With activeOnly, it counts only the resources whose
// scan status is ACTIVE, which are the ones being scanned. Coverage has an
// entry for each scan type on a resource, so only the PACKAGE entries are
// counted. A Lambda function with code scanning on also has a CODE entry.
func (c *AWSClient) CountInspectorCoverage(ctx context.Context, region, accountID string, activeOnly bool) (map[string]int, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	filter := &inspectortypes.CoverageFilterCriteria{
		AccountId: []inspectortypes.CoverageStringFilter{{Comparison: inspectortypes.CoverageStringComparisonEquals, Value: aws.String(accountID)}},
		ScanType: []inspectortypes.CoverageStringFilter{{
			Comparison: inspectortypes.CoverageStringComparisonEquals, Value: aws.String(string(inspectortypes.ScanTypePackage)),
		}},
	}
	if activeOnly {
		filter.ScanStatusCode = []inspectortypes.CoverageStringFilter{{
			Comparison: inspectortypes.CoverageStringComparisonEquals, Value: aws.String(string(inspectortypes.ScanStatusCodeActive)),
		}}
	}
	paginator := inspector2.NewListCoverageStatisticsPaginator(inspector2.NewFromConfig(cfg), &inspector2.ListCoverageStatisticsInput{
		FilterCriteria: filter,
		GroupBy:        inspectortypes.GroupKeyResourceType,
	})
	counts := map[string]int{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("counting the resources Inspector covers in %s: %w", region, err)
		}
		for _, group := range page.CountsByGroup {
			counts[string(group.GroupKey)] += int(group.Count)
		}
	}
	return counts, nil
}

// InspectorFinding is what the collector reads of one Amazon Inspector
// finding.
type InspectorFinding struct {
	// ResourceType is the type of the finding's resource, such as
	// AWS_EC2_INSTANCE.
	ResourceType string

	// Severity is CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, or UNTRIAGED.
	Severity string

	// FirstObservedAt is when the vulnerability was first observed.
	FirstObservedAt time.Time
}

// ListInspectorFindings calls visit with each ACTIVE Amazon Inspector
// finding on accountID's EC2 instances, ECR images, and Lambda functions in
// region, over every page of ListFindings. An administrator account's
// listing also holds its members' findings, which are left out.
func (c *AWSClient) ListInspectorFindings(ctx context.Context, region, accountID string, visit func(InspectorFinding)) error {
	cfg := c.cfg.Copy()
	cfg.Region = region
	equals := func(value string) inspectortypes.StringFilter {
		return inspectortypes.StringFilter{Comparison: inspectortypes.StringComparisonEquals, Value: aws.String(value)}
	}
	paginator := inspector2.NewListFindingsPaginator(inspector2.NewFromConfig(cfg), &inspector2.ListFindingsInput{
		FilterCriteria: &inspectortypes.FilterCriteria{
			AwsAccountId:  []inspectortypes.StringFilter{equals(accountID)},
			FindingStatus: []inspectortypes.StringFilter{equals(string(inspectortypes.FindingStatusActive))},
			ResourceType:  []inspectortypes.StringFilter{equals(InspectorEC2Instance), equals(InspectorECRImage), equals(InspectorLambdaFunction)},
		},
		MaxResults: aws.Int32(100),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("listing Inspector findings in %s: %w", region, err)
		}
		for _, f := range page.Findings {
			if aws.ToString(f.AwsAccountId) != accountID || f.Status != inspectortypes.FindingStatusActive || len(f.Resources) == 0 {
				continue
			}
			if f.FirstObservedAt == nil {
				return errMissing(page.ResultMetadata, "ListFindings", "firstObservedAt for a finding")
			}
			visit(InspectorFinding{
				ResourceType:    string(f.Resources[0].Type),
				Severity:        string(f.Severity),
				FirstObservedAt: f.FirstObservedAt.UTC(),
			})
		}
	}
	return nil
}
