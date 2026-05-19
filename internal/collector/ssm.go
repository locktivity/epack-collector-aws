package collector

import (
	"context"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// collectSSMParameters collects Parameter Store posture for a single region.
// Parameter VALUES are not fetched — only metadata. One paginated
// DescribeParameters call supplies everything we need across all three levels.
func (c *Collector) collectSSMParameters(ctx context.Context, client *aws.AWSClient, region, accountID string, level componentsdk.Level) (*SSMParametersMetrics, error) {
	params, err := client.ListSSMParameters(ctx, region)
	if err != nil {
		return nil, err
	}

	out := &SSMParametersMetrics{
		ParameterCount: len(params),
	}
	for _, p := range params {
		if p.Type != SSMParameterTypeSecureString {
			continue
		}
		out.SecureStringCount++
		if !isCustomerKMS(p.KMSKeyARN) {
			out.SecureStringsWithoutCustomerKMSCount++
		}
	}

	if !level.AtLeast(componentsdk.LevelAudit) {
		return out, nil
	}

	out.Parameters = make([]SSMParameterRow, 0, len(params))
	for _, p := range params {
		out.Parameters = append(out.Parameters, ssmParameterToRow(p, region, accountID, level))
	}
	return out, nil
}

// isCustomerKMS distinguishes a customer-managed key reference from the
// AWS-managed `alias/aws/ssm` default. AWS returns either an alias name (with
// the `alias/aws/ssm` form), a customer alias, or a key ARN/UUID. Anything
// equal to (or starting with) the AWS-managed alias is treated as non-customer.
func isCustomerKMS(keyRef string) bool {
	if keyRef == "" {
		return false
	}
	return !strings.HasPrefix(keyRef, "alias/aws/")
}

// ssmParameterToRow projects an aws.SSMParameter onto its audit-level row.
// Internal-level fields (Description, KMSKeyARN) are populated when level >=
// internal — no extra API calls; the data is already in the DescribeParameters
// response.
//
// ARN is constructed from region + accountID + name. AWS doesn't return the
// ARN on DescribeParameters; it follows the documented format
// arn:aws:ssm:<region>:<account>:parameter<name> where name carries its
// leading slash as part of the suffix.
func ssmParameterToRow(p aws.SSMParameter, region, accountID string, level componentsdk.Level) SSMParameterRow {
	row := SSMParameterRow{
		Name:             p.Name,
		Region:           region,
		ARN:              ssmParameterARN(region, accountID, p.Name),
		Type:             p.Type,
		DataType:         p.DataType,
		Version:          p.Version,
		Tier:             p.Tier,
		LastModifiedUser: p.LastModifiedUser,
		HasCustomerKMS:   p.Type == SSMParameterTypeSecureString && isCustomerKMS(p.KMSKeyARN),
	}
	if p.LastModifiedDate != nil {
		row.LastModifiedDate = p.LastModifiedDate.UTC().Format(time.RFC3339)
	}
	if level.AtLeast(componentsdk.LevelInternal) {
		row.Description = p.Description
		row.KMSKeyARN = p.KMSKeyARN
	}
	return row
}

func ssmParameterARN(region, accountID, name string) string {
	// AWS docs say the ARN is `arn:aws:ssm:<region>:<account>:parameter<name>`
	// where <name> retains its leading slash. So a parameter named `/foo/bar`
	// becomes `arn:aws:ssm:us-east-1:123:parameter/foo/bar`. A parameter named
	// `foo` (no leading slash, the legacy form) becomes `parameter/foo`.
	if strings.HasPrefix(name, "/") {
		return "arn:aws:ssm:" + region + ":" + accountID + ":parameter" + name
	}
	return "arn:aws:ssm:" + region + ":" + accountID + ":parameter/" + name
}

// mergeSSMParametersMetrics combines per-region results. The orchestrator's
// normalizeForLevel pass is the single source of truth for the nil→[] flip
// at audit+.
func mergeSSMParametersMetrics(a, b SSMParametersMetrics) SSMParametersMetrics {
	return SSMParametersMetrics{
		ParameterCount:                       a.ParameterCount + b.ParameterCount,
		SecureStringCount:                    a.SecureStringCount + b.SecureStringCount,
		SecureStringsWithoutCustomerKMSCount: a.SecureStringsWithoutCustomerKMSCount + b.SecureStringsWithoutCustomerKMSCount,
		Parameters:                           append(append([]SSMParameterRow(nil), a.Parameters...), b.Parameters...),
	}
}
