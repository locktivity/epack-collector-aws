package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
)

// ListKMSCustomerKeys returns every CUSTOMER-managed KMS key in the region
// with the metadata needed for posture analysis. AWS-managed keys are filtered
// out because customers have no posture lever over them.
//
// Per key, this issues DescribeKey (always) and GetKeyRotationStatus (symmetric
// CMKs only — asymmetric keys reject the call). Aliases are sourced from a
// single per-region ListAliases call and joined into each row.
func (c *AWSClient) ListKMSCustomerKeys(ctx context.Context, region string) ([]KMSKey, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := kms.NewFromConfig(cfg)

	aliasesByKey, err := listKMSAliasesByKey(ctx, client)
	if err != nil {
		return nil, err
	}

	var keys []KMSKey
	paginator := kms.NewListKeysPaginator(client, &kms.ListKeysInput{})
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing KMS keys in %s: %w", region, err)
		}
		for _, k := range out.Keys {
			row, ok, err := projectKMSKey(ctx, client, aws.ToString(k.KeyId), aliasesByKey)
			if err != nil {
				return nil, err
			}
			if ok {
				keys = append(keys, row)
			}
		}
	}
	return keys, nil
}

// projectKMSKey fetches DescribeKey + (for symmetric CMKs) GetKeyRotationStatus
// and projects the result into our KMSKey shape. Returns ok=false for
// AWS-managed keys so the caller can filter them out without extra branches.
func projectKMSKey(ctx context.Context, client *kms.Client, keyID string, aliasesByKey map[string][]string) (KMSKey, bool, error) {
	descOut, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return KMSKey{}, false, fmt.Errorf("describing KMS key %s: %w", keyID, err)
	}
	m := descOut.KeyMetadata
	if m == nil || m.KeyManager != kmstypes.KeyManagerTypeCustomer {
		return KMSKey{}, false, nil
	}

	row := KMSKey{
		KeyID:        aws.ToString(m.KeyId),
		ARN:          aws.ToString(m.Arn),
		KeyState:     string(m.KeyState),
		KeyUsage:     string(m.KeyUsage),
		KeySpec:      string(m.KeySpec),
		Origin:       string(m.Origin),
		MultiRegion:  aws.ToBool(m.MultiRegion),
		CreationDate: m.CreationDate,
		DeletionDate: m.DeletionDate,
		Description:  aws.ToString(m.Description),
		Aliases:      aliasesByKey[keyID],
	}

	// Rotation only applies to symmetric CMKs whose key material AWS controls;
	// asymmetric, HMAC, and external/CloudHSM origin keys reject the call.
	if row.KeySpec == string(kmstypes.KeySpecSymmetricDefault) && row.Origin == string(kmstypes.OriginTypeAwsKms) {
		rotOut, err := client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: aws.String(keyID)})
		if err != nil {
			if !isExpectedRotationStatusError(err) {
				return KMSKey{}, false, fmt.Errorf("getting rotation status for KMS key %s: %w", keyID, err)
			}
		} else {
			row.RotationEnabled = rotOut.KeyRotationEnabled
		}
	}

	return row, true, nil
}

// isExpectedRotationStatusError matches the error codes AWS returns for keys
// that don't support rotation. Treated as "rotation not applicable" (false)
// rather than collection failure.
func isExpectedRotationStatusError(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "UnsupportedOperationException", "AccessDeniedException", "DisabledException":
		return true
	}
	return false
}

func listKMSAliasesByKey(ctx context.Context, client *kms.Client) (map[string][]string, error) {
	out := map[string][]string{}
	paginator := kms.NewListAliasesPaginator(client, &kms.ListAliasesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing KMS aliases: %w", err)
		}
		for _, a := range page.Aliases {
			targetID := aws.ToString(a.TargetKeyId)
			if targetID == "" {
				continue
			}
			out[targetID] = append(out[targetID], aws.ToString(a.AliasName))
		}
	}
	return out, nil
}
