package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

// Bucket transport enforcement classification. S3's API endpoints answer both
// HTTP and HTTPS, so the only thing that forces TLS at the bucket layer is a
// policy statement denying requests where aws:SecureTransport is false.
//
// The classifier is deliberately conservative in one direction only: "enforced"
// requires a deny that conclusively covers every principal, every S3 action,
// and the whole bucket, with the transport check as its only condition. A
// statement that gestures at transport without meeting that bar is "partial",
// because a confident wrong "enforced" is the worst answer this surface could
// give. "none" is determinate: nothing in the policy addresses transport, so
// plaintext requests are allowed.
const (
	tlsEnforcementEnforced = "enforced"
	tlsEnforcementPartial  = "partial"
	tlsEnforcementNone     = "none"
	tlsEnforcementUnknown  = "unknown"
)

// classifyBucketTransport fetches each bucket's policy and classifies its TLS
// enforcement. The policy document itself is discarded here; internal-level
// enrichment refetches it for the inventory rows.
func (c *Collector) classifyBucketTransport(ctx context.Context, client s3BucketEnricher, buckets []aws.Bucket) map[string]string {
	out := make(map[string]string, len(buckets))
	for _, b := range buckets {
		region := b.Region
		if region == "" {
			region = "us-east-1"
		}
		policy, err := client.GetBucketPolicy(ctx, region, b.Name)
		switch {
		case err != nil:
			out[b.Name] = tlsEnforcementUnknown
		case policy == nil:
			out[b.Name] = tlsEnforcementNone
		default:
			out[b.Name] = classifyTransportEnforcement(policy.Document, b.Name)
		}
	}
	return out
}

// flexibleStrings accepts the scalar-or-array shapes policy JSON uses freely,
// plus bare booleans in condition values.
type flexibleStrings []string

func (f *flexibleStrings) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*f = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err == nil {
		*f = many
		return nil
	}
	var anything interface{}
	if err := json.Unmarshal(b, &anything); err != nil {
		return err
	}
	switch v := anything.(type) {
	case bool:
		*f = []string{fmt.Sprintf("%t", v)}
	case []interface{}:
		for _, item := range v {
			*f = append(*f, fmt.Sprintf("%v", item))
		}
	default:
		*f = []string{fmt.Sprintf("%v", v)}
	}
	return nil
}

type policyStatements []policyStatement

func (s *policyStatements) UnmarshalJSON(b []byte) error {
	var many []policyStatement
	if err := json.Unmarshal(b, &many); err == nil {
		*s = many
		return nil
	}
	var one policyStatement
	if err := json.Unmarshal(b, &one); err != nil {
		return err
	}
	*s = []policyStatement{one}
	return nil
}

type policyStatement struct {
	Effect       string                                `json:"Effect"`
	Principal    json.RawMessage                       `json:"Principal"`
	NotPrincipal json.RawMessage                       `json:"NotPrincipal"`
	Action       flexibleStrings                       `json:"Action"`
	NotAction    flexibleStrings                       `json:"NotAction"`
	Resource     flexibleStrings                       `json:"Resource"`
	NotResource  flexibleStrings                       `json:"NotResource"`
	Condition    map[string]map[string]flexibleStrings `json:"Condition"`
}

// classifyTransportEnforcement classifies a non-empty policy document.
func classifyTransportEnforcement(document, bucket string) string {
	var policy struct {
		Statement policyStatements `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(document), &policy); err != nil {
		return tlsEnforcementUnknown
	}

	sawTransportDeny := false
	for _, stmt := range policy.Statement {
		if !strings.EqualFold(stmt.Effect, "Deny") || !deniesInsecureTransport(stmt.Condition) {
			continue
		}
		sawTransportDeny = true
		if statementConclusivelyCoversBucket(stmt, bucket) {
			return tlsEnforcementEnforced
		}
	}
	if sawTransportDeny {
		return tlsEnforcementPartial
	}
	return tlsEnforcementNone
}

// deniesInsecureTransport reports whether the condition matches requests made
// without TLS. Operator and key compare case-insensitively, as IAM does.
// BoolIfExists is equivalent to Bool here because aws:SecureTransport is
// present on every request.
func deniesInsecureTransport(condition map[string]map[string]flexibleStrings) bool {
	for operator, keys := range condition {
		op := strings.ToLower(operator)
		if op != "bool" && op != "boolifexists" {
			continue
		}
		for key, values := range keys {
			if !strings.EqualFold(key, "aws:SecureTransport") {
				continue
			}
			for _, v := range values {
				if strings.EqualFold(v, "false") {
					return true
				}
			}
		}
	}
	return false
}

// statementConclusivelyCoversBucket reports whether the deny covers every
// request to the bucket. Any Not* form and any condition beyond the transport
// check narrows the deny, so both disqualify: a narrower deny still helps, but
// it does not prove enforcement.
func statementConclusivelyCoversBucket(stmt policyStatement, bucket string) bool {
	if stmt.NotPrincipal != nil || len(stmt.NotAction) > 0 || len(stmt.NotResource) > 0 {
		return false
	}
	if len(stmt.Condition) != 1 {
		return false
	}
	for _, keys := range stmt.Condition {
		if len(keys) != 1 {
			return false
		}
	}
	return principalCoversEveryone(stmt.Principal) &&
		actionsCoverAllS3(stmt.Action) &&
		resourcesCoverWholeBucket(stmt.Resource, bucket)
}

func principalCoversEveryone(raw json.RawMessage) bool {
	if raw == nil {
		return false
	}
	var star string
	if err := json.Unmarshal(raw, &star); err == nil {
		return star == "*"
	}
	var byService map[string]flexibleStrings
	if err := json.Unmarshal(raw, &byService); err != nil {
		return false
	}
	for service, values := range byService {
		if !strings.EqualFold(service, "AWS") {
			continue
		}
		for _, v := range values {
			if v == "*" {
				return true
			}
		}
	}
	return false
}

func actionsCoverAllS3(actions flexibleStrings) bool {
	for _, a := range actions {
		if a == "*" || strings.EqualFold(a, "s3:*") {
			return true
		}
	}
	return false
}

// resourcesCoverWholeBucket requires both the bucket itself and its objects,
// matched by suffix so every partition (aws, aws-cn, aws-us-gov) passes.
func resourcesCoverWholeBucket(resources flexibleStrings, bucket string) bool {
	bucketARN := ":s3:::" + bucket
	objectsARN := ":s3:::" + bucket + "/*"

	coversBucket, coversObjects := false, false
	for _, r := range resources {
		if r == "*" {
			return true
		}
		if strings.HasSuffix(r, bucketARN) {
			coversBucket = true
		}
		if strings.HasSuffix(r, objectsARN) {
			coversObjects = true
		}
	}
	return coversBucket && coversObjects
}
