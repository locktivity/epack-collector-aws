package collector

import (
	"net/http"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

const (
	cisRulesetARN   = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
	cisRulesetID    = "ruleset/cis-aws-foundations-benchmark/v/1.2.0"
	cisStandardARN  = "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0"
	cisStandardID   = "standards/cis-aws-foundations-benchmark/v/1.4.0"
	memberAccountID = "999900001111"
)

// cisFinding is a CIS control finding as Security Hub sends it, with no
// profile level in its related requirements.
func cisFinding(id, control, status, recordState, workflow, account string) map[string]any {
	return map[string]any{
		"SchemaVersion": "2018-10-08", "Id": id, "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub", "ProductName": "Security Hub",
		"GeneratorId": "security-control/" + control, "AwsAccountId": account, "CreatedAt": "2025-12-01T00:00:00Z", "UpdatedAt": "2025-12-31T00:00:00Z",
		"Title": control, "Description": "control finding", "Severity": map[string]any{"Label": "MEDIUM"},
		"Resources":  []any{map[string]any{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::" + id}},
		"Compliance": map[string]any{"Status": status, "SecurityControlId": control, "RelatedRequirements": []string{"CIS AWS Foundations Benchmark v1.4.0/2.1.5"}},
		"Workflow":   map[string]any{"Status": workflow}, "RecordState": recordState,
	}
}

// inspectorFinding is an Inspector package vulnerability finding on an EC2
// instance.
func inspectorFinding(id, instance, account string) map[string]any {
	return map[string]any{
		"SchemaVersion": "2018-10-08", "Id": id, "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/inspector", "ProductName": "Inspector",
		"GeneratorId": "AWSInspector", "AwsAccountId": account, "CreatedAt": "2025-12-10T00:00:00Z", "UpdatedAt": "2025-12-31T00:00:00Z",
		"Types": []string{"Software and Configuration Checks/Vulnerabilities/CVE"},
		"Title": "CVE-2025-0001 - openssl", "Description": "vulnerability", "Severity": map[string]any{"Label": "HIGH"},
		"Resources": []any{map[string]any{"Type": "AwsEc2Instance", "Id": "arn:aws:ec2:us-east-1:" + account + ":instance/" + instance}},
		"Workflow":  map[string]any{"Status": "NEW"}, "RecordState": "ACTIVE",
	}
}

// runSecurityHub runs the kit's account subscribed to one standard,
// standardsARN, whose findings carry standardsID, and returns its account
// security values.
func runSecurityHub(t *testing.T, standardsARN, standardsID string, cis, inspector []any) AccountSecurity {
	t.Helper()
	isolateAWSEnvironment(t)
	var responses []collectortest.Response
	for _, r := range kitResponses() {
		if r.Operation != "aws.securityhub.GetEnabledStandards" && r.Operation != "aws.securityhub.GetFindings" {
			responses = append(responses, r)
		}
	}
	findings := "https://securityhub.us-east-1.amazonaws.com/findings"
	responses = append(responses,
		restResponse("aws.securityhub.GetEnabledStandards", http.MethodPost, "https://securityhub.us-east-1.amazonaws.com/standards/get", 0, kitJSON(map[string]any{"StandardsSubscriptions": []any{map[string]any{
			"StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:111122223333:subscription/cis-aws-foundations-benchmark",
			"StandardsArn":             standardsARN, "StandardsStatus": "READY", "StandardsInput": map[string]string{},
		}}})),
		withRequestBody(restResponse("aws.securityhub.GetFindings", http.MethodPost, findings, 0, kitJSON(map[string]any{"Findings": cis})),
			map[string]any{"Filters": map[string]any{"ComplianceAssociatedStandardsId": []any{map[string]any{"Comparison": "EQUALS", "Value": standardsID}}}}),
		withRequestBody(restResponse("aws.securityhub.GetFindings", http.MethodPost, findings, 0, kitJSON(map[string]any{"Findings": inspector})),
			map[string]any{"Filters": map[string]any{"ProductName": []any{map[string]any{"Comparison": "PREFIX", "Value": "Inspector"}}}}),
	)
	res := runKit(t, kitConfig(), kitSecrets(), responses)
	if res.ExitCode != 0 {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	var detailed Output
	decodeArtifact(t, res, awsPath, &detailed)
	return detailed.Accounts[0].AccountSecurity
}

func wantCISLevel(t *testing.T, got CISComplianceByLevel, passed, failed, notAvailable int, state string, enabled bool) {
	t.Helper()
	if got.PassedControls != passed || got.FailedControls != failed || got.NotAvailableControls != notAvailable || got.ComplianceState != state || got.Enabled != enabled {
		t.Errorf("CIS = {enabled:%v passed:%d failed:%d not_available:%d state:%s}, want {enabled:%v passed:%d failed:%d not_available:%d state:%s}",
			got.Enabled, got.PassedControls, got.FailedControls, got.NotAvailableControls, got.ComplianceState, enabled, passed, failed, notAvailable, state)
	}
}

// CIS AWS Foundations Benchmark v1.2.0 has a ruleset ARN, and its controls
// count as those of v1.4.0 do.
func TestSecurityHub_CISRulesetStandardIsCounted(t *testing.T) {
	findings := []any{
		cisFinding("s3-1", "S3.1", "PASSED", "ACTIVE", "RESOLVED", kitAccountID),
		cisFinding("iam-9", "IAM.9", "FAILED", "ACTIVE", "NEW", kitAccountID),
	}
	for _, tc := range []struct{ name, arn, id string }{
		{"v1.4.0 standard", cisStandardARN, cisStandardID},
		{"v1.2.0 ruleset", cisRulesetARN, cisRulesetID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sec := runSecurityHub(t, tc.arn, tc.id, findings, nil)
			wantCISLevel(t, sec.SecurityHub.CISAWSFoundationsBenchmarkUnknownLevel, 1, 1, 0, "FAILED", true)
		})
	}
}

// Security Hub leaves archived and suppressed findings out of a control's
// status, and so does the collector.
func TestSecurityHub_ArchivedAndSuppressedFindingsDoNotDriveCISStatus(t *testing.T) {
	live := cisFinding("bucket-live", "S3.1", "PASSED", "ACTIVE", "RESOLVED", kitAccountID)
	for _, tc := range []struct {
		name    string
		finding map[string]any
		passed  int
		failed  int
		state   string
	}{
		{"active failed finding", cisFinding("bucket-b", "S3.1", "FAILED", "ACTIVE", "NEW", kitAccountID), 0, 1, "FAILED"},
		{"archived failed finding", cisFinding("bucket-deleted", "S3.1", "FAILED", "ARCHIVED", "NEW", kitAccountID), 1, 0, "PASSED"},
		{"suppressed failed finding", cisFinding("bucket-suppressed", "S3.1", "FAILED", "ACTIVE", "SUPPRESSED", kitAccountID), 1, 0, "PASSED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sec := runSecurityHub(t, cisStandardARN, cisStandardID, []any{live, tc.finding}, nil)
			wantCISLevel(t, sec.SecurityHub.CISAWSFoundationsBenchmarkUnknownLevel, tc.passed, tc.failed, 0, tc.state, true)
		})
	}

	// The standard is still enabled with no finding that counts.
	t.Run("only an archived not-available finding", func(t *testing.T) {
		cis := []any{cisFinding("config-gone", "IAM.9", "NOT_AVAILABLE", "ARCHIVED", "NEW", kitAccountID)}
		sec := runSecurityHub(t, cisStandardARN, cisStandardID, cis, nil)
		wantCISLevel(t, sec.SecurityHub.CISAWSFoundationsBenchmarkUnknownLevel, 0, 0, 0, "UNKNOWN", true)
	})
}

// A Security Hub administrator account's GetFindings also answers its member
// accounts' findings, which do not count for the collected account.
func TestSecurityHub_MemberAccountFindingsAreLeftOut(t *testing.T) {
	t.Run("Inspector", func(t *testing.T) {
		inspector := []any{inspectorFinding("f1", "i-0own1", kitAccountID), inspectorFinding("f2", "i-0member", memberAccountID)}
		got := runSecurityHub(t, cisStandardARN, cisStandardID, nil, inspector).Inspector
		if got.TotalAffectedResources != 1 || got.UnpatchedResources != 1 || got.TotalFindings == nil || *got.TotalFindings != 1 {
			t.Errorf("inspector = {affected:%d unpatched:%d findings:%s}, want the one finding on the account's own instance",
				got.TotalAffectedResources, got.UnpatchedResources, showPct(got.TotalFindings))
		}
	})

	t.Run("CIS", func(t *testing.T) {
		cis := []any{
			cisFinding("own", "S3.1", "PASSED", "ACTIVE", "RESOLVED", kitAccountID),
			cisFinding("member", "S3.1", "FAILED", "ACTIVE", "NEW", memberAccountID),
		}
		sec := runSecurityHub(t, cisStandardARN, cisStandardID, cis, nil)
		wantCISLevel(t, sec.SecurityHub.CISAWSFoundationsBenchmarkUnknownLevel, 1, 0, 0, "PASSED", true)
	})
}
