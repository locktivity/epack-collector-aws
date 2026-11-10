package collector

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

// identifierRole is the second configured account's role, which AWS refuses.
const identifierRole = "arn:aws:iam::444455556666:role/epack-collector"

// identifierRun runs the kit tenant at level with two configured accounts:
// the kit account, labeled production and given an external ID that OIDC
// ignores, and a second account whose role AWS refuses. AWS also denies the
// password policy read, each IAM user's MFA device listing, and the KMS key's
// rotation status, with messages that hold the caller's role ARN, the account
// ID, and the resource's ARN.
func identifierRun(t *testing.T, level componentsdk.Level) componentsdk.InProcessResult {
	t.Helper()
	isolateAWSEnvironment(t)
	config := map[string]any{
		"auth_mode": "oidc",
		"level":     string(level),
		"accounts": []any{
			map[string]any{"role_arn": kitRoleARN, "label": "production", "external_id": "kit-external-id"},
			map[string]any{"role_arn": identifierRole},
		},
	}
	refused := withRequestBody(collectortest.Response{
		Operation: "aws.sts.AssumeRoleWithWebIdentity", Method: http.MethodPost, URL: kitSTSURL, Status: http.StatusForbidden, Header: xmlHeader(),
		Body: "<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>Not authorized to perform sts:AssumeRoleWithWebIdentity on " +
			identifierRole + "</Message></Error><RequestId>kit-request</RequestId></ErrorResponse>",
	}, formFields("aws.sts.AssumeRoleWithWebIdentity", map[string]string{"RoleArn": identifierRole}))
	mfaDenied := collectortest.Response{
		Operation: "aws.iam.ListMFADevices", Method: http.MethodPost, URL: kitIAMURL, Status: http.StatusForbidden, Header: xmlHeader(),
		Body: "<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>" + kitCaller +
			"iam:ListMFADevices on resource: arn:aws:iam::111122223333:user/bob because no identity-based policy allows the iam:ListMFADevices action" +
			"</Message></Error><RequestId>kit-request</RequestId></ErrorResponse>",
	}
	rotationDenied := collectortest.Response{
		Operation: "aws.kms.GetKeyRotationStatus", Method: http.MethodPost, URL: regional("kms"), Status: http.StatusBadRequest,
		Header: jsonHeader("application/x-amz-json-1.1"),
		Body: kitJSON(map[string]any{"__type": "AccessDeniedException", "message": kitCaller + "kms:GetKeyRotationStatus on resource: arn:aws:kms:us-east-1:111122223333:key/" +
			kitKMSKeyID + " because no identity-based policy allows the kms:GetKeyRotationStatus action"}),
	}
	responses := append([]collectortest.Response{refused}, replaceResponses(kitResponses(),
		iamDenied("aws.iam.GetAccountPasswordPolicy", "iam:GetAccountPasswordPolicy", "because no identity-based policy allows the iam:GetAccountPasswordPolicy action"),
		mfaDenied, rotationDenied)...)
	res := runKit(t, config, kitSecrets(), responses)
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	return res
}

// identifierValues are the values in the run that identify the company's
// accounts and resources: account IDs, ARNs, the organization ID, the
// identity store ID, the GuardDuty administrator, a KMS key ID, and IAM user
// names as warnings name them.
var identifierValues = []string{
	kitAccountID, "444455556666", "arn:aws", "o-kit12345678", kitStoreID, "ssoins-", "999900001111",
	kitKMSKeyID, "IAM user alice", "IAM user bob",
}

// A trust run writes no identifier of the company's accounts or resources:
// not in its data artifacts, not in the diagnostics, and not in the result.
// Its diagnostics name the account by its label or position and an error by
// its code. The build file is left out of the check: it holds the
// collector's schemas, whose descriptions give example ARNs, the same in
// every run.
func TestTrustRunWritesNoAccountIdentifiers(t *testing.T) {
	res := identifierRun(t, componentsdk.LevelTrust)
	for _, a := range res.Artifacts {
		if a.Path == "artifacts/aws.collector-build.json" {
			continue
		}
		for _, id := range identifierValues {
			if strings.Contains(string(a.Data), id) {
				t.Errorf("%s holds %q at trust", a.Path, id)
			}
		}
	}

	var out Output
	decodeArtifact(t, res, awsPath, &out)
	if len(out.Accounts) != 1 || out.Accounts[0].AccountLabel != "production" {
		t.Fatalf("accounts = %+v, want the production account", out.Accounts)
	}
	if len(out.FailedAccounts) != 1 || out.FailedAccounts[0].ErrorCode != "AccessDenied" {
		t.Errorf("failed accounts = %+v, want the second account's AccessDenied", out.FailedAccounts)
	}
	if out.Diagnostics == nil {
		t.Fatal("no diagnostics")
	}
	if want := []string{"failed to collect account 2: AccessDenied"}; !slices.Equal(out.Diagnostics.AccountErrors, want) {
		t.Errorf("account errors = %q, want %q", out.Diagnostics.AccountErrors, want)
	}
	for _, want := range []string{
		`external_id is ignored in OIDC mode for account "production"`,
		`account "production": failed to collect IAM account password policy: AccessDenied`,
		`account "production": failed to list MFA devices for an IAM user: AccessDenied`,
		`account "production" region us-east-1: failed to read rotation status for a KMS key: AccessDeniedException`,
	} {
		if !slices.Contains(out.Diagnostics.Warnings, want) {
			t.Errorf("warnings = %q, want %q", out.Diagnostics.Warnings, want)
		}
	}
	if len(res.Result.Warnings) != 0 {
		t.Errorf("result warnings = %+v, want none", res.Result.Warnings)
	}
}

// An audit run writes the identifiers a trust run leaves out, and its
// diagnostics read as they always have.
func TestAuditRunWritesAccountIdentifiers(t *testing.T) {
	res := identifierRun(t, componentsdk.LevelAudit)

	var doc any
	decodeArtifact(t, res, awsPath, &doc)
	expectValues(t, doc, map[string]any{
		"/accounts/0/account_id":               kitAccountID,
		"/accounts/0/iam/root_organization_id": "o-kit12345678",
		"/accounts/0/account_security/guardduty/finding_notification/administrator_account_id": "999900001111",
		"/accounts/0/identity_center/instance_arn":                                             kitInstanceARN,
		"/accounts/0/identity_center/instance_owner_account_id":                                kitAccountID,
		"/accounts/0/identity_center/identity_store_id":                                        kitStoreID,
		"/failed_accounts/0/account_id":                                                        "444455556666",
		"/failed_accounts/0/role_arn":                                                          identifierRole,
	})

	var out Output
	decodeArtifact(t, res, awsPath, &out)
	if len(out.Diagnostics.AccountErrors) != 1 || !strings.HasPrefix(out.Diagnostics.AccountErrors[0], "failed to collect account ("+identifierRole+"): ") {
		t.Errorf("account errors = %q, want the second account named by its role", out.Diagnostics.AccountErrors)
	}
	for _, want := range []string{
		"external_id is ignored in OIDC mode for role " + kitRoleARN,
		"account " + kitAccountID + ": failed to collect IAM account password policy: ",
		"account " + kitAccountID + ": failed to list MFA devices for IAM user bob: ",
		"account " + kitAccountID + " region us-east-1: failed to read rotation status for KMS key " + kitKMSKeyID + ": ",
	} {
		if !slices.ContainsFunc(out.Diagnostics.Warnings, func(w string) bool { return strings.HasPrefix(w, want) }) {
			t.Errorf("warnings = %q, want one starting %q", out.Diagnostics.Warnings, want)
		}
	}

	for path, pointer := range map[string]string{cloudPosturePath: "/accounts/0/account_id", accessPosturePath: "/scopes/0/id", vulnScanningPath: "/scopes/0/id"} {
		var normalized any
		decodeArtifact(t, res, path, &normalized)
		expectValues(t, normalized, map[string]any{pointer: kitAccountID})
	}
}
