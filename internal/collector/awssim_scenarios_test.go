package collector

import (
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// The simulated accounts are rosters the AWS simulator answers for, each
// with the values roster.Derive computes from it. A value the collector
// reports otherwise is listed with a verdict and a note that says where in
// the collector's code it was checked, so a new difference fails, and so
// does a listed one that goes away. The sandbox's expectations.yaml in
// epack-collector-sandboxes gives the same differences their verdicts, and
// definitions.yaml there holds the questions a definition verdict names.

// simStanding are the differences every account shows.
var simStanding = simulate.Same(simulate.Gap,
	"storageNetworkUnsupported in normalized.go: S3 has no setting that turns off public network access, so the collector leaves the values out with an unsupported gap.",
	"/accounts/0/storage/network_restricted_pct", "/accounts/0/storage/network_restricted_storage_resource_count",
).With(simulate.Same(simulate.Definition,
	"workforce-not-in-use in definitions.yaml: normalizedWorkforceSignIn in deprecated.go writes user_count and mfa_source only while Identity Center is in use, which the sandbox's account instance never is.",
	"/workforce_sign_in/user_count", "/workforce_sign_in/mfa_source",
), simulate.Same(simulate.Gap,
	"accessPostureLeftOut in access_posture.go: AWS has no account setting that requires SSO, or MFA, of everyone, and doesn't say whether Identity Center users come through SCIM, so the collector leaves these out with an unsupported gap. definitions.yaml asks sign-in-requirement-without-setting of the first two.",
	simAccessBoth("/sign_in/sso_required", "/sign_in/mfa_required", "/sign_in/scim_enabled")...,
), simulate.Same(simulate.Gap,
	"externalMembersUnsupported in access_posture.go: IAM has no guest or outside users, so the collector leaves the external member values out with an unsupported gap. definitions.yaml asks external-members-without-guests of them.",
	simAccessBoth("/members/external_members_present", "/members/external_member_count")...,
))

// simAccessBoth is each access-posture pointer in the totals and in the
// account's scope.
func simAccessBoth(pointers ...string) []string {
	var out []string
	for _, p := range pointers {
		out = append(out, "access-posture:"+p, "access-posture:/scopes/0"+p)
	}
	return out
}

// simNoDatabase is the difference an account with no database shows.
var simNoDatabase = simulate.Same(simulate.Definition,
	"backup-without-databases in definitions.yaml: normalizedBackup in normalized.go leaves the backup group out when the account has no database, and Derive gives the null minimum the schema calls for when no resource has backups.",
	"/accounts/0/backup/retention_days_min")

// simUnrecorded lists the answers the sandbox's recording can't vouch
// for, with why. Each body follows the service's API reference.
var simUnrecorded = map[string]string{
	"aws.iam.ListAttachedUserPolicies: unrecorded operation":                                                                    simPolicyReadsUnrecorded,
	"aws.iam.ListUserPolicies: unrecorded operation":                                                                            simPolicyReadsUnrecorded,
	"aws.iam.ListGroupsForUser: unrecorded operation":                                                                           simPolicyReadsUnrecorded,
	"aws.iam.ListAttachedGroupPolicies: unrecorded operation":                                                                   simPolicyReadsUnrecorded,
	"aws.iam.ListGroupPolicies: unrecorded operation":                                                                           simPolicyReadsUnrecorded,
	"aws.iam.GetGroupPolicy: unrecorded operation":                                                                              simPolicyReadsUnrecorded,
	"aws.iam.GetUser: unrecorded operation":                                                                                     simPolicyReadsUnrecorded,
	"aws.iam.GetPolicy: unrecorded operation":                                                                                   simNoManagedPolicy,
	"aws.iam.GetPolicyVersion: unrecorded operation":                                                                            simNoManagedPolicy,
	"aws.iam.GetUserPolicy: unrecorded operation":                                                                               simNoUserPolicy,
	"aws.iam.ListSAMLProviders ListSAMLProvidersResponse.ListSAMLProvidersResult[].SAMLProviderList[]: type":                    "the sandbox account trusts no SAML provider, so IAM lists none",
	"aws.iam.ListSAMLProviders ListSAMLProvidersResponse.ListSAMLProvidersResult[].SAMLProviderList[].member: unrecorded field": "the sandbox account trusts no SAML provider, so IAM lists none",
	"aws.ec2.DescribeSecurityGroups DescribeSecurityGroupsResponse.securityGroupInfo[].item[].ipPermissions[].item[].fromPort: missing field":   "the sandbox has no rule for all traffic, which EC2 lists with no ports",
	"aws.ec2.DescribeSecurityGroups DescribeSecurityGroupsResponse.securityGroupInfo[].item[].ipPermissions[].item[].toPort: missing field":     "the sandbox has no rule for all traffic, which EC2 lists with no ports",
	"aws.s3.GetBucketLocation LocationConstraint.#text: unrecorded field":                                                                       "every sandbox bucket is in us-east-1, whose location S3 answers empty",
	"aws.s3.GetBucketEncryption ServerSideEncryptionConfiguration.Rule[].ApplyServerSideEncryptionByDefault[].KMSMasterKeyID: unrecorded field": "every sandbox bucket uses SSE-S3, which names no KMS key",
	"aws.rds.DescribeDBInstances DescribeDBInstancesResponse.DescribeDBInstancesResult[].DBInstances[]: type":                                   "the sandbox runs no database, which no profile metric justifies the cost of",
	"aws.rds.DescribeDBInstances DescribeDBInstancesResponse.DescribeDBInstancesResult[].DBInstances[].DBInstance: unrecorded field":            "the sandbox runs no database, which no profile metric justifies the cost of",
	"aws.kms.GetKeyRotationStatus: unrecorded operation":                                                                                        "the sandbox has no customer managed KMS key, so the collector never reads a key's rotation",
}

// Why the IAM policy reads are unrecorded.
const (
	simPolicyReadsUnrecorded = "the recording predates the reads of the policies of the IAM users with access keys, and the sandbox's IAM users have no console password, so the collector never checked them for administrator access"
	simNoManagedPolicy       = "no sandbox IAM user or group has a managed policy attached, so the collector never reads one's default version"
	simNoUserPolicy          = "no sandbox IAM user has an inline policy of its own, only its group's"
)

// simUncompared lists the fields the collector writes that the rosters
// give no value for, with why.
var simUncompared = map[string]string{
	"/accounts/*/vuln_scanning/enabled": "The sandbox never turned Amazon Inspector on, so its roster has no scanning block and Derive gives no vulnerability scanning values. The simulator answers Inspector and Security Hub with the recording's answers.",
}

// simNoConsoleUsers are the differences an account with no IAM user who
// signs in shows.
var simNoConsoleUsers = simulate.Same(simulate.Known,
	"normalizedIAM in deprecated.go leaves the deprecated mfa_coverage_pct out with no gap over no users, as v0.6 did and TestToCloudPosture_IAMCounts pins, where its replacement local_mfa_coverage_pct is null. The deprecated field has no x-epack-null or denominator for a null to rest on.",
	"/accounts/0/iam/mfa_coverage_pct")

func simScenarios(t testing.TB) []simulate.Scenario {
	return []simulate.Scenario{{Name: "sandbox", Roster: simBase(t), Differences: simNoDatabase.With(simNoConsoleUsers)}}
}

func TestSimulatedAccounts(t *testing.T) {
	simHarness(t, simStanding).Tenants(t, simScenarios(t))
}

// Every answer the simulator gives, for the sandbox and for each matrix
// row, keeps the recording's shape, and each simUnrecorded listing is one
// some roster still needs.
func TestSimulatorShapes(t *testing.T) {
	rosters := []*roster.Roster{simBase(t)}
	base, axes := simMatrixBase(t), simMatrixAxes()
	for _, row := range append(roster.OneAtATime(axes), roster.Pairwise(axes)...) {
		v, err := roster.Build(base, axes, row)
		if err != nil {
			t.Fatal(err)
		}
		rosters = append(rosters, v.Roster)
	}
	simHarness(t, simStanding).CheckRecorded(t, rosters...)
}
