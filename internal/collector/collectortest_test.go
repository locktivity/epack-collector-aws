package collector

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

// kitOperations lists every operation the collector calls.
var kitOperations = []string{
	"github.id_token.get",
	"aws.sts.AssumeRoleWithWebIdentity",
	"aws.sts.GetCallerIdentity",
	"aws.ec2.DescribeRegions",
	"aws.iam.ListAccountAliases",
	"aws.iam.GenerateCredentialReport",
	"aws.iam.GetCredentialReport",
	"aws.iam.GetAccountSummary",
	"aws.iam.GetAccountPasswordPolicy",
	"aws.iam.ListOrganizationsFeatures",
	"aws.iam.ListMFADevices",
	"aws.iam.ListRoles",
	"aws.iam.ListSAMLProviders",
	"aws.organizations.ListAccounts",
	"aws.s3.ListBuckets",
	"aws.s3.GetBucketLocation",
	"aws.s3.GetPublicAccessBlock",
	"aws.s3.GetBucketEncryption",
	"aws.s3.GetBucketVersioning",
	"aws.s3.GetBucketLogging",
	"aws.s3.GetBucketPolicy",
	"aws.s3.GetBucketAcl",
	"aws.s3.GetBucketLifecycleConfiguration",
	"aws.s3.GetObjectLockConfiguration",
	"aws.s3control.GetPublicAccessBlock",
	"aws.cloudfront.ListDistributions",
	"aws.rds.DescribeDBInstances",
	"aws.rds.DescribeDBClusters",
	"aws.rds.DescribeDBParameters",
	"aws.rds.DescribeEventSubscriptions",
	"aws.sns.ListSubscriptionsByTopic",
	"aws.ec2.DescribeVpcs",
	"aws.ec2.DescribeFlowLogs",
	"aws.ec2.DescribeSecurityGroups",
	"aws.ec2.DescribeInstances",
	"aws.ec2.DescribeVolumes",
	"aws.ec2.DescribeSnapshots",
	"aws.ec2.DescribeImages",
	"aws.lambda.ListFunctions",
	"aws.lambda.GetPolicy",
	"aws.lambda.ListFunctionUrlConfigs",
	"aws.cloudwatchlogs.DescribeLogGroups",
	"aws.cloudwatch.DescribeAlarms",
	"aws.elasticloadbalancingv2.DescribeLoadBalancers",
	"aws.elasticloadbalancingv2.DescribeListeners",
	"aws.elasticloadbalancingv2.DescribeTargetGroups",
	"aws.sesv2.ListConfigurationSets",
	"aws.sesv2.GetConfigurationSet",
	"aws.sesv2.ListEmailIdentities",
	"aws.sesv2.GetEmailIdentity",
	"aws.ecs.ListClusters",
	"aws.ecs.ListServices",
	"aws.ecs.DescribeServices",
	"aws.applicationautoscaling.DescribeScalableTargets",
	"aws.applicationautoscaling.DescribeScalingPolicies",
	"aws.autoscaling.DescribePolicies",
	"aws.autoscaling.DescribeAutoScalingGroups",
	"aws.kms.ListAliases",
	"aws.kms.ListKeys",
	"aws.kms.DescribeKey",
	"aws.kms.GetKeyRotationStatus",
	"aws.secretsmanager.ListSecrets",
	"aws.ssm.DescribeParameters",
	"aws.wafv2.ListWebACLs",
	"aws.wafv2.GetWebACL",
	"aws.wafv2.ListResourcesForWebACL",
	"aws.wafv2.GetLoggingConfiguration",
	"aws.cloudtrail.DescribeTrails",
	"aws.cloudtrail.GetTrailStatus",
	"aws.configservice.DescribeConfigurationRecorders",
	"aws.configservice.DescribeConfigurationRecorderStatus",
	"aws.configservice.DescribeConfigRules",
	"aws.configservice.DescribeComplianceByConfigRule",
	"aws.configservice.DescribeConfigRuleEvaluationStatus",
	"aws.guardduty.ListDetectors",
	"aws.guardduty.GetDetector",
	"aws.guardduty.ListFindings",
	"aws.guardduty.GetFindings",
	"aws.guardduty.GetAdministratorAccount",
	"aws.eventbridge.ListRules",
	"aws.eventbridge.ListTargetsByRule",
	"aws.accessanalyzer.ListAnalyzers",
	"aws.accessanalyzer.ListFindings",
	"aws.securityhub.DescribeHub",
	"aws.securityhub.GetEnabledStandards",
	"aws.securityhub.ListEnabledProductsForImport",
	"aws.securityhub.GetFindings",
	"aws.ssoadmin.ListInstances",
	"aws.identitystore.ListUsers",
	"aws.identitystore.ListGroups",
	"aws.identitystore.ListGroupMemberships",
	"aws.ssoadmin.ListPermissionSets",
	"aws.ssoadmin.DescribePermissionSet",
	"aws.ssoadmin.ListAccountsForProvisionedPermissionSet",
	"aws.ssoadmin.ListManagedPoliciesInPermissionSet",
	"aws.ssoadmin.GetInlinePolicyForPermissionSet",
	"aws.ssoadmin.ListAccountAssignments",
}

// kitResultPath is where the kit's runs write their collector result.
const kitResultPath = "artifacts/aws.collector-result.json"

// kitSteps are a clean internal-level run's steps in order, with their
// titles: one account's sign-in, the account-wide reads, each surface the
// regions scan, and the security services.
var kitSteps = [][2]string{
	{"sign_in", "Sign in"},
	{"account", "Account alias and regions"},
	{"iam", "IAM users, roles, and password policy"},
	{"s3", "S3 buckets"},
	{"cloudfront", "CloudFront distributions"},
	{"rds", "RDS databases"},
	{"network", "VPCs and security groups"},
	{"lambda", "Lambda functions"},
	{"ec2", "EC2 instances and volumes"},
	{"cloudwatch_logs", "CloudWatch log groups"},
	{"monitoring", "CloudWatch alarms"},
	{"stored_images", "EBS snapshots and AMIs"},
	{"load_balancers", "Load balancers"},
	{"ses", "SES configuration sets and identities"},
	{"ecs", "ECS services"},
	{"auto_scaling", "Auto Scaling groups"},
	{"kms", "KMS keys"},
	{"secrets_manager", "Secrets Manager secrets"},
	{"ssm_parameters", "SSM parameters"},
	{"waf", "WAF web ACLs"},
	{"cloudtrail", "CloudTrail trails"},
	{"config", "AWS Config"},
	{"guardduty", "GuardDuty"},
	{"access_analyzer", "IAM Access Analyzer"},
	{"security_hub", "Security Hub"},
	{"inspector", "Inspector"},
	{"identity_center", "IAM Identity Center"},
}

// kitStepPins pins the steps in order, and that there are no more.
func kitStepPins() map[string]any {
	pins := map[string]any{}
	for i, s := range kitSteps {
		pins[fmt.Sprintf("/steps/%d/name", i)] = s[0]
		pins[fmt.Sprintf("/steps/%d/title", i)] = s[1]
	}
	pins[fmt.Sprintf("/steps/%d", len(kitSteps))] = collectortest.Absent
	return pins
}

// isolateAWSEnvironment keeps the AWS SDK's default configuration from
// reading the developer's or CI's own profile, region, and credentials.
func isolateAWSEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN", "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ENDPOINT_URL",
		"AWS_USE_FIPS_ENDPOINT", "AWS_USE_DUALSTACK_ENDPOINT", "AWS_STS_REGIONAL_ENDPOINTS", "AWS_CA_BUNDLE",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("AWS_CONFIG_FILE", "/nonexistent/aws/config")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/aws/credentials")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

func kitSuite() collectortest.Suite {
	return collectortest.Suite{
		Spec:    Spec("test", "collectortest"),
		Run:     Run,
		Config:  kitConfig(),
		Secrets: kitCanaries(),
		Clock:   kitClock,
		Scenarios: []collectortest.Scenario{
			{
				// The account-level block covers ACLs only, so each bucket's
				// own block decides it, and a fault on that read leaves a gap.
				// Each per-item call gets its own answer: bob's MFA device is
				// virtual, and the account's snapshot is not public. A count
				// that reads 0, such as the distribution's HTTP origins, is
				// emitted. The group open to the world on all traffic counts
				// as open on SSH and RDP alike. The account owns its
				// organization's Identity Center instance and holds no
				// Identity Center roles, so the instance alone shows it in use.
				Name:      "clean",
				Responses: kitResponses(),
				Expect: map[string]map[string]any{awsPath: {
					"/accounts/0/s3/account_public_access_block_enabled":                         false,
					"/accounts/0/s3/public_access_blocked":                                       50,
					"/accounts/0/s3/buckets/0/public_access_blocked":                             false,
					"/accounts/0/s3/buckets/1/public_access_blocked":                             true,
					"/accounts/0/account_security/cloudtrail/trails/0/bucket_public_access":      "blocked",
					"/accounts/0/iam/hardware_mfa_enabled":                                       33,
					"/accounts/0/iam/hardware_mfa_enabled_user_count":                            1,
					"/accounts/0/stored_images/snapshot_count":                                   1,
					"/accounts/0/stored_images/public_snapshot_count":                            0,
					"/accounts/0/stored_images/public_snapshots":                                 []any{},
					"/accounts/0/rds/instances/0/dml_logging":                                    "configured",
					"/accounts/0/rds/instances/0/db_port_ingress_sources":                        []any{"sg-0web"},
					"/accounts/0/rds/backup_failure_alerting_reaching_subscriber_count":          1,
					"/accounts/0/load_balancers/load_balancers/0/listeners/1/redirects_to_https": true,
					"/accounts/0/account_security/inspector/patched_findings":                    0,
					"/accounts/0/cloudfront/distributions/0/http_only_origin_count":              0,
					"/accounts/0/cloudfront/distributions/0/match_viewer_origin_count":           0,
					"/accounts/0/auto_scaling/groups/0/suspended_process_count":                  0,
					"/accounts/0/monitoring/alarms/0/other_action_count":                         0,
					"/accounts/0/network/open_to_world_ssh":                                      50,
					"/accounts/0/network/open_to_world_rdp":                                      25,
					"/accounts/0/network/security_groups/3/open_to_world_ssh":                    true,
					"/accounts/0/network/security_groups/3/open_to_world_rdp":                    true,
					"/accounts/0/iam/saml_provider_count":                                        0,
					"/accounts/0/iam/identity_center_role_count":                                 0,
					"/accounts/0/identity_center/instance_status":                                "ACTIVE",
					"/accounts/0/identity_center/instance_owner_account_id":                      kitAccountID,
					"/accounts/0/identity_center/instance_type":                                  "organization",
					"/accounts/0/identity_center/regions_checked":                                []any{kitRegion},
					"/accounts/0/identity_center/external_id_user_count":                         0,
					"/accounts/0/identity_center/mfa_evidence":                                   "manual_required",
				}, cloudPosturePath: {
					"/accounts/0/iam/user_count":            3,
					"/accounts/0/iam/access_key_user_count": 2,
					"/accounts/0/iam/saml_provider_count":   0,
					"/workforce_sign_in/in_use":             true,
					"/workforce_sign_in/user_count":         2,
					"/workforce_sign_in/mfa_source":         "sign_in_service",
				}, kitResultPath: kitStepPins()},
			},
			{
				// The account's block sets every flag, so it decides each
				// bucket even though neither bucket's own block can be read.
				Name:      "account block covers unreadable buckets",
				Responses: accountBlockCoversResponses(),
				Expect: map[string]map[string]any{
					awsPath: {
						"/accounts/0/s3/account_public_access_block_enabled":                                true,
						"/accounts/0/s3/public_access_blocked":                                              100,
						"/accounts/0/s3/public_access_block_unknown_count":                                  0,
						"/accounts/0/s3/buckets/0/public_access_blocked":                                    true,
						"/accounts/0/s3/buckets/1/public_access_blocked":                                    true,
						"/accounts/0/account_security/cloudtrail/trails/0/bucket_public_access":             "blocked",
						"/accounts/0/account_security/cloudtrail/trails/1/bucket_public_access":             "blocked",
						"/accounts/0/account_security/cloudtrail/trail_buckets_public_access_blocked_count": 1,
					},
					cloudPosturePath: {"/accounts/0/storage/public_access_blocked_pct": 100},
				},
			},
			{
				// The account's block sets the ACL flags and the log bucket's
				// own block the policy flags. S3 enforces a flag when either
				// side sets it, so the bucket is blocked, and the rows of the
				// trails delivering to it agree with its own row.
				Name:      "account and bucket blocks split the flags",
				Responses: splitBlockResponses(),
				Expect: map[string]map[string]any{awsPath: {
					"/accounts/0/s3/public_access_blocked":                                                  50,
					"/accounts/0/s3/buckets/1/public_access_blocked":                                        true,
					"/accounts/0/account_security/cloudtrail/trails/0/bucket_public_access":                 "blocked",
					"/accounts/0/account_security/cloudtrail/trails/1/bucket_public_access":                 "blocked",
					"/accounts/0/account_security/cloudtrail/trail_buckets_public_access_blocked_count":     1,
					"/accounts/0/account_security/cloudtrail/trail_buckets_public_access_not_blocked_count": 0,
				}},
			},
			{
				Name:      "empty account",
				Responses: emptyAccountResponses(),
				Expect: map[string]map[string]any{awsPath: {
					"/accounts/0/iam/iam_user_count":                              0,
					"/accounts/0/iam/mfa_enabled":                                 nil,
					"/accounts/0/s3/bucket_count":                                 0,
					"/accounts/0/s3/public_access_blocked":                        nil,
					"/accounts/0/rds/database_count":                              0,
					"/accounts/0/rds/encrypted_at_rest":                           nil,
					"/accounts/0/iam/users":                                       []any{},
					"/accounts/0/lambda/functions":                                []any{},
					"/accounts/0/s3/buckets":                                      []any{},
					"/accounts/0/account_security/security_hub/integration_count": collectortest.Absent,
					"/accounts/0/monitoring/alarm_count":                          0,
					"/accounts/0/iam/mfa_enabled_user_count":                      0,
					"/accounts/0/s3/public_access_blocked_bucket_count":           0,
					"/accounts/0/rds/encrypted_at_rest_database_count":            0,
					"/accounts/0/network/open_to_world_ssh_security_group_count":  0,
					"/accounts/0/waf/covered_internet_facing_alb_count":           0,
					"/accounts/0/waf/internet_facing_alb_coverage_pct":            nil,
				}},
			},
			{
				// An account always has enabled regions, so an empty list is
				// not an answer: every regional surface is left out rather
				// than read as empty.
				Name:      "region list comes back empty",
				Responses: emptyRegionListResponses(),
				Expect: map[string]map[string]any{awsPath: {
					"/accounts/0/regions":            nil,
					"/accounts/0/ec2/instance_count": nil,
					"/accounts/0/monitoring":         nil,
				}},
			},
			{
				// EC2 fails a read that names a group it does not have, so an
				// answer without the database's group is incomplete. The
				// database's reachability is left out with a gap, not counted
				// as closed.
				Name:      "group read by ID comes back empty",
				Responses: emptyGroupReadResponses(),
				Expect: map[string]map[string]any{awsPath: {
					"/accounts/0/rds/db_port_open_to_internet_count":      nil,
					"/accounts/0/rds/instances/0/db_port_ingress_sources": nil,
				}},
			},
			{
				// A count that reads 0 is emitted, since an absent count reads
				// as unknown.
				Name:      "counts that read zero",
				Responses: zeroCountResponses(),
				Expect: map[string]map[string]any{awsPath: {
					"/accounts/0/account_security/security_hub/integration_count":            0,
					"/accounts/0/account_security/security_hub/product_subscriptions":        []any{},
					"/accounts/0/ecs/services/0/subnet_count":                                0,
					"/accounts/0/cloudfront/distributions/0/http_only_origin_count":          1,
					"/accounts/0/cloudfront/distributions/0/https_only_origin_count":         0,
					"/accounts/0/cloudfront/distributions/0/s3_origin_count":                 0,
					"/accounts/0/account_security/guardduty/finding_notification/rule_count": 0,
				}},
			},
			{
				// KMS rotates only symmetric keys whose key material it
				// generated, so the key with imported key material is not
				// counted as having rotation off.
				Name:      "a key KMS cannot rotate",
				Responses: unrotatableKeyResponses(),
				Expect: map[string]map[string]any{awsPath: {
					"/accounts/0/kms/customer_managed_key_count":        2,
					"/accounts/0/kms/cmks_with_rotation_disabled_count": 1,
					"/accounts/0/kms/keys/0/origin":                     "AWS_KMS",
					"/accounts/0/kms/keys/0/rotation_enabled":           false,
					"/accounts/0/kms/keys/1/origin":                     "EXTERNAL",
					"/accounts/0/kms/keys/1/rotation_enabled":           false,
				}},
			},
			{
				// An account whose people all sign in through Identity Center
				// once reported 100% MFA coverage over its zero IAM users.
				Name:      "no IAM users, Identity Center users",
				Responses: kitResponsesWithReport(kitRootOnlyReport),
				Expect: map[string]map[string]any{
					awsPath: {
						"/accounts/0/iam/iam_user_count":                  0,
						"/accounts/0/iam/mfa_enabled":                     nil,
						"/accounts/0/iam/mfa_enabled_user_count":          0,
						"/accounts/0/iam/hardware_mfa_enabled":            nil,
						"/accounts/0/iam/hardware_mfa_enabled_user_count": 0,
						"/accounts/0/iam/access_keys_rotated":             nil,
						"/accounts/0/iam/access_keys_rotated_user_count":  0,
						"/accounts/0/identity_center/user_count":          2,
					},
					cloudPosturePath: {
						"/accounts/0/iam/mfa_coverage_pct":                  collectortest.Absent,
						"/accounts/0/iam/access_key_rotation_compliant_pct": collectortest.Absent,
						"/accounts/0/iam/user_count":                        0,
						"/accounts/0/iam/access_key_user_count":             0,
						"/accounts/0/iam/saml_provider_count":               0,
						"/workforce_sign_in/in_use":                         true,
						"/workforce_sign_in/user_count":                     2,
						"/workforce_sign_in/mfa_source":                     "sign_in_service",
					},
				},
			},
			{
				// With no IAM users, no SAML provider, and no Identity
				// Center, only the root user signs in to the account, and
				// each count reads 0.
				Name:      "no IAM users, no Identity Center",
				Responses: noIdentityCenterResponses(kitRootOnlyReport),
				Expect: map[string]map[string]any{
					awsPath: {
						"/accounts/0/iam/iam_user_count":                      0,
						"/accounts/0/iam/saml_provider_count":                 0,
						"/accounts/0/iam/identity_center_saml_provider_count": 0,
						"/accounts/0/iam/identity_center_role_count":          0,
						"/accounts/0/identity_center/enabled":                 false,
						"/accounts/0/identity_center/regions_checked":         []any{kitRegion},
						"/accounts/0/identity_center/instance_type":           collectortest.Absent,
					},
					cloudPosturePath: {
						"/accounts/0/iam/user_count":                        0,
						"/accounts/0/iam/access_key_user_count":             0,
						"/accounts/0/iam/saml_provider_count":               0,
						"/accounts/0/iam/mfa_coverage_pct":                  collectortest.Absent,
						"/accounts/0/iam/access_key_rotation_compliant_pct": collectortest.Absent,
						"/workforce_sign_in/in_use":                         false,
						"/workforce_sign_in/user_count":                     collectortest.Absent,
						"/workforce_sign_in/mfa_source":                     collectortest.Absent,
					},
				},
			},
			{
				// The instance's home region is the second region scanned.
				Name:      "Identity Center instance in a second region",
				Responses: secondRegionInstanceResponses(),
				Config:    map[string]any{"regions": []any{kitRegion, "us-west-2"}},
				Expect: map[string]map[string]any{
					awsPath: {
						"/accounts/0/identity_center/enabled":         true,
						"/accounts/0/identity_center/instance_region": "us-west-2",
						"/accounts/0/identity_center/instance_type":   "organization",
						"/accounts/0/identity_center/regions_checked": []any{kitRegion, "us-west-2"},
					},
					cloudPosturePath: {
						"/workforce_sign_in/in_use":     true,
						"/workforce_sign_in/user_count": 2,
						"/workforce_sign_in/mfa_source": "sign_in_service",
					},
				},
			},
			{
				// A member account cannot see its organization's instance, so
				// the roles and SAML provider Identity Center leaves in it
				// show it in use, and where its users' MFA is set is unknown.
				Name:      "member account with Identity Center roles",
				Responses: memberAccountResponses(),
				Expect: map[string]map[string]any{
					awsPath: {
						"/accounts/0/iam/identity_center_role_count":          2,
						"/accounts/0/iam/identity_center_saml_provider_count": 1,
						"/accounts/0/iam/saml_provider_count":                 0,
						"/accounts/0/identity_center/enabled":                 false,
					},
					cloudPosturePath: {
						"/accounts/0/iam/user_count":          0,
						"/accounts/0/iam/saml_provider_count": 0,
						"/workforce_sign_in/in_use":           true,
						"/workforce_sign_in/user_count":       collectortest.Absent,
						"/workforce_sign_in/mfa_source":       "unknown",
					},
				},
			},
			{
				// People who sign in through a SAML provider the account
				// trusts directly are not IAM users, so the provider count
				// shows them.
				Name:      "SAML provider trusted directly",
				Responses: directSAMLResponses(),
				Expect: map[string]map[string]any{
					awsPath: {
						"/accounts/0/iam/saml_provider_count":                 1,
						"/accounts/0/iam/identity_center_saml_provider_count": 0,
					},
					cloudPosturePath: {
						"/accounts/0/iam/user_count":          0,
						"/accounts/0/iam/saml_provider_count": 1,
						"/workforce_sign_in/in_use":           false,
					},
				},
			},
			{
				// Every user has an external ID, which an identity provider's
				// user provisioning sets, so their MFA is set at that
				// provider. The IDs and their issuer are canaries, so only
				// whether a user has one may reach the artifacts.
				Name:      "Identity Center users from an external identity provider",
				Responses: externalIDUsersResponses(kitRootOnlyReport),
				Secrets: map[string]string{
					"KIT_EXTERNAL_ID_ISSUER": kitExternalIDIssuer,
					"KIT_DANA_EXTERNAL_ID":   kitDanaExternalID,
					"KIT_ELI_EXTERNAL_ID":    kitEliExternalID,
				},
				Expect: map[string]map[string]any{
					awsPath: {
						"/accounts/0/identity_center/external_id_user_count":  2,
						"/accounts/0/identity_center/mfa_evidence":            "external_idp",
						"/accounts/0/identity_center/users/0/has_external_id": true,
					},
					cloudPosturePath: {
						"/workforce_sign_in/in_use":     true,
						"/workforce_sign_in/user_count": 2,
						"/workforce_sign_in/mfa_source": "external_idp",
					},
				},
			},
			{
				// A credential report that timed out once reported 0% MFA
				// coverage.
				Name:      "credential report never finishes",
				Responses: reportPendingResponses(),
				Expect: map[string]map[string]any{
					awsPath: {
						"/accounts/0/iam/credential_report_error_code":    "CredentialReportTimeout",
						"/accounts/0/iam/iam_user_count":                  nil,
						"/accounts/0/iam/mfa_enabled":                     nil,
						"/accounts/0/iam/mfa_enabled_user_count":          nil,
						"/accounts/0/iam/hardware_mfa_enabled_user_count": nil,
						"/accounts/0/iam/access_keys_rotated_user_count":  nil,
						"/accounts/0/iam/root_mfa_enabled":                true,
					},
					cloudPosturePath: {
						"/accounts/0/iam/mfa_coverage_pct":                  nil,
						"/accounts/0/iam/access_key_rotation_compliant_pct": nil,
					},
				},
			},
			{
				Name:          "token rejected",
				ExpectFailure: componentsdk.CodeAuthFailed,
				Responses: []collectortest.Response{
					kitSignInResponses()[0],
					{
						Operation: "aws.sts.AssumeRoleWithWebIdentity", Method: http.MethodPost, URL: kitSTSURL, Status: http.StatusBadRequest, Header: xmlHeader(),
						Body: "<ErrorResponse><Error><Type>Sender</Type><Code>InvalidIdentityToken</Code><Message>Incorrect token audience</Message></Error><RequestId>kit</RequestId></ErrorResponse>",
					},
				},
			},
		},
		Required: []string{"github.id_token.get", "aws.sts.AssumeRoleWithWebIdentity", "aws.sts.GetCallerIdentity"},
		Semantics: append([]collectortest.Semantic{
			{
				Operation: "aws.guardduty.GetAdministratorAccount", Fault: "empty-object",
				Meaning: "the detector has no administrator account",
				Expect:  map[string]map[string]any{awsPath: {"/accounts/0/account_security/guardduty/finding_notification/administrator_account_id": nil}},
			},
			{
				Operation: "aws.ssoadmin.GetInlinePolicyForPermissionSet", Fault: "empty-object",
				Meaning: "the permission set has no inline policy",
				Expect:  map[string]map[string]any{awsPath: {"/accounts/0/identity_center/permission_sets/0/has_inline_policy": nil}},
			},
			{
				// The first call reads the organization trail's status.
				Operation: "aws.cloudtrail.GetTrailStatus", Fault: "403",
				Meaning:   "a member account is blocked from its organization's trail, which counts as coverage",
				Positions: []string{collectortest.PositionAll, collectortest.PositionFirst},
				Expect: map[string]map[string]any{awsPath: {
					"/accounts/0/account_security/cloudtrail/trails/0/is_logging":            true,
					"/accounts/0/account_security/cloudtrail/trails/0/trail_status_inferred": true,
				}},
			},
			// The calls read the app bucket's block, then the logs bucket's
			// for the bucket inventory, then the logs bucket's again for its
			// trails. The app bucket has no block of its own in the clean
			// scenario either.
			{
				Operation: "aws.s3.GetPublicAccessBlock", Fault: "404-no-public-access-block",
				Meaning:   "the bucket has no public access block of its own, so only the account's ACL flags apply",
				Positions: []string{collectortest.PositionAll},
				Expect: map[string]map[string]any{awsPath: {
					"/accounts/0/s3/public_access_blocked":                                  0,
					"/accounts/0/s3/public_access_block_unknown_count":                      0,
					"/accounts/0/s3/buckets/1/public_access_blocked":                        false,
					"/accounts/0/account_security/cloudtrail/trails/0/bucket_public_access": "not_blocked",
				}},
			},
			{
				Operation: "aws.s3.GetPublicAccessBlock", Fault: "404-no-public-access-block",
				Meaning:   "the bucket has no public access block of its own, so only the account's ACL flags apply",
				Positions: []string{collectortest.PositionMiddle},
				Expect: map[string]map[string]any{awsPath: {
					"/accounts/0/s3/public_access_blocked":                                  0,
					"/accounts/0/s3/buckets/1/public_access_blocked":                        false,
					"/accounts/0/account_security/cloudtrail/trails/0/bucket_public_access": "blocked",
				}},
			},
			{
				Operation: "aws.s3.GetPublicAccessBlock", Fault: "404-no-public-access-block",
				Meaning:   "the bucket has no public access block of its own, so only the account's ACL flags apply",
				Positions: []string{collectortest.PositionLast},
				Expect: map[string]map[string]any{awsPath: {
					"/accounts/0/s3/public_access_blocked":                                  50,
					"/accounts/0/s3/buckets/1/public_access_blocked":                        true,
					"/accounts/0/account_security/cloudtrail/trails/0/bucket_public_access": "not_blocked",
				}},
			},
			{
				Operation: "aws.s3control.GetPublicAccessBlock", Fault: "404-no-public-access-block",
				Meaning: "the account has no public access block, so each bucket's own block decides",
				Expect: map[string]map[string]any{awsPath: {
					"/accounts/0/s3/account_public_access_block_enabled": false,
					"/accounts/0/s3/public_access_blocked":               50,
					"/accounts/0/s3/buckets/1/public_access_blocked":     true,
				}},
			},
		}, emptyListSemantics()...),
		Ignore:        map[string][]string{awsPath: kitIgnore()},
		Operations:    kitOperations,
		Insensitive:   []string{"github.id_token.get", "aws.sts.AssumeRoleWithWebIdentity"},
		Faults:        awsFaults(),
		GapOperations: true,
	}
}

// jsonListOperations are the JSON-protocol operations that answer with a
// list. A JSON-protocol operation that answers one object, or one item per ID
// it was given, stays off it, so {} still has to leave a gap there.
var jsonListOperations = []string{
	"aws.organizations.ListAccounts",
	"aws.lambda.ListFunctions",
	"aws.lambda.ListFunctionUrlConfigs",
	"aws.cloudwatchlogs.DescribeLogGroups",
	"aws.sesv2.ListConfigurationSets",
	"aws.sesv2.ListEmailIdentities",
	"aws.ecs.ListClusters",
	"aws.ecs.ListServices",
	"aws.applicationautoscaling.DescribeScalableTargets",
	"aws.applicationautoscaling.DescribeScalingPolicies",
	"aws.kms.ListAliases",
	"aws.kms.ListKeys",
	"aws.secretsmanager.ListSecrets",
	"aws.ssm.DescribeParameters",
	"aws.wafv2.ListWebACLs",
	"aws.wafv2.ListResourcesForWebACL",
	"aws.cloudtrail.DescribeTrails",
	"aws.configservice.DescribeConfigurationRecorders",
	"aws.configservice.DescribeConfigurationRecorderStatus",
	"aws.configservice.DescribeConfigRules",
	"aws.configservice.DescribeComplianceByConfigRule",
	"aws.configservice.DescribeConfigRuleEvaluationStatus",
	"aws.guardduty.ListDetectors",
	"aws.guardduty.ListFindings",
	"aws.eventbridge.ListRules",
	"aws.eventbridge.ListTargetsByRule",
	"aws.accessanalyzer.ListAnalyzers",
	"aws.accessanalyzer.ListFindings",
	"aws.securityhub.GetEnabledStandards",
	"aws.securityhub.ListEnabledProductsForImport",
	"aws.securityhub.GetFindings",
	"aws.ssoadmin.ListInstances",
	"aws.identitystore.ListUsers",
	"aws.identitystore.ListGroups",
	"aws.identitystore.ListGroupMemberships",
	"aws.ssoadmin.ListPermissionSets",
	"aws.ssoadmin.ListAccountsForProvisionedPermissionSet",
	"aws.ssoadmin.ListManagedPoliciesInPermissionSet",
	"aws.ssoadmin.ListAccountAssignments",
}

// emptyListSemantics declares the empty-object fault an answer on each JSON
// list operation. XML services cannot parse {}, so on theirs it stays a
// failure.
func emptyListSemantics() []collectortest.Semantic {
	out := make([]collectortest.Semantic, 0, len(jsonListOperations))
	for _, op := range jsonListOperations {
		out = append(out, collectortest.Semantic{
			Operation: op, Fault: "empty-object",
			Meaning: "AWS's JSON protocol omits empty lists, so {} answers none",
		})
	}
	return out
}

// awsFaults are AWS's own forms of failure: throttling sent as a 400 in the
// JSON protocols and in the Query protocols' two error layouts, and S3's
// SlowDown, each once (a retry clears it) and on every attempt. The 404s
// that say no public access block is configured are answers, which
// Semantics pins.
func awsFaults() []collectortest.Fault {
	jsonThrottle := `{"__type":"ThrottlingException","message":"Rate exceeded"}`
	queryThrottle := "<ErrorResponse><Error><Type>Sender</Type><Code>Throttling</Code><Message>Rate exceeded</Message></Error><RequestId>kit</RequestId></ErrorResponse>"
	ec2Throttle := "<Response><Errors><Error><Code>RequestLimitExceeded</Code><Message>Request limit exceeded.</Message></Error></Errors><RequestID>kit</RequestID></Response>"
	slowDown := "<Error><Code>SlowDown</Code><Message>Please reduce your request rate.</Message><RequestId>kit</RequestId></Error>"
	noBlock := "<Error><Code>NoSuchPublicAccessBlockConfiguration</Code><Message>The public access block configuration was not found</Message><RequestId>kit</RequestId></Error>"
	noAccountBlock := "<ErrorResponse><Error><Code>NoSuchPublicAccessBlockConfiguration</Code><Message>The public access block configuration was not found</Message></Error><RequestId>kit</RequestId></ErrorResponse>"
	xml := http.Header{"Content-Type": []string{"text/xml"}}
	jsonOps, queryOps, ec2Ops, s3Ops := operationsByProtocol()
	return []collectortest.Fault{
		withOperations(collectortest.StatusFault("400-throttled-json-once", http.StatusBadRequest, nil, jsonThrottle, "", true), jsonOps),
		withOperations(collectortest.StatusFault("400-throttled-json", http.StatusBadRequest, nil, jsonThrottle, componentsdk.CodeRateLimited, false), jsonOps),
		withOperations(collectortest.StatusFault("400-throttled-query-once", http.StatusBadRequest, xml, queryThrottle, "", true), queryOps),
		withOperations(collectortest.StatusFault("400-throttled-query", http.StatusBadRequest, xml, queryThrottle, componentsdk.CodeRateLimited, false), queryOps),
		withOperations(collectortest.StatusFault("400-throttled-ec2-once", http.StatusBadRequest, xml, ec2Throttle, "", true), ec2Ops),
		withOperations(collectortest.StatusFault("400-throttled-ec2", http.StatusBadRequest, xml, ec2Throttle, componentsdk.CodeRateLimited, false), ec2Ops),
		withOperations(collectortest.StatusFault("503-slowdown-once", http.StatusServiceUnavailable, xml, slowDown, "", true), s3Ops),
		withOperations(collectortest.StatusFault("503-slowdown", http.StatusServiceUnavailable, xml, slowDown, componentsdk.CodeRateLimited, false), s3Ops),
		withOperations(collectortest.StatusFault("404-no-public-access-block", http.StatusNotFound, xml, noBlock, "", false), []string{"aws.s3.GetPublicAccessBlock"}),
		withOperations(collectortest.StatusFault("404-no-public-access-block", http.StatusNotFound, xml, noAccountBlock, "", false), []string{"aws.s3control.GetPublicAccessBlock"}),
	}
}

func withOperations(f collectortest.Fault, ops []string) collectortest.Fault {
	f.Operations = ops
	return f
}

// operationsByProtocol sorts the kit's AWS operations by the error layout
// they answer with. CloudFront and S3 Control wrap their XML errors the way
// the Query protocol does. CloudWatch answers in CBOR and gets only the
// built-in faults.
func operationsByProtocol() (jsonOps, queryOps, ec2Ops, s3Ops []string) {
	query := map[string]bool{"iam": true, "sts": true, "rds": true, "elasticloadbalancingv2": true, "autoscaling": true, "sns": true, "cloudfront": true, "s3control": true}
	for _, op := range kitOperations {
		parts := strings.Split(op, ".")
		if parts[0] != "aws" {
			continue
		}
		switch service := parts[1]; {
		case service == "ec2":
			ec2Ops = append(ec2Ops, op)
		case query[service]:
			queryOps = append(queryOps, op)
		case service == "s3":
			s3Ops = append(s3Ops, op)
		case service == "cloudwatch":
		default:
			jsonOps = append(jsonOps, op)
		}
	}
	return jsonOps, queryOps, ec2Ops, s3Ops
}

func TestCollectorKit(t *testing.T) {
	isolateAWSEnvironment(t)
	s := kitSuite()
	s.Scenarios = append(s.Scenarios, kitRecordings(t, "aws")...)
	collectortest.Run(t, s)
}

// kitMarkers are the read-status markers under an account's entry that
// change under the fault matrix: whether a source was read, its error code,
// and counts of items that could not be read. The detailed artifact keeps
// them for readers of earlier versions, while the values they describe are
// left out with gaps.
var kitMarkers = []string{
	"account_security/access_analyzer/analyzers/0/findings_unresolved",
	"account_security/access_analyzer/analyzers_with_unresolved_findings_count",
	"account_security/access_analyzer/regions_evaluated_count",
	"account_security/access_analyzer/regions_unresolved_count",
	"account_security/cloudtrail/trail_buckets_public_access_unknown_count",
	"account_security/cloudtrail/trail_buckets_retention_unknown_count",
	"account_security/cloudtrail/trail_listing_error_code",
	"account_security/cloudtrail/trail_listing_evaluated",
	"account_security/cloudtrail/trail_status_evaluated_count",
	"account_security/cloudtrail/trail_status_unknown_count",
	"account_security/cloudtrail/trails/0/trail_status_error_code",
	"account_security/cloudtrail/trails/0/trail_status_evaluated",
	"account_security/cloudtrail/trails/1/trail_status_error_code",
	"account_security/cloudtrail/trails/1/trail_status_evaluated",
	"account_security/guardduty/finding_notification/detector_regions_evaluated_count",
	"account_security/guardduty/finding_notification/detector_regions_unresolved_count",
	"account_security/guardduty/finding_notification/topics_unresolved_count",
	"account_security/inspector/status_error_code",
	"account_security/inspector/status_evaluated",
	"cloudfront/distributions_error_code",
	"cloudfront/distributions_evaluated",
	"ecs/scaling_unresolved_service_count",
	"ecs/services/0/scaling_unresolved",
	"iam/credential_report_error_code",
	"iam/credential_report_evaluated",
	"iam/organization_accounts_error_code",
	"iam/organization_accounts_evaluated",
	"iam/password_policy_error_code",
	"iam/password_policy_evaluated",
	"iam/root_organizations_features_error_code",
	"iam/root_organizations_features_evaluated",
	"identity_center/assignments_evaluated",
	"load_balancers/listeners_unresolved_count",
	"load_balancers/load_balancers/0/listeners_unresolved",
	"load_balancers/target_group_listing_failed_region_count",
	"monitoring/topics_unresolved_count",
	"network/vpcs/0/flow_logs_error_code",
	"network/vpcs/0/flow_logs_evaluated",
	"rds/backup_alerting_topics_unresolved_count",
	"rds/db_port_ingress_unevaluated_count",
	"rds/dml_logging_unknown_count",
	"rds/event_subscriptions_unresolved_region_count",
	"rds/instances/0/db_port_ingress_evaluated",
	"s3/account_public_access_block_evaluated",
	"s3/bucket_listing_error_code",
	"s3/bucket_listing_evaluated",
	"s3/buckets/0/default_encryption_error_code",
	"s3/buckets/0/default_encryption_evaluated",
	"s3/buckets/1/default_encryption_error_code",
	"s3/buckets/1/default_encryption_evaluated",
	"s3/default_encryption_evaluated_count",
	"s3/default_encryption_inferred_count",
	"s3/default_encryption_unknown_count",
	"s3/public_access_block_unknown_count",
	"s3/tls_enforcement_unknown_bucket_count",
	"ses/configuration_sets/0/unresolved",
	"ses/configuration_sets_unresolved_count",
	"ses/identities/0/unresolved",
	"ses/identities_unresolved_count",
	"stored_images/image_exposure_unknown",
	"stored_images/snapshot_exposure_unknown",
	"waf/cloudfront_scope_evaluated",
	"waf/regions_evaluated_count",
	"waf/web_acls/0/logging_evaluated",
	"waf/web_acls/1/logging_evaluated",
}

// kitIgnore is what may change under a fault without a gap: the read-status
// markers and the diagnostics block's warnings.
func kitIgnore() []string {
	out := []string{"/diagnostics"}
	for _, m := range kitMarkers {
		out = append(out, "/accounts/0/"+m)
	}
	return out
}

// kitRecordings loads the scenarios TestRecord in record_test.go records
// from sandboxes, and logs each one not recorded yet.
func kitRecordings(t *testing.T, names ...string) []collectortest.Scenario {
	t.Helper()
	var out []collectortest.Scenario
	for _, name := range names {
		path := filepath.Join("testdata", "recordings", name+".json")
		sc, err := collectortest.LoadScenario(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			t.Logf("no recording at %s yet", path)
		case err != nil:
			t.Fatal(err)
		default:
			out = append(out, sc)
		}
	}
	return out
}
