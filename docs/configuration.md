# AWS Collector Configuration

## Authentication

The AWS collector supports multiple authentication methods. The `auth_mode` option controls how the collector assumes IAM roles:

- `oidc` - Uses an OIDC token to assume roles via `AssumeRoleWithWebIdentity`: GitHub Actions' own in a workflow, or a token file named by `AWS_WEB_IDENTITY_TOKEN_FILE` elsewhere (recommended)
- `assume_role` - Uses standard `AssumeRole` with optional `external_id` (default for backward compatibility)

### 1. OIDC (Recommended)

OIDC provides credential-free authentication. In GitHub Actions, the collector obtains a JWT token from GitHub and exchanges it for temporary AWS credentials. Elsewhere, it reads the token from a file, as described below.

**Trust Policy (OIDC):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:your-org/your-repo:*"
        }
      }
    }
  ]
}
```

**Configuration:**

```yaml
collectors:
  aws:
    source: "locktivity/epack-collector-aws@^0.1.0"
    config:
      auth_mode: "oidc"
      role_arn: "arn:aws:iam::123456789012:role/EpackCollectorRole"
    secrets:
      - ACTIONS_ID_TOKEN_REQUEST_URL
      - ACTIONS_ID_TOKEN_REQUEST_TOKEN
```

**GitHub Actions Workflow:**

```yaml
permissions:
  id-token: write  # Required for OIDC
  contents: read
```

#### Token from a file

Outside GitHub Actions, OIDC mode reads the token from the file `AWS_WEB_IDENTITY_TOKEN_FILE` names. Use this for any issuer AWS can trust, such as a GitLab job's ID token. Each account's role trusts the issuer through an IAM identity provider, so several accounts need no intermediate role.

**Configuration:**

```yaml
collectors:
  aws:
    source: "locktivity/epack-collector-aws@^0.1.0"
    config:
      auth_mode: "oidc"
      role_arn: "arn:aws:iam::123456789012:role/EpackCollectorRole"
    secrets:
      - AWS_WEB_IDENTITY_TOKEN_FILE
```

**Example (GitLab CI):**

The role trusts the `gitlab.com` identity provider with the job's audience and subject:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/gitlab.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "gitlab.com:aud": "https://gitlab.com",
          "gitlab.com:sub": "project_path:your-group/your-project:ref_type:branch:ref:main"
        }
      }
    }
  ]
}
```

The job requests an ID token with that audience and writes it to the file:

```yaml
  id_tokens:
    AWS_ID_TOKEN:
      aud: https://gitlab.com
  script:
    - umask 077
    - printf '%s' "$AWS_ID_TOKEN" > "$CI_PROJECT_DIR/.aws-web-identity-token"
    - export AWS_WEB_IDENTITY_TOKEN_FILE="$CI_PROJECT_DIR/.aws-web-identity-token"
```

### 2. IAM Role with AssumeRole

For environments without OIDC support, use standard `AssumeRole` with bootstrap credentials.

**Trust Policy (AssumeRole):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::COLLECTOR_ACCOUNT:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "your-external-id"
        }
      }
    }
  ]
}
```

**Configuration:**

```yaml
collectors:
  aws:
    source: "locktivity/epack-collector-aws@^0.1.0"
    config:
      auth_mode: "assume_role"
      role_arn: "arn:aws:iam::123456789012:role/EpackCollectorRole"
      external_id: "your-external-id"
```

### 3. Default Credential Chain

If no `role_arn` is specified, the collector uses the AWS SDK's default credential chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. Shared credentials file (`~/.aws/credentials`)
3. `aws login` sessions (profiles with `login_session` in `~/.aws/config`)
4. EC2 instance profile / ECS task role

```yaml
collectors:
  aws:
    source: "locktivity/epack-collector-aws@^0.1.0"
    config:
      regions:
        - us-east-1
```

## Required IAM Permissions

The collector needs read-only AWS permissions in each target account. The minimum set depends on the `level` config (see [levels.md](levels.md)). Levels are cumulative: audit needs the trust set plus more; internal needs the audit set plus more.

All actions are List, Describe, or Get. Value-reading APIs (`secretsmanager:GetSecretValue`, `ssm:GetParameter`, etc.) are intentionally absent and are forbidden in collector source by a build-time lint.

If a surface is missing its required permissions, the collector emits a per-surface AccessDenied diagnostic warning and continues; it does not fail the whole run. Each value a denied call leaves out gets a `permission_denied` gap in `artifacts/aws.collector-result.json` that names the call. When AWS's message names the IAM action, as in "not authorized to perform: iam:GenerateCredentialReport", the gap names it in `missing_permission`, and its warning says where to allow it: the collector's IAM policy, or the service control policy or permissions boundary that allows the action nowhere. When a policy denies the action explicitly, the warning names that policy and the gap names no permission to grant, because an explicit deny overrides any allow.

`iam:ListOrganizationsFeatures` only evaluates centralized root access from the AWS Organizations management account or an IAM delegated administrator account. Member-account roles record the AWS error code in the evidence pack instead of inferring the organization-level state.

Without `iam:ListSAMLProviders`, the SAML provider counts are left out with a `permission_denied` gap. Whether IAM Identity Center is in use is still decided from the instance and role listings.

### Trust level (default)

The minimum policy. Required for every collection level.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",

        "iam:GenerateCredentialReport",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:GetCredentialReport",
        "iam:ListAccountAliases",
        "iam:ListOrganizationsFeatures",
        "iam:ListMFADevices",
        "iam:ListRoles",
        "iam:ListSAMLProviders",

        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketLocation",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicy",
        "s3:GetBucketObjectLockConfiguration",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetEncryptionConfiguration",
        "s3:GetLifecycleConfiguration",
        "s3:ListAllMyBuckets",

        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshots",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcs",

        "cloudfront:ListDistributions",
        "cloudwatch:DescribeAlarms",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeLoadBalancers",
        "events:ListRules",
        "events:ListTargetsByRule",
        "sns:ListSubscriptionsByTopic",

        "wafv2:ListWebACLs",
        "wafv2:GetWebACL",
        "wafv2:ListResourcesForWebACL",

        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:DescribePolicies",
        "application-autoscaling:DescribeScalableTargets",
        "application-autoscaling:DescribeScalingPolicies",
        "ecs:DescribeServices",
        "ecs:ListClusters",
        "ecs:ListServices",
        "elasticloadbalancing:DescribeTargetGroups",

        "ses:GetConfigurationSet",
        "ses:GetEmailIdentity",
        "ses:ListConfigurationSets",
        "ses:ListEmailIdentities",

        "rds:DescribeDBClusters",
        "rds:DescribeDBParameters",
        "rds:DescribeEventSubscriptions",
        "rds:DescribeDBInstances",

        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",

        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",

        "guardduty:GetAdministratorAccount",
        "guardduty:GetDetector",
        "guardduty:ListDetectors",
        "guardduty:ListFindings",

        "securityhub:DescribeHub",
        "securityhub:GetEnabledStandards",
        "securityhub:GetFindings",
        "securityhub:ListEnabledProductsForImport",

        "access-analyzer:ListAnalyzers",
        "access-analyzer:ListFindings",

        "sso:ListInstances",
        "sso:ListPermissionSets",
        "identitystore:ListGroups",
        "identitystore:ListUsers",

        "lambda:ListFunctions",
        "logs:DescribeLogGroups",

        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "kms:ListKeys",

        "secretsmanager:ListSecrets",
        "ssm:DescribeParameters"
      ],
      "Resource": "*"
    }
  ]
}
```

### Audit level

Add these actions to the trust-level policy above. They surface the Identity Center access model (permission sets, the user and group roster, membership and account-assignment edges), per-function Lambda configuration, KMS alias enrichment, web ACL logging state, and the organization-membership classification of cross-account role trust.

```json
[
  "sso:DescribePermissionSet",
  "sso:ListAccountsForProvisionedPermissionSet",
  "sso:ListManagedPoliciesInPermissionSet",
  "sso:GetInlinePolicyForPermissionSet",
  "sso:ListAccountAssignments",

  "identitystore:ListGroupMemberships",

  "organizations:ListAccounts",

  "lambda:GetPolicy",
  "lambda:ListFunctionUrlConfigs",

  "kms:ListAliases",

  "wafv2:GetLoggingConfiguration"
]
```

`wafv2:GetLoggingConfiguration` is best effort: without it, per-ACL rows report `logging_evaluated: false` rather than failing the region.

`organizations:ListAccounts` is optional and best effort: it succeeds only from the Organizations management account or a delegated administrator. Without it, per-role `external_trust_in_org` determinations are absent rather than guessed, and the run continues.

### Internal level

Add these actions on top of the audit-level set. They surface per-rule Config compliance, GuardDuty finding payloads, per-bucket S3 ACL configuration, and per-VPC flow log status.

```json
[
  "config:DescribeConfigRules",
  "config:DescribeComplianceByConfigRule",
  "config:DescribeConfigRuleEvaluationStatus",

  "guardduty:GetFindings",

  "ec2:DescribeFlowLogs",

  "s3:GetBucketAcl"
]
```

## Multi-Account Setup

For organizations with multiple AWS accounts:

### With OIDC (Recommended)

Each target account needs a role trusting the GitHub OIDC provider:

```yaml
collectors:
  aws:
    source: "locktivity/epack-collector-aws@^0.1.0"
    config:
      auth_mode: "oidc"
      accounts:
        - role_arn: "arn:aws:iam::111111111111:role/EpackCollectorRole"
        - role_arn: "arn:aws:iam::222222222222:role/EpackCollectorRole"
        - role_arn: "arn:aws:iam::333333333333:role/EpackCollectorRole"
      regions:
        - us-east-1
        - us-west-2
        - eu-west-1
    secrets:
      - ACTIONS_ID_TOKEN_REQUEST_URL
      - ACTIONS_ID_TOKEN_REQUEST_TOKEN
```

### With AssumeRole

Each target account needs a role trusting the bootstrap account:

```yaml
collectors:
  aws:
    source: "locktivity/epack-collector-aws@^0.1.0"
    config:
      auth_mode: "assume_role"
      accounts:
        - role_arn: "arn:aws:iam::111111111111:role/EpackCollectorRole"
          external_id: "prod-123"
        - role_arn: "arn:aws:iam::222222222222:role/EpackCollectorRole"
          external_id: "staging-456"
        - role_arn: "arn:aws:iam::333333333333:role/EpackCollectorRole"
          external_id: "dev-789"
      regions:
        - us-east-1
        - us-west-2
        - eu-west-1
```

> **Note:** `external_id` is ignored in OIDC mode. The OIDC token claims provide equivalent security through repository/branch constraints in the trust policy.

## Region Configuration

By default, the collector discovers all enabled regions in the account and scans up to five of them concurrently. AWS rate limits are per region, so concurrent regions do not compete for API quotas. To limit to specific regions:

```yaml
collectors:
  aws:
    source: "locktivity/epack-collector-aws@^0.1.0"
    config:
      regions:
        - us-east-1
        - us-west-2
```

## Troubleshooting

### "Access Denied" Errors

1. Verify the IAM role/user has all required permissions. Each gap in `artifacts/aws.collector-result.json` names the call AWS denied, and `missing_permission` names the IAM action to allow when AWS's message names one.
2. Check that the trust policy allows the collector's identity
3. Ensure the external ID matches (if configured)

### Rejected Credentials

A token or access key AWS does not accept, such as an identity token with the wrong audience or a deleted access key, fails the run with exit code 3 and the code `auth_failed`. No evidence is emitted. When some configured accounts sign in and others do not, the run succeeds and lists the others under `failed_accounts`.

### "Credential Report Not Ready"

The collector polls for the credential report for up to 45 seconds. When it is still not ready, the IAM user metrics are null, `credential_report_error_code` is `CredentialReportTimeout`, and the result artifact records them as timed out. A later run usually finds the report ready. If it never is, check IAM permissions for `iam:GenerateCredentialReport`.

### "Service Not Available in Region"

Some services (like GuardDuty) may not be available in all regions. The collector handles this gracefully and continues with available services.

### Rate Limiting

The collector retries throttled AWS calls with backoff. A call still throttled after its retries leaves the values it would have given null, and the result artifact records them as rate limited. For large accounts with many resources, collection may take several minutes.
