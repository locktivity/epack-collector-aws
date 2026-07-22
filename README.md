# epack-collector-aws

Collects AWS account security posture metrics for the epack ecosystem.

## Features

- **Configurable collection depth**: an optional `level` config knob (`trust` / `audit` / `internal`) controls how much detail to collect. See [docs/levels.md](docs/levels.md) for the artifact contract and per-surface field breakdowns.
- **Multi-account support**: collect from multiple AWS accounts in a single run.
- **IAM**: MFA coverage, password policies, access-key rotation, root-account state; per-user / per-role inventory + full credential report at higher levels.
- **S3**: encryption, public-access blocks, versioning, logging; per-bucket policy / ACL / lifecycle at higher levels.
- **RDS**: encryption, public accessibility, deletion protection, backups, Multi-AZ; per-instance / per-cluster rows.
- **Network**: security-group analysis; per-VPC inventory with internal-level flow log status and per-SG-rule inventory.
- **Account security services**: CloudTrail, AWS Config (with per-rule compliance), GuardDuty (with per-finding triage), Security Hub, Inspector.
- **Identity Center (IAM Identity Center / AWS SSO)**: instance + user / group / permission-set inventory.
- **Lambda**: deprecated runtime detection, public Function URL detection, per-function metadata (env var KEYS only — values never collected).
- **EC2**: IMDSv2 enforcement, public-IP exposure, default-VPC residency, unencrypted-volume detection.
- **CloudWatch Logs**: retention + customer-KMS coverage, per-log-group inventory.
- **KMS**: customer-managed key rotation, pending-deletion detection.
- **Secrets Manager + SSM Parameter Store**: rotation + customer-KMS coverage; metadata only — secret values are never read (enforced by build-time lint).

## Installation

```bash
go install github.com/locktivity/epack-collector-aws/cmd/epack-collector-aws@latest
```

Or build from source:

```bash
git clone https://github.com/locktivity/epack-collector-aws
cd epack-collector-aws
make build
```

## Configuration

### Collection Level

An optional `level` config field controls how much detail the collector gathers.
Three values: `trust` (default — pass/fail posture only), `audit` (adds
per-resource breakdowns), `internal` (adds raw identifying detail for breach
investigation). Levels are cumulative — `internal` ⊃ `audit` ⊃ `trust`.

```yaml
collectors:
  aws:
    source: "locktivity/epack-collector-aws@^1"
    config:
      level: audit       # optional; defaults to trust
      role_arn: arn:aws:iam::123456789012:role/EpackCollectorRole
```

Unrecognized values downgrade to `trust` with a stderr warning. The active
level appears in the output as the top-level `collected_at_level` field. See
[docs/levels.md](docs/levels.md) for the per-surface field breakdown.

### Authentication Modes

The collector supports two authentication modes via the `auth_mode` option:

- **`oidc`** - Uses GitHub Actions OIDC for credential-free authentication (recommended for GitHub Actions)
- **`assume_role`** - Uses standard AssumeRole with optional external_id (default for backward compatibility)

### Single Account with OIDC (Recommended)

```yaml
collectors:
  aws:
    source: "locktivity/epack-collector-aws@^0.1.0"
    config:
      auth_mode: "oidc"
      role_arn: "arn:aws:iam::123456789012:role/EpackCollectorRole"
      regions:
        - us-east-1
        - us-west-2
    secrets:
      - ACTIONS_ID_TOKEN_REQUEST_URL
      - ACTIONS_ID_TOKEN_REQUEST_TOKEN
```

### Single Account with AssumeRole

```yaml
collectors:
  aws:
    source: "locktivity/epack-collector-aws@^0.1.0"
    config:
      auth_mode: "assume_role"
      role_arn: "arn:aws:iam::123456789012:role/EpackCollectorRole"
      external_id: "unique-external-id"
      label: "production"
      regions:
        - us-east-1
        - us-west-2
```

### Multi-Account

```yaml
collectors:
  aws:
    source: "locktivity/epack-collector-aws@^0.1.0"
    config:
      auth_mode: "oidc"  # or "assume_role"
      accounts:
        - role_arn: "arn:aws:iam::111111111111:role/EpackCollectorRole"
          label: "production"
        - role_arn: "arn:aws:iam::222222222222:role/EpackCollectorRole"
          label: "staging"
      regions:
        - us-east-1
        - us-west-2
    secrets:
      - ACTIONS_ID_TOKEN_REQUEST_URL
      - ACTIONS_ID_TOKEN_REQUEST_TOKEN
```

### Default Credentials

If no `role_arn` or `accounts` specified, the collector uses the default AWS credential chain (environment variables, config file, instance profile).

## Required IAM Permissions

The collector needs read-only AWS permissions in each target account. The minimum set depends on the `level` config (see [Collection Level](#collection-level) above). Levels are cumulative: audit needs the trust set plus more; internal needs the audit set plus more.

All actions are List, Describe, or Get. Value-reading APIs (`secretsmanager:GetSecretValue`, `ssm:GetParameter`, etc.) are intentionally absent and are forbidden in collector source by a build-time lint.

If a surface is missing its required permissions, the collector emits a per-surface AccessDenied diagnostic warning and continues; it does not fail the whole run.

`iam:ListOrganizationsFeatures` only evaluates centralized root access from the AWS Organizations management account or an IAM delegated administrator account. Member-account roles record the AWS error code in the evidence pack instead of inferring the organization-level state.

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
        "iam:GetRole",
        "iam:ListAccountAliases",
        "iam:ListOrganizationsFeatures",
        "iam:ListMFADevices",
        "iam:ListRoles",
        "iam:ListUsers",

        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketLocation",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetEncryptionConfiguration",
        "s3:ListAllMyBuckets",

        "ec2:DescribeInstances",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcs",

        "rds:DescribeDBClusters",
        "rds:DescribeDBInstances",

        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",

        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",

        "guardduty:GetDetector",
        "guardduty:ListDetectors",
        "guardduty:ListFindings",

        "securityhub:DescribeHub",
        "securityhub:GetEnabledStandards",
        "securityhub:GetFindings",
        "securityhub:ListEnabledProductsForImport",

        "access-analyzer:ListAnalyzers",

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

Add these actions to the trust-level policy above. They surface the Identity Center access model (permission sets, the user and group roster, membership and account-assignment edges), per-function Lambda configuration, KMS alias enrichment, and the organization-membership classification of cross-account role trust.

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

  "kms:ListAliases"
]
```

`organizations:ListAccounts` is optional and best effort: it succeeds only from the Organizations management account or a delegated administrator. Without it, per-role `external_trust_in_org` determinations are absent (never guessed) and the run continues quietly.

### Internal level

Add these actions on top of the audit-level set. They surface per-rule Config compliance, GuardDuty finding payloads, and per-bucket S3 ACL and lifecycle configuration.

```json
[
  "config:DescribeConfigRules",
  "config:DescribeComplianceByConfigRule",
  "config:DescribeConfigRuleEvaluationStatus",

  "guardduty:GetFindings",

  "ec2:DescribeFlowLogs",

  "s3:GetBucketAcl",
  "s3:GetLifecycleConfiguration"
]
```

## Output

The collector outputs JSON with posture metrics for each account. The example
below shows the trust-level shape; audit and internal levels add per-resource
inventory arrays inside each surface (see [docs/levels.md](docs/levels.md)).
The full machine-readable shape is in [docs/schema/v1.0.0.json](docs/schema/v1.0.0.json).

```json
{
  "schema_version": "1.0.0",
  "collected_at": "2024-01-15T10:30:00Z",
  "collected_at_level": "trust",
  "accounts": [
    {
      "account_id": "123456789012",
      "account_alias": "production",
      "regions": ["us-east-1", "us-west-2"],
      "iam": {
        "iam_users_present": true,
        "mfa_enabled": 95,
        "hardware_mfa_enabled": 0,
        "access_keys_rotated": 80,
        "root_mfa_enabled": true,
        "root_credentials_present": true,
        "root_password_present": true,
        "root_access_keys_exist": false,
        "root_signing_certificates_present": false,
        "root_access_protected": true,
        "root_organizations_features_evaluated": true,
        "root_organization_id": "o-abc1234567",
        "root_credentials_management_feature_enabled": true,
        "root_sessions_feature_enabled": true
      },
      "s3": {
        "public_access_blocked": 100,
        "default_encryption_enabled": 95,
        "default_encryption_evaluated_count": 20,
        "default_encryption_inferred_count": 0,
        "default_encryption_unknown_count": 0,
        "versioning_enabled": 60,
        "logging_enabled": 40,
        "log_sink_bucket_count": 2,
        "account_public_access_block_enabled": true
      },
      "rds": {
        "encrypted_at_rest": 100,
        "publicly_accessible": 0,
        "deletion_protection": 90,
        "backup_retention_adequate": 100,
        "multi_az_enabled": 80
      },
      "network": {
        "open_to_world_ssh": 2,
        "open_to_world_rdp": 0
      },
      "account_security": {
        "cloudtrail": {
          "enabled": true,
          "multi_region_enabled": true,
          "organization_trail_enabled": true,
          "trail_status_evaluated_count": 1,
          "trail_status_inferred_count": 0,
          "trail_status_unknown_count": 0
        },
        "config": {
          "enabled": true,
          "recorder_running": true
        },
        "guardduty": {
          "enabled": true,
          "unremediated_findings_over_48h": 1
        },
        "security_hub": {
          "enabled": true,
          "cis_aws_foundations_benchmark_level_1": {
            "enabled": true,
            "compliance_percent": 88,
            "compliance_state": "WARNING",
            "passed_controls": 44,
            "failed_controls": 3,
            "warning_controls": 3,
            "not_available_controls": 1
          },
          "cis_aws_foundations_benchmark_level_2": {
            "enabled": true,
            "compliance_percent": 82,
            "compliance_state": "FAILED",
            "passed_controls": 55,
            "failed_controls": 8,
            "warning_controls": 4,
            "not_available_controls": 2
          },
          "cis_aws_foundations_benchmark_unknown_level": {
            "enabled": true,
            "compliance_percent": 90,
            "compliance_state": "FAILED",
            "passed_controls": 9,
            "failed_controls": 1,
            "warning_controls": 0,
            "not_available_controls": 0
          }
        },
        "inspector": {
          "enabled": true,
          "unpatched_server_percent": 25
        }
      },
      "identity_center": {
        "enabled": true,
        "user_count": 47,
        "group_count": 12,
        "permission_set_count": 8
      },
      "lambda": {
        "function_count": 23,
        "deprecated_runtime_count": 2
      },
      "ec2": {
        "instance_count": 14,
        "imdsv2_required_count": 14,
        "public_ip_count": 1,
        "default_vpc_count": 0,
        "instances_with_unencrypted_volume_count": 0
      },
      "cloudwatch_logs": {
        "log_group_count": 87,
        "log_groups_without_retention_count": 5,
        "log_groups_without_customer_kms_count": 80
      },
      "kms": {
        "customer_managed_key_count": 3,
        "cmks_with_rotation_disabled_count": 0,
        "cmks_pending_deletion_count": 0
      },
      "secrets_manager": {
        "secret_count": 12,
        "secrets_without_rotation_count": 3,
        "secrets_without_customer_kms_count": 12,
        "secrets_pending_deletion_count": 0
      },
      "ssm_parameters": {
        "parameter_count": 156,
        "secure_string_count": 24,
        "secure_strings_without_customer_kms_count": 24
      }
    }
  ]
}
```

Trust-level fields are always present. Audit and internal levels add
`<surface>.<inventory_array>` fields (e.g., `lambda.functions`, `ec2.instances`)
inside each surface — see [docs/levels.md](docs/levels.md) for the
artifact contract and per-surface field breakdowns.

## Upgrading from v0.1.x

The v0.2.x line is backward-compatible at the schema layer: all new fields
are additive and the schema version stays at `1.0.0`. A consumer written
against a v0.1.x pack still reads the same trust-level signals it always
did.

What's new:

- **`collected_at_level`** is a new top-level field on the output. Always
  present; one of `"trust"`, `"audit"`, `"internal"`.
- **Seven new top-level surfaces** appear under each `AccountPosture`:
  `identity_center`, `lambda`, `ec2`, `cloudwatch_logs`, `kms`,
  `secrets_manager`, `ssm_parameters`. Their trust-level aggregates are
  populated by default (no config change needed).
- **`level` config knob** is added; default is `trust` (zero behavior change
  from v0.1.x if omitted).
- **Existing surfaces gain inventory arrays** at audit/internal level
  (`iam.users`, `s3.buckets`, etc.). At trust level these emit as `null`
  for the "collected vs not collected" contract — see
  [docs/levels.md](docs/levels.md#artifact-contract-null-vs--vs-).

What you may need to do:

- **Update your IAM role** to include the new permissions if you want to
  run at `audit` or `internal` level (see the
  [Required IAM Permissions](#required-iam-permissions) section). Without
  them the new surfaces emit zeros with an AccessDenied diagnostic warning.
- **No code change** needed for consumers that ignore unknown fields.

## Development

```bash
# Build
make build

# Test
make test

# Lint
make lint

# SDK conformance test
make sdk-test
```

## License

Apache 2.0
