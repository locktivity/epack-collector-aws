# AWS Collector Overview

The AWS collector gathers security posture metrics from AWS accounts. The
amount of detail it gathers is controlled by an optional `level` config knob
with three values: `trust` (default, pass/fail posture only), `audit` (adds
per-resource breakdowns), and `internal` (adds raw identifying detail for
breach investigation). See [levels.md](levels.md) for the full contract.

This page lists the surfaces and their trust-level signals. Per-level field
breakdowns live in [levels.md](levels.md); the machine-readable shape lives
in [schema/v1.0.0.json](schema/v1.0.0.json).

A value the collector could not read is null, and the run's result artifact
(`artifacts/aws.collector-result.json` under the default collector name)
records which values were left out and why. A percentage over an empty
population, such as `mfa_enabled` in an account with no IAM users, is also
null; the count beside it (here `iam_user_count`) is 0.

## What It Collects

### IAM Security

| Metric | Description |
|--------|-------------|
| `credential_report_evaluated` | Whether the IAM credential report was collected. The user aggregates below are meaningful only when true |
| `credential_report_error_code` | Error code when the credential report could not be collected (e.g. `CredentialReportTimeout`) |
| `iam_users_present` | Whether at least one IAM user (excluding root) exists in the account |
| `iam_user_count` | IAM users in the credential report, excluding root |
| `access_key_user_count` | IAM users with at least one active access key |
| `mfa_enabled` | Percentage of IAM users with MFA enabled |
| `mfa_enabled_user_count` | IAM users with MFA enabled |
| `hardware_mfa_enabled` | Percentage of IAM users with hardware MFA (physical OTP devices or FIDO/U2F security keys) |
| `hardware_mfa_enabled_user_count` | IAM users with hardware MFA |
| `access_keys_rotated` | Percentage of users with active access keys whose keys were all rotated within 90 days |
| `access_keys_rotated_user_count` | Users with active access keys whose keys were all rotated within 90 days |
| `saml_provider_count` | SAML identity providers the account trusts for sign-in, not counting the ones IAM Identity Center creates |
| `identity_center_saml_provider_count` | SAML providers IAM Identity Center created in the account, whose names start with `AWSSSO_` |
| `identity_center_role_count` | Roles IAM Identity Center provisioned in the account for its permission sets, named `AWSReservedSSO_` under `/aws-reserved/sso.amazonaws.com/` |
| `root_credential_state_evaluated` | Whether root credential state was read from the credential report or the account summary. The root credential flags below are meaningful only when true |
| `root_mfa_enabled` | Whether root MFA is active (false when root has no credentials) |
| `root_credentials_present` | Whether root has any password, access key, or signing certificate present |
| `root_password_present` | Whether root has a password present |
| `root_access_keys_exist` | Whether root has access keys (should be false) |
| `root_signing_certificates_present` | Whether root has signing certificates present |
| `root_access_protected` | Whether root MFA is active or no long-term root credentials are present |
| `root_organizations_features_evaluated` | Whether centralized root access features were read from IAM |
| `root_organization_id` | Organization ID returned by IAM when centralized root access features were read |
| `root_credentials_management_feature_enabled` | Whether IAM reported the `RootCredentialsManagement` centralized root access feature |
| `root_sessions_feature_enabled` | Whether IAM reported the `RootSessions` centralized root access feature |
| `root_organizations_features_error_code` | Error code when centralized root access features could not be read |

### S3 Security

| Metric | Description |
|--------|-------------|
| `bucket_listing_evaluated` | Whether the bucket listing was collected. The bucket aggregates below are meaningful only when true |
| `bucket_listing_error_code` | Error code when the bucket listing could not be collected |
| `account_public_access_block_evaluated` | Whether the account-level public access block settings were read |
| `bucket_count` | Total S3 buckets returned by `ListBuckets` |
| `public_access_blocked` | Percentage of buckets whose effective S3 Block Public Access settings block public access |
| `public_access_blocked_bucket_count` | Buckets whose effective S3 Block Public Access settings block public access |
| `public_access_block_unknown_count` | Buckets whose effective S3 Block Public Access setting could not be fully evaluated |
| `default_encryption_enabled` | Percentage of buckets with default encryption. Null while any bucket's setting could not be read |
| `default_encryption_enabled_bucket_count` | Buckets with default encryption |
| `default_encryption_evaluated_count` | Buckets whose default encryption setting was evaluated |
| `default_encryption_inferred_count` | Evaluated buckets counted from the documented AWS SSE-S3 baseline rather than a readable encryption rule |
| `default_encryption_unknown_count` | Buckets whose default encryption setting could not be evaluated |
| `versioning_enabled` | Percentage of buckets with versioning enabled |
| `versioning_enabled_bucket_count` | Buckets with versioning enabled |
| `logging_required_bucket_count` | Buckets that are not a server access log destination |
| `logging_enabled` | Percentage of those buckets with access logging |
| `logging_enabled_bucket_count` | Those buckets with access logging |
| `account_public_access_block_enabled` | Whether account-level public access block is enabled |

### RDS Security

| Metric | Description |
|--------|-------------|
| `regions_evaluated_count` | Regions whose RDS listing succeeded; aggregates cover only these regions |
| `regions_failed` | Regions whose RDS listing failed. Aggregates are meaningful only when absent |
| `database_count` | Instances plus clusters across evaluated regions |
| `instance_count` | Instances across evaluated regions |
| `encrypted_at_rest` | Percentage of instances/clusters with encryption |
| `publicly_accessible` | Percentage of instances publicly accessible (should be 0%) |
| `deletion_protection` | Percentage with deletion protection enabled |
| `backup_retention_adequate` | Percentage with backup retention >= 7 days |
| `multi_az_enabled` | Percentage with Multi-AZ deployment |
| `*_database_count`, `publicly_accessible_instance_count` | The count each percentage above is taken of |

### Network Security

| Metric | Description |
|--------|-------------|
| `regions_evaluated_count` | Regions whose network listing succeeded; exposure aggregates cover only these regions |
| `regions_failed` | Regions whose network listing failed. Exposure aggregates are meaningful only when absent, since partial coverage can only understate exposure |
| `security_group_count` | Security groups across evaluated regions |
| `open_to_world_ssh` | Percentage of security groups allowing SSH from 0.0.0.0/0 or ::/0 |
| `open_to_world_ssh_security_group_count` | Security groups allowing SSH from 0.0.0.0/0 or ::/0 |
| `open_to_world_rdp` | Percentage allowing RDP from 0.0.0.0/0 or ::/0 |
| `open_to_world_rdp_security_group_count` | Security groups allowing RDP from 0.0.0.0/0 or ::/0 |
| `vpcs[].flow_logs_enabled` | Internal-level per-VPC flow log status |
| `vpcs[].flow_logs_evaluated` | Whether internal-level flow log status was evaluated for the VPC |
| `vpcs[].flow_logs_error_code` | Error code when internal-level flow log status could not be read |

### Account Security Services

| Service | Metrics |
|---------|---------|
| **CloudTrail** | Trail-listing evaluated marker and error code, enabled, multi-region, organization trail coverage, trail-status evaluated / inferred / unknown counts |
| **AWS Config** | Enabled, recorder running |
| **GuardDuty** | Enabled, unremediated high/critical findings >48h, finding notification routing |
| **Security Hub** | Enabled, CIS AWS Foundations Benchmark level 1/2/unknown-level compliance |
| **Inspector** | Status evaluated marker and error code, enabled, unpatched server %, the unpatched resources it is taken of, and the affected resources it is over |

For CIS level splits, the collector uses Security Hub finding `related_requirements` level tags and aggregates to one status per control (FAILED > WARNING > PASSED > NOT_AVAILABLE).
Findings without explicit level tags are reported in an explicit unknown-level bucket.

Interpretation guide:
- `security_hub.enabled=true` means Security Hub is available in the account/region.
- `level_1` and `level_2` values are only populated when findings include explicit level tags.
- `unknown_level` captures CIS controls where Security Hub did not provide a level tag.
- `compliance_percent` is over `scored_controls`, the passed, failed, and warning controls; it is null when there are none.

### Identity Center (IAM Identity Center / AWS SSO)

| Metric | Description |
|--------|-------------|
| `enabled` | Whether an Identity Center instance was found in any scanned region. A member account cannot see its organization's instance |
| `instance_status` | AWS's status for the instance, such as `ACTIVE`. Only an active instance signs people in |
| `instance_owner_account_id` | The account that owns the instance: the management account for an organization instance |
| `instance_type` | `organization` or `account`. An account instance cannot sign people in to AWS accounts |
| `user_count` | Users in the connected identity store |
| `external_id_user_count` | Users with an external ID, which an external identity provider sets when it provisions users. The IDs are not collected |
| `mfa_evidence` | Where users' MFA is set: `external_idp` when every user has an external ID, `manual_required` when none does, and `unknown` for a mix or a directory with no users |
| `group_count` | Groups in the connected identity store |
| `permission_set_count` | Permission sets provisioned on the instance |
| `regions_checked` | The scanned regions whose instance listing answered |

### Lambda

| Metric | Description |
|--------|-------------|
| `function_count` | Total Lambda functions across regions |
| `deprecated_runtime_count` | Functions on AWS-deprecated runtimes (Node ≤16, Python ≤3.8, Ruby ≤2.7, Java 8, Go 1.x, .NET Core ≤6) |

### EC2

| Metric | Description |
|--------|-------------|
| `instance_count` | Running instances across regions |
| `imdsv2_required_count` | Instances enforcing IMDSv2 (HttpTokens=required) |
| `public_ip_count` | Instances with a public IP |
| `default_vpc_count` | Instances in the default VPC (anti-pattern) |
| `instances_with_unencrypted_volume_count` | Instances with at least one unencrypted attached EBS volume |

### CloudWatch Logs

| Metric | Description |
|--------|-------------|
| `log_group_count` | Log groups across regions |
| `log_groups_without_retention_count` | Groups with no retention policy (logs accumulate forever) |
| `log_groups_without_customer_kms_count` | Groups using AWS-managed (vs customer-managed) KMS |

### KMS

Scoped to CUSTOMER-managed keys only; AWS-managed keys offer no posture lever.

| Metric | Description |
|--------|-------------|
| `customer_managed_key_count` | Customer-managed keys across regions |
| `cmks_with_rotation_disabled_count` | Keys KMS can rotate (symmetric, with key material KMS generated) that have automatic rotation off |
| `cmks_pending_deletion_count` | Keys scheduled for deletion |

### Secrets Manager

Secret VALUES are NEVER collected — only metadata. Value-reading APIs are forbidden in collector source by build-time lint.

| Metric | Description |
|--------|-------------|
| `secret_count` | Secrets across regions |
| `secrets_without_rotation_count` | Secrets without auto-rotation configured |
| `secrets_without_customer_kms_count` | Secrets using AWS-managed (vs customer-managed) KMS |
| `secrets_pending_deletion_count` | Secrets scheduled for deletion |

### SSM Parameter Store

Parameter VALUES are NEVER collected — only metadata. Value-reading APIs are forbidden in collector source by build-time lint.

| Metric | Description |
|--------|-------------|
| `parameter_count` | Parameters across regions |
| `secure_string_count` | SecureString-type parameters (the encrypted, sensitive ones) |
| `secure_strings_without_customer_kms_count` | SecureStrings using `alias/aws/ssm` (vs a customer-managed key) |

## Testing

- Unit tests validate collector math/aggregation and AWS helper logic:
  - `go test ./...`
- E2E tests hit live AWS APIs and are opt-in:
  - `AWS_E2E_RUN=true go test -tags=e2e -v ./internal/collector/...`

## Multi-Region Collection

The collector automatically handles AWS's regional vs global services:

- **Global services** (IAM, S3 bucket listing, CloudTrail): Collected once
- **Regional services** (RDS, EC2, GuardDuty, Lambda, CloudWatch Logs, KMS, Secrets Manager, SSM Parameters): Collected from all configured regions
- **IAM Identity Center**: Looked for in every scanned region, since the instance's home region can be any of them. A member account cannot see its organization's instance, so the roles and SAML provider Identity Center creates in the account show it there

Metrics from regional services are aggregated across all regions.

## Multi-Account Collection

Configure multiple accounts to collect from all AWS accounts in your organization:

```yaml
collectors:
  - name: aws
    config:
      accounts:
        - role_arn: "arn:aws:iam::111111111111:role/EpackCollectorRole"
          label: "production"
        - role_arn: "arn:aws:iam::222222222222:role/EpackCollectorRole"
          label: "staging"
```

The optional `label` is operator-supplied and rides each account's output as
`account_label`, including failed-account records.

Each account's posture is collected independently and included in the output.
An account that fails entirely is recorded under `failed_accounts` (with the
account ID parsed from its role ARN and the upstream error code) instead of
silently disappearing, and the normalized artifact carries a matching stub
entry (with `collection_error_code` and no metric groups) plus an
`accounts_expected` count. A metric group with no value left in it is left out
of the normalized artifact.

## Normalized Artifact

The normalized artifact (`artifacts/aws.cloud-posture.json`) follows the
`evidencepack/cloud-posture@v1` schema. Each account carries the counts behind
its MFA and access key rotation percentages, `iam.user_count` and
`iam.access_key_user_count`. A count is 0 when there is nothing to count, and
the percentage is then left out. `iam.saml_provider_count` counts the SAML
providers the account trusts directly. It leaves out the one IAM Identity
Center creates.

The top-level `workforce_sign_in` block describes IAM Identity Center, AWS's
workforce sign-in service, across the accounts:

- `in_use` is true when any account shows an active organization instance,
  the roles Identity Center provisions, or the SAML provider it creates. It is
  false when the instance and role listings answered for every account and
  found neither. The SAML provider listing is not needed for false.
- `user_count` is the number of users in the organization instance's
  directory, when an account could read it.
- `mfa_source` is `external_idp` when every user has an external ID, and
  `sign_in_service` when none does, in which case Identity Center's own MFA
  settings apply. It is `unknown` for a mix, a directory with no users, or
  when no account could see the instance, and left out when `in_use` is
  false. Each account's `identity_center.mfa_evidence` in the detailed
  artifact gives the same answer, with `manual_required` for
  `sign_in_service`.

When the accounts' evidence cannot decide a value, the value is left out, and
the run's result names the read that failed. For example, `in_use` is left out
when an account's instance listing failed and no account shows Identity
Center.
