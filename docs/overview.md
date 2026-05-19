# AWS Collector Overview

The AWS collector gathers security posture metrics from AWS accounts. The
amount of detail it gathers is controlled by an optional `level` config knob
with three values: `trust` (default, pass/fail posture only), `audit` (adds
per-resource breakdowns), and `internal` (adds raw identifying detail for
breach investigation). See [levels.md](levels.md) for the full contract.

This page lists the surfaces and their trust-level signals. Per-level field
breakdowns live in [levels.md](levels.md); the machine-readable shape lives
in [schema/v1.0.0.json](schema/v1.0.0.json).

## What It Collects

### IAM Security

| Metric | Description |
|--------|-------------|
| `iam_users_present` | Whether at least one IAM user (excluding root) exists in the account |
| `mfa_enabled` | Percentage of IAM users with MFA enabled |
| `hardware_mfa_enabled` | Percentage of IAM users with hardware MFA (physical OTP devices or FIDO/U2F security keys) |
| `access_keys_rotated` | Percentage of access keys rotated within 90 days |
| `root_mfa_enabled` | Whether the root account has MFA enabled |
| `root_access_keys_exist` | Whether root has access keys (should be false) |

### S3 Security

| Metric | Description |
|--------|-------------|
| `public_access_blocked` | Percentage of buckets with public access blocked |
| `default_encryption_enabled` | Percentage of buckets with default encryption |
| `versioning_enabled` | Percentage of buckets with versioning enabled |
| `logging_enabled` | Percentage of buckets with access logging |
| `account_public_access_block_enabled` | Whether account-level public access block is enabled |

### RDS Security

| Metric | Description |
|--------|-------------|
| `encrypted_at_rest` | Percentage of instances/clusters with encryption |
| `publicly_accessible` | Percentage publicly accessible (should be 0%) |
| `deletion_protection` | Percentage with deletion protection enabled |
| `backup_retention_adequate` | Percentage with backup retention >= 7 days |
| `multi_az_enabled` | Percentage with Multi-AZ deployment |

### Network Security

| Metric | Description |
|--------|-------------|
| `open_to_world_ssh` | Percentage of security groups allowing SSH from 0.0.0.0/0 |
| `open_to_world_rdp` | Percentage allowing RDP from 0.0.0.0/0 |
| `flow_logs_enabled` | Percentage of VPCs with flow logs |

### Account Security Services

| Service | Metrics |
|---------|---------|
| **CloudTrail** | Enabled, multi-region |
| **AWS Config** | Enabled, recorder running |
| **GuardDuty** | Enabled, unremediated high/critical findings >48h |
| **Security Hub** | Enabled, CIS AWS Foundations Benchmark level 1/2/unknown-level compliance |
| **Inspector** | Enabled, unpatched server % |

For CIS level splits, the collector uses Security Hub finding `related_requirements` level tags and aggregates to one status per control (FAILED > WARNING > PASSED > NOT_AVAILABLE).
Findings without explicit level tags are reported in an explicit unknown-level bucket.

Interpretation guide:
- `security_hub.enabled=true` means Security Hub is available in the account/region.
- `level_1` and `level_2` values are only populated when findings include explicit level tags.
- `unknown_level` captures CIS controls where Security Hub did not provide a level tag.

### Identity Center (IAM Identity Center / AWS SSO)

| Metric | Description |
|--------|-------------|
| `enabled` | Whether an IdC instance exists in the primary region |
| `user_count` | Users in the connected identity store |
| `group_count` | Groups in the connected identity store |
| `permission_set_count` | Permission sets provisioned on the instance |

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
| `cmks_with_rotation_disabled_count` | Symmetric CMKs without automatic key rotation |
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
- **IAM Identity Center**: Probed once in the primary region; accounts with IdC deployed elsewhere should configure that region as primary

Metrics from regional services are aggregated across all regions.

## Multi-Account Collection

Configure multiple accounts to collect from all AWS accounts in your organization:

```yaml
collectors:
  - name: aws
    config:
      accounts:
        - role_arn: "arn:aws:iam::111111111111:role/EpackCollectorRole"
        - role_arn: "arn:aws:iam::222222222222:role/EpackCollectorRole"
```

Each account's posture is collected independently and included in the output.
