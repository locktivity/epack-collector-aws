# AWS Collector Overview

The AWS collector gathers security posture metrics from AWS accounts, providing visibility into IAM, S3, RDS, network, and account-level security configurations.

## What It Collects

### IAM Security

| Metric | Description |
|--------|-------------|
| `iam_users_present` | Whether at least one IAM user (excluding root) exists in the account |
| `mfa_enabled` | Percentage of IAM users with MFA enabled |
| `hardware_mfa_enabled` | Percentage of IAM users with hardware MFA (currently reported as 0) |
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

## Testing

- Unit tests validate collector math/aggregation and AWS helper logic:
  - `go test ./...`
- E2E tests hit live AWS APIs and are opt-in:
  - `AWS_E2E_RUN=true go test -tags=e2e -v ./internal/collector/...`

## Multi-Region Collection

The collector automatically handles AWS's regional vs global services:

- **Global services** (IAM, S3 bucket listing, CloudTrail): Collected once
- **Regional services** (RDS, EC2, GuardDuty): Collected from all configured regions

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
