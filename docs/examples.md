# AWS Collector Examples

## Basic Usage

Collect from the current AWS account using default credentials:

```yaml
collectors:
  - name: aws
    config: {}
```

## Cross-Account Collection

Assume a role in a target account:

```yaml
collectors:
  - name: aws
    config:
      role_arn: "arn:aws:iam::123456789012:role/EpackCollectorRole"
      external_id: "epack-collection-abc123"
```

## Multi-Account Collection

Collect from multiple AWS accounts:

```yaml
collectors:
  - name: aws
    config:
      accounts:
        - role_arn: "arn:aws:iam::111111111111:role/EpackCollectorRole"
          external_id: "prod"
        - role_arn: "arn:aws:iam::222222222222:role/EpackCollectorRole"
          external_id: "staging"
        - role_arn: "arn:aws:iam::333333333333:role/EpackCollectorRole"
          external_id: "dev"
```

## Specific Regions Only

Limit collection to specific regions:

```yaml
collectors:
  - name: aws
    config:
      role_arn: "arn:aws:iam::123456789012:role/EpackCollectorRole"
      regions:
        - us-east-1
        - us-west-2
        - eu-west-1
```

## Sample Output

Metrics use percentages (0-100), booleans, and counts where appropriate.

```json
{
  "schema_version": "1.0.0",
  "collected_at": "2024-01-15T10:30:00Z",
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
        "root_access_keys_exist": false
      },
      "s3": {
        "public_access_blocked": 100,
        "default_encryption_enabled": 95,
        "versioning_enabled": 60,
        "logging_enabled": 40,
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
        "open_to_world_rdp": 0,
        "flow_logs_enabled": 100
      },
      "account_security": {
        "cloudtrail": {
          "enabled": true,
          "multi_region_enabled": true
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
      }
    }
  ]
}
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Posture Collection

on:
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM UTC
  workflow_dispatch:

jobs:
  collect:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read

    steps:
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/EpackCollectorRole
          aws-region: us-east-1

      - name: Install epack
        run: |
          curl -sSL https://install.epack.dev | bash

      - name: Collect AWS posture
        run: |
          epack collect
```

## Terraform for IAM Role

```hcl
resource "aws_iam_role" "epack_collector" {
  name = "EpackCollectorRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.collector_account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.external_id
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "epack_collector" {
  role       = aws_iam_role.epack_collector.name
  policy_arn = aws_iam_policy.epack_collector.arn
}

resource "aws_iam_policy" "epack_collector" {
  name        = "EpackCollectorPolicy"
  description = "Read-only access for epack AWS collector"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:GetAccountPasswordPolicy",
          "iam:GetCredentialReport",
          "iam:GenerateCredentialReport",
          "iam:ListUsers",
          "iam:ListMFADevices",
          "iam:ListRoles",
          "iam:GetRole",
          "iam:ListAccountAliases",
          "s3:ListAllMyBuckets",
          "s3:GetBucket*",
          "s3:GetAccountPublicAccessBlock",
          "rds:DescribeDB*",
          "ec2:DescribeVpcs",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeFlowLogs",
          "ec2:DescribeRegions",
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "config:Describe*",
          "guardduty:ListDetectors",
          "guardduty:GetDetector",
          "guardduty:ListFindings",
          "securityhub:Describe*",
          "securityhub:Get*",
          "securityhub:List*",
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
      }
    ]
  })
}

variable "collector_account_id" {
  description = "AWS account ID where the collector runs"
  type        = string
}

variable "external_id" {
  description = "External ID for assume role"
  type        = string
  default     = "epack-collector"
}
```
