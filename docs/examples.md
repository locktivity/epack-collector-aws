# AWS Collector Examples

## Basic Usage

Collect from the current AWS account using default credentials:

```yaml
collectors:
  aws:
    source: "locktivity/epack-collector-aws@^0.1.0"
    config: {}
```

## Cross-Account Collection

### With OIDC (Recommended for GitHub Actions)

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

### With AssumeRole

```yaml
collectors:
  aws:
    source: "locktivity/epack-collector-aws@^0.1.0"
    config:
      auth_mode: "assume_role"
      role_arn: "arn:aws:iam::123456789012:role/EpackCollectorRole"
      external_id: "epack-collection-abc123"
```

## Multi-Account Collection

### With OIDC

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
    secrets:
      - ACTIONS_ID_TOKEN_REQUEST_URL
      - ACTIONS_ID_TOKEN_REQUEST_TOKEN
```

### With AssumeRole

```yaml
collectors:
  aws:
    source: "locktivity/epack-collector-aws@^0.1.0"
    config:
      auth_mode: "assume_role"
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
  aws:
    source: "locktivity/epack-collector-aws@^0.1.0"
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
        "credential_report_evaluated": true,
        "iam_users_present": true,
        "mfa_enabled": 95,
        "hardware_mfa_enabled": 0,
        "access_keys_rotated": 80,
        "root_credential_state_evaluated": true,
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
        "bucket_listing_evaluated": true,
        "account_public_access_block_evaluated": true,
        "bucket_count": 20,
        "public_access_blocked": 100,
        "public_access_block_unknown_count": 0,
        "default_encryption_enabled": 95,
        "default_encryption_evaluated_count": 20,
        "default_encryption_inferred_count": 0,
        "default_encryption_unknown_count": 0,
        "versioning_enabled": 60,
        "logging_enabled": 40,
        "account_public_access_block_enabled": true
      },
      "rds": {
        "regions_evaluated_count": 2,
        "database_count": 6,
        "encrypted_at_rest": 100,
        "publicly_accessible": 0,
        "deletion_protection": 90,
        "backup_retention_adequate": 100,
        "multi_az_enabled": 80
      },
      "network": {
        "regions_evaluated_count": 2,
        "open_to_world_ssh": 2,
        "open_to_world_rdp": 0
      },
      "account_security": {
        "cloudtrail": {
          "trail_listing_evaluated": true,
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
          "status_evaluated": true,
          "enabled": true,
          "unpatched_server_percent": 25
        }
      }
    }
  ]
}
```

## CI/CD Integration

### GitHub Actions with OIDC (Recommended)

Using OIDC, the collector obtains credentials directly from GitHub without needing `aws-actions/configure-aws-credentials`:

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
      id-token: write  # Required for OIDC token
      contents: read

    steps:
      - name: Install epack
        run: |
          curl -sSL https://install.epack.dev | bash

      - name: Collect AWS posture
        run: |
          epack collect
        # epack.yaml should have:
        # collectors:
        #   aws:
        #     source: "locktivity/epack-collector-aws@^0.1.0"
        #     config:
        #       auth_mode: "oidc"
        #       role_arn: "arn:aws:iam::123456789012:role/EpackCollectorRole"
        #     secrets:
        #       - ACTIONS_ID_TOKEN_REQUEST_URL
        #       - ACTIONS_ID_TOKEN_REQUEST_TOKEN
```

The `secrets` field tells epack to pass through the `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` environment variables (provided by GitHub when `id-token: write` permission is set). The collector uses these to obtain an OIDC token.

### GitHub Actions with AssumeRole

If OIDC isn't available, use `aws-actions/configure-aws-credentials` to obtain bootstrap credentials:

```yaml
name: Security Posture Collection

on:
  schedule:
    - cron: '0 6 * * *'
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
          role-to-assume: arn:aws:iam::BOOTSTRAP_ACCOUNT:role/BootstrapRole
          aws-region: us-east-1

      - name: Install epack
        run: |
          curl -sSL https://install.epack.dev | bash

      - name: Collect AWS posture
        run: |
          epack collect
        # epack.yaml should have:
        # collectors:
        #   aws:
        #     source: "locktivity/epack-collector-aws@^0.1.0"
        #     config:
        #       auth_mode: "assume_role"
        #       role_arn: "arn:aws:iam::TARGET_ACCOUNT:role/EpackCollectorRole"
        #       external_id: "your-external-id"
```

## Terraform for IAM Role

### OIDC Trust Policy (Recommended for GitHub Actions)

```hcl
# First, create the GitHub OIDC provider (once per account)
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["ffffffffffffffffffffffffffffffffffffffff"]
}

resource "aws_iam_role" "epack_collector" {
  name = "EpackCollectorRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:*"
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

variable "github_org" {
  description = "GitHub organization name"
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name"
  type        = string
}
```

### AssumeRole Trust Policy

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

### Collector Policy (shared by both)

The list below is the trust-level (default) set. The authoritative, level-tiered permission reference lives in the README under Required IAM Permissions; add the audit or internal actions from there when your pipeline collects at those levels.

```hcl
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
          "iam:GetAccountSummary",
          "iam:GetCredentialReport",
          "iam:GenerateCredentialReport",
          "iam:ListOrganizationsFeatures",
          "iam:ListUsers",
          "iam:ListMFADevices",
          "iam:ListRoles",
          "iam:GetRole",
          "iam:ListAccountAliases",
          "s3:ListAllMyBuckets",
          "s3:GetBucket*",
          "s3:GetEncryptionConfiguration",
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
          "sso:ListInstances",
          "sso:ListPermissionSets",
          "identitystore:ListUsers",
          "identitystore:ListGroups",
          "lambda:ListFunctions",
          "logs:DescribeLogGroups",
          "kms:ListKeys",
          "kms:DescribeKey",
          "kms:GetKeyRotationStatus",
          "secretsmanager:ListSecrets",
          "ssm:DescribeParameters",
          "access-analyzer:ListAnalyzers",
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
      }
    ]
  })
}
```
