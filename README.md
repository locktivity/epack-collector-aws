# epack-collector-aws

Collects AWS account security posture metrics for the epack ecosystem.

## Features

- **Multi-account support**: Collect from multiple AWS accounts in a single run
- **IAM security**: MFA coverage, password policies, access key rotation, root account security
- **S3 security**: Encryption, public access blocks, versioning, logging
- **RDS security**: Encryption, public accessibility, deletion protection, backups
- **Network security**: Security group analysis, VPC flow logs
- **Account security services**: CloudTrail, AWS Config, GuardDuty, Security Hub, Inspector

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

### Single Account

```yaml
collectors:
  - name: aws
    config:
      role_arn: "arn:aws:iam::123456789012:role/EpackCollectorRole"
      external_id: "unique-external-id"  # optional
      regions:
        - us-east-1
        - us-west-2
```

### Multi-Account

```yaml
collectors:
  - name: aws
    config:
      accounts:
        - role_arn: "arn:aws:iam::111111111111:role/EpackCollectorRole"
          external_id: "prod-external-id"
        - role_arn: "arn:aws:iam::222222222222:role/EpackCollectorRole"
          external_id: "staging-external-id"
      regions:
        - us-east-1
        - us-west-2
```

### Default Credentials

If no `role_arn` or `accounts` specified, the collector uses the default AWS credential chain (environment variables, config file, instance profile).

## Required IAM Permissions

Create a role with the following read-only permissions in each target account:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountPasswordPolicy",
        "iam:GetCredentialReport",
        "iam:GenerateCredentialReport",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListRoles",
        "iam:GetRole",
        "iam:ListAccountAliases",
        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicy",
        "s3:GetBucketLocation",
        "s3:GetAccountPublicAccessBlock",
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "ec2:DescribeVpcs",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeRegions",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "guardduty:ListFindings",
        "securityhub:DescribeHub",
        "securityhub:GetEnabledStandards",
        "securityhub:ListEnabledProductsForImport",
        "securityhub:GetFindings",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## Output

The collector outputs JSON with posture metrics for each account:

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
