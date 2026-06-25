# AWS Collector Configuration

## Authentication

The AWS collector supports multiple authentication methods. The `auth_mode` option controls how the collector assumes IAM roles:

- `oidc` - Uses GitHub Actions OIDC to assume roles via `AssumeRoleWithWebIdentity` (recommended for GitHub Actions)
- `assume_role` - Uses standard `AssumeRole` with optional `external_id` (default for backward compatibility)

### 1. GitHub Actions OIDC (Recommended)

When running in GitHub Actions, OIDC provides secure, credential-free authentication. The collector obtains a JWT token from GitHub and exchanges it for temporary AWS credentials.

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
3. EC2 instance profile / ECS task role

```yaml
collectors:
  aws:
    source: "locktivity/epack-collector-aws@^0.1.0"
    config:
      regions:
        - us-east-1
```

## Required IAM Permissions

Create a managed policy with these read-only permissions:

`iam:ListOrganizationsFeatures` only evaluates centralized root access when
the collector role runs in the AWS Organizations management account or an IAM
delegated administrator account. Member-account roles record the AWS error code
as evidence instead of inferring the organization-level state.

For internal-level collection, also grant `ec2:DescribeFlowLogs` so VPC rows can
include per-VPC flow log status. Trust and audit collection do not call that API.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IAMReadAccess",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountSummary",
        "iam:GetCredentialReport",
        "iam:GenerateCredentialReport",
        "iam:ListOrganizationsFeatures",
        "iam:ListAccountAliases"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3ReadAccess",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicy",
        "s3:GetBucketLocation",
        "s3:GetAccountPublicAccessBlock"
      ],
      "Resource": "*"
    },
    {
      "Sid": "RDSReadAccess",
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EC2ReadAccess",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcs",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeRegions"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudTrailReadAccess",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ConfigReadAccess",
      "Effect": "Allow",
      "Action": [
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus"
      ],
      "Resource": "*"
    },
    {
      "Sid": "GuardDutyReadAccess",
      "Effect": "Allow",
      "Action": [
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "guardduty:ListFindings"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SecurityHubReadAccess",
      "Effect": "Allow",
      "Action": [
        "securityhub:DescribeHub",
        "securityhub:GetEnabledStandards",
        "securityhub:ListEnabledProductsForImport",
        "securityhub:GetFindings"
      ],
      "Resource": "*"
    },
    {
      "Sid": "STSReadAccess",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
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

By default, the collector discovers all enabled regions in the account. To limit to specific regions:

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

1. Verify the IAM role/user has all required permissions
2. Check that the trust policy allows the collector's identity
3. Ensure the external ID matches (if configured)

### "Credential Report Not Ready"

The collector automatically retries generating the credential report. If it times out after 10 attempts, check IAM permissions for `iam:GenerateCredentialReport`.

### "Service Not Available in Region"

Some services (like GuardDuty) may not be available in all regions. The collector handles this gracefully and continues with available services.

### Rate Limiting

The AWS SDK automatically handles rate limiting with exponential backoff. For large accounts with many resources, collection may take several minutes.
