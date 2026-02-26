# AWS Collector Configuration

## Authentication

The AWS collector supports multiple authentication methods:

### 1. IAM Role (Recommended for Cross-Account)

Create an IAM role in each target account with the required permissions and a trust policy allowing the collector to assume it.

**Trust Policy:**

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
  - name: aws
    config:
      role_arn: "arn:aws:iam::123456789012:role/EpackCollectorRole"
      external_id: "your-external-id"
```

### 2. Default Credential Chain

If no `role_arn` is specified, the collector uses the AWS SDK's default credential chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. Shared credentials file (`~/.aws/credentials`)
3. EC2 instance profile / ECS task role

```yaml
collectors:
  - name: aws
    config:
      regions:
        - us-east-1
```

## Required IAM Permissions

Create a managed policy with these read-only permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IAMReadAccess",
      "Effect": "Allow",
      "Action": [
        "iam:GetCredentialReport",
        "iam:GenerateCredentialReport",
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
        "s3:GetBucketEncryption",
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
        "ec2:DescribeFlowLogs",
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

```yaml
collectors:
  - name: aws
    config:
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

## Region Configuration

By default, the collector discovers all enabled regions in the account. To limit to specific regions:

```yaml
collectors:
  - name: aws
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
