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
| `console_user_count` | IAM users with a console password, who can sign in |
| `console_mfa_enabled` | Percentage of the IAM users who can sign in with MFA enabled |
| `console_mfa_user_count` | IAM users who can sign in with MFA enabled |
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
| `root_organization_id` | Audit level and above: the organization ID returned by IAM when centralized root access features were read |
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
| `public_access_blocked` | Percentage of databases with no publicly accessible instance. A cluster counts when none of its instances is publicly accessible |
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
- Each level's `enabled` is true when a CIS standard is enabled, including one that has no findings yet. Every CIS standard covers both levels.
- `level_1` and `level_2` counts are only populated when findings include explicit level tags.
- `unknown_level` captures CIS controls where Security Hub did not provide a level tag.
- `compliance_percent` is over `scored_controls`, the passed, failed, and warning controls; it is null when there are none.

### Identity Center (IAM Identity Center / AWS SSO)

| Metric | Description |
|--------|-------------|
| `enabled` | Whether an Identity Center instance was found in any scanned region. A member account cannot see its organization's instance |
| `instance_status` | AWS's status for the instance, such as `ACTIVE`. Only an active instance signs people in |
| `instance_owner_account_id` | Audit level and above: the account that owns the instance, the management account for an organization instance |
| `instance_type` | `organization` or `account`. An account instance cannot sign people in to AWS accounts |
| `user_count` | Users in the connected identity store |
| `external_id_user_count` | Users with an external ID from SCIM provisioning, which IAM Identity Center sets when an external identity provider provisions a user. External IDs from other issuers, such as an Active Directory sync, do not count. The IDs are not collected |
| `mfa_evidence` | Where users' MFA is set: `external_idp` when every user has an external ID from SCIM provisioning, `manual_required` when none does, and `unknown` for a mix or a directory with no users. Users synced from Active Directory count as Identity Center's own |
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

## Not Collected

AWS offers the following through its APIs, and the collector does not read
them.

- **Security Hub standards other than CIS.** Security Hub also checks controls
  for standards such as AWS Foundational Security Best Practices and PCI DSS.
  The collector reads control results only for the CIS AWS Foundations
  Benchmark.
- **AWS Backup.** AWS Backup lists the resources it has backed up and the
  backup plans that set their retention. The collector reads backup retention
  only from RDS.
- **Instance patch compliance.** Systems Manager Patch Manager reports how many
  patches each managed instance is missing against its patch baseline. The
  only Systems Manager data the collector reads is Parameter Store metadata.
- **ECR basic scanning.** Amazon ECR's basic scanning reports vulnerabilities
  in container images without Amazon Inspector. The collector reads image
  findings only from Inspector.

## Testing

- Unit tests validate collector math/aggregation and AWS helper logic:
  - `go test ./...`
- E2E tests hit live AWS APIs and are opt-in:
  - `AWS_E2E_RUN=true go test -tags=e2e -v ./internal/collector/...`

## Multi-Region Collection

The collector automatically handles AWS's regional vs global services:

- **Global services** (IAM, S3 bucket listing): Collected once
- **Regional services** (RDS, EC2, GuardDuty, Lambda, CloudWatch Logs, KMS, Secrets Manager, SSM Parameters): Collected from all configured regions
- **CloudTrail**: Trails are listed in every scanned region, since a single-region trail is listed only in its own region. A multi-region trail appears once
- **AWS Config and Security Hub**: Read in the primary region only. The primary region is the first configured region, or else the region the collector signs in to when it is enabled. A recorder or hub in another region is not counted, and Security Hub's CIS results cover the primary region's findings alone
- **Amazon Inspector**: Its status, coverage, and findings are read in every scanned region, for the vuln-scanning file. In the detailed file, `enabled` is Inspector's status in the primary region, and the other Inspector values come from Security Hub there
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
upstream error code, and from the audit level the account ID parsed from its
role ARN and the role itself) instead of silently disappearing, and the
normalized artifact carries a matching stub entry (with
`collection_error_code` and no metric groups). The normalized
`all_accounts_collected` is false when any account failed, and from the audit
level `accounts_expected` counts every configured account. A metric group with
no value left in it is left out of the normalized artifact. The access-posture
and vuln-scanning files leave a failed account out of `scopes`. Each total it
would add to is left out with its error.

## Normalized Artifacts

The collector writes three normalized files. A trust-level file has no
account IDs, `accounts_expected`, counts, or `scopes`, since the schemas mark
them audit-level. A percentage over an empty population is null, and its
present flag is false. When the accounts' evidence cannot decide a value, the
value is left out, and the run's result names the read that failed. A value
AWS never reports is left out with an `unsupported` gap. A value AWS reports
that the collector does not read is left out with a `not_read` gap, whose
detail names the call that would supply it.

### Cloud posture

`artifacts/aws.cloud-posture.json` follows the `evidencepack/cloud-posture@v1`
schema. Storage counts the S3 buckets, `database` the RDS instances and
clusters, and `network` the security groups. Each group has a present flag at
every level, such as `storage.storage_resources_present`, and the counts from
the audit level. Each percentage is computed from its counts. The exposure
percentages `network.ssh_open_to_world_pct` and
`network.rdp_open_to_world_pct` round up, so one exposed group never reads 0.
The other percentages round down. `database.multi_az_pct` is written from the
audit level. A database has public access blocked when it is a DB instance
outside a cluster that is not publicly accessible, or a DB cluster none of
whose instances is. `backup.retention_days_min` is the shortest automated
backup retention among the databases that keep automated backups, and null
when none does, since a database whose retention period is 0 days has them
off. The group is left out for an account with no database. The deprecated
`iam.user_count` and `iam.mfa_coverage_pct` count the IAM users with a
console password, as their access-posture replacements
`members.local_member_count` and `local_mfa_coverage_pct` do. The deprecated
`iam.access_key_user_count` and `access_key_rotation_compliant_pct` count the
users with an active access key, the root user included, as
`credentials.credential_count` counts the keys.
S3 has no setting that turns off public network access, so
`storage.network_restricted_pct` and its count are left out with an
`unsupported` gap. `threat_detection.enabled` is true when every scanned
region has a GuardDuty detector whose status is `ENABLED`.

### Access posture

`artifacts/aws.access-posture.json` follows the
`evidencepack/access-posture@v1` schema, with `system_type` `cloud`. Its
sections hold totals across the accounts. From the audit level, `scopes`
lists each account alone, with its alias as the name. A present flag is true
when any account's is. `sign_in.sso_configured` is false when any account's
is false, left out when any other account's is unknown, and true otherwise.

- `sign_in.sso_configured` is true when an account has an active
  organization instance of IAM Identity Center, an `AWSReservedSSO_` role, or
  a SAML provider. AWS has no account setting to require SSO or MFA for
  everyone, so `sso_required` and `mfa_required` are left out. So is
  `scim_enabled`.
- Members are the IAM users with a console password in the credential
  report, and the users of the organization's IAM Identity Center. An IAM
  user with access keys and no console password is a credential, not a
  member. Every IAM member can sign in with its own password, so the
  `local_*` values count the IAM members, with MFA from the report's
  `mfa_active`. An IAM member is inactive when the password and access keys
  were all last used more than 90 days before the run, or never.
- `members.sso_member_count` counts the users in the directory of the
  organization instance, when an account can read it. It is 0 when no account
  has Identity Center. People who sign in through a SAML provider an account
  trusts directly are not counted. `member_count` adds them to the IAM
  members, and `sso_coverage_pct` is their share. An account in `scopes`
  counts the users ListAccountAssignments assigns to it, directly or through
  a group, read from the account that holds the organization instance. When
  Identity Center users are counted, the inactive members are left out with a
  `not_read` gap, since their sign-ins are in CloudTrail. The external member
  values are left out.
- Admins are the IAM members with one of the AWS managed policies
  `AdministratorAccess`, `PowerUserAccess`, or `IAMFullAccess`, attached to
  the user or to one of the user's groups. A user with an inline or customer
  managed policy and none of those three leaves the admin counts out with a
  `partial` gap, since the admin check does not evaluate policy documents.
  So does a user whose policies cannot be read. When Identity Center users are
  counted, `admin_count` and `admin_share_pct` are left out with a `not_read`
  gap, since the policies of the permission sets assigned to them are not
  evaluated. The `local_admin_*` values still count the IAM admins.
- `root` counts one root user for each account. A root user counts as having
  MFA when it has MFA, or has no password, access key, or signing certificate
  to sign in with.
- Credentials are the active access keys in the credential report, the root
  user's included. AWS access keys never expire, so `never_expiring_pct` is
  100 whenever there is one. A key is unused when it was last used more than
  90 days before the run, or never. It is overdue for rotation when it was
  last rotated more than 90 days before the run.
- A key's unrestricted and write access values come from its IAM user's
  identity policies: the managed policies attached to the user and to its
  groups, read at their default version, and the inline policies of each. A
  key is unrestricted when an allow of every action on every resource, `*` on
  `*`, holds with no deny taking any of it back, and its requests are not
  limited to a set of source addresses. A deny of every action with a
  `NotIpAddress` condition on `aws:SourceIp` limits them, and so does an
  `IpAddress` condition on `aws:SourceIp` on every allow, unless the set of
  addresses holds `0.0.0.0/0` or `::/0`. A key can write when it is allowed
  every action, or an action that is not read-only. An action is read-only
  when its name after the service prefix starts with Get, List, Describe,
  Head, BatchGet, Search, Lookup, Scan, Query, Select, or View, as `s3:Get*`
  does, and the AWS managed `ReadOnlyAccess`, `ViewOnlyAccess`, and
  `SecurityAudit` policies are read-only. A deny of every action on every
  resource with no condition leaves a key no permission, so it counts in
  neither value. A request signed with an access key carries no MFA, so a
  statement that requires MFA does not apply to it, and one that applies only
  without MFA, such as a deny with a `BoolIfExists` condition that
  `aws:MultiFactorAuthPresent` is false, does. Other conditions are not
  evaluated: an allow with one still counts, and a deny with one still takes
  back full access. The root user's keys are unrestricted and can write,
  since no IAM policy limits the root user.
- A key whose user has a permissions boundary leaves out each value its
  identity policies allow, with a `not_read` gap, since the boundary can take
  it back and is not evaluated. When a policy or a boundary cannot be read,
  the values it could change are left out with that read's gap, unless the
  policies that were read decide them: a deny of everything decides both, and
  a deny that takes back full access, or limits the source addresses,
  decides that the key is not unrestricted. Service control policies, which
  can narrow what a key can do in an account in AWS Organizations, are not
  read or evaluated, and neither are resource-based policies.
- Connected apps are the AWS accounts outside the organization that an IAM
  role's trust policy lets assume the role without MFA. `app_count` counts
  each such account once, however many roles in however many accounts trust
  it. A trust policy statement that requires MFA lets in people who sign in
  from the other account, not an app, so an account only such statements
  admit is not counted. A statement requires MFA when it has a `Bool`
  condition that `aws:MultiFactorAuthPresent` is true, or a numeric condition
  on `aws:MultiFactorAuthAge`. `BoolIfExists` with `aws:MultiFactorAuthPresent`
  true does not count, since AWS lets requests signed with an IAM user's
  access keys through it. An account that any other statement admits, such as
  one with a vendor's `sts:ExternalId` condition, is counted. The detailed
  file's `roles[]` still shows every account a role trusts. The
  organization's accounts come from AWS Organizations' `ListAccounts`, and an
  account in no organization has none but itself. A role that trusts only its
  own account, a service principal, or a SAML or OIDC provider, such as IAM
  Identity Center's `AWSSSO_` provider or a GitHub Actions OIDC provider, adds
  none, since those let in the account's own people and workloads. An account
  the run collects is not counted either, and neither are IAM Identity Center
  applications, since users signing in to an application gives it no access
  to the account. When an account's roles cannot be listed, both values are
  left out with that call's gap. When a role lets another account in without
  MFA and `ListAccounts` fails, as it does outside the management account and
  a delegated administrator, they are left out with its gap. When a role lets
  every principal, `*`, assume it without MFA, they are left out with a
  `not_read` gap, since the trust policy's other conditions decide whom it
  admits and are not evaluated. In each case `apps_present` is still true
  when an account is known to be outside. The roles are listed at every
  level, and `app_count` is written from the audit level.

### Vulnerability scanning

`artifacts/aws.vuln-scanning.json` follows the
`evidencepack/vuln-scanning@v1` schema. It has one `inspector` entry each for
`hosts`, `containers`, and `functions`. Amazon Inspector's status, coverage,
and findings are read in every scanned region. From the audit level, `scopes`
lists each account alone.

- `enabled` is true when Inspector and the category's scan type are on in
  every scanned region. The scan types are EC2 scanning for hosts, ECR
  scanning for containers, and Lambda standard scanning for functions.
- The hosts are the running EC2 instances, and the functions are the Lambda
  functions. The containers are the ECR images in Inspector's coverage, which
  has them only where ECR scanning is on. Where it is off, the container
  resource values are left out with a `not_read` gap, since ECR itself is not
  read.
- A resource is scanned when its scan status in Inspector's coverage is
  `ACTIVE`. A region where Inspector is off adds no scanned resource and no
  finding.
- The open findings are Inspector's `ACTIVE` findings, by severity. A finding
  is overdue when it is rated critical and was first observed more than 30
  days before the run, or rated high and first observed more than 90 days
  before it.
- A run with Inspector off still succeeds, with `enabled` false. A read that
  fails leaves out the values it feeds, with a gap.
