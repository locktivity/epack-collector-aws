# Collection Levels

The AWS collector accepts an optional `level` config knob controlling how
much detail it gathers. There are three levels, and they are cumulative:
`internal` is a strict superset of `audit`, which is a strict superset of
`trust`. No level removes a field that a lower level produced.

## The three levels

| Level | Question it answers | What's in the artifact |
|---|---|---|
| `trust` (default) | Do they pass? | Aggregates and pass/fail flags only. No names of users, resources, or findings. |
| `audit` | Where is the gap? | Per-resource rows with identifying names and configuration detail. No per-user activity. |
| `internal` | Who or what specifically? | Per-user activity, finding payloads, key ARNs, recent audit-log events. |

## Configuration

Set the level in your epack.yaml under the collector's `config` block:

```yaml
collectors:
  aws:
    source: locktivity/epack-collector-aws@^1
    config:
      level: audit
      role_arn: arn:aws:iam::123456789012:role/EpackCollectorRole
      regions:
        - us-east-1
        - us-west-2
```

Default is `trust` when the key is absent or empty. Unrecognized values
(typos, future levels we don't know about) downgrade to `trust` with a
stderr warning. The collector never silently upgrades to a higher level.

The active level appears in the output artifact as the top-level
`collected_at_level` field.

## What each level adds, per surface

### IAM (`iam`)

- **trust**: `iam_users_present`, MFA / hardware-MFA / access-key-rotation
  percentages, literal root MFA state, root credential-presence flags, root
  access protection, and centralized root access feature evidence when the
  caller is the Organizations management account or delegated administrator.
- **audit**: `users[]` (per-user MFA + access-key + console flags),
  `roles[]` (per-role ARN, external-trust flag, wildcard-principal flag,
  the foreign principal account IDs, and a best-effort
  `external_trust_in_org` determination backed by the
  `organization_accounts_evaluated` marker).
- **internal**: `credential_report` (full per-user activity from the IAM
  credential report: last-used dates, key rotation dates, password state);
  `roles[].trust_policy_json` (the decoded trust policy document verbatim).

### S3 (`s3`)

- **trust**: bucket count; per-bucket aggregate percentages for public access
  blocked after applying account-level S3 Block Public Access, evaluated
  default encryption, versioning, logging; account-level public-access-block
  flag; public-access-block unknown count; default-encryption evaluated,
  inferred, and unknown counts; log sink bucket count. The `logging_enabled`
  percentage excludes server access log destination buckets from the
  denominator (they don't need their own logging).
- **audit**: `buckets[]` per-bucket row (the same data the percentages were
  computed from, plus region and `is_log_sink` flag). `default_encryption_enabled`
  is `null` when the bucket's encryption setting could not be evaluated. A
  `default_encryption_error_code` value records either the collection gap or a
  documented-baseline inference.
- **internal**: per-bucket gains `policy`, `acl`, `lifecycle` sub-objects
  fetched via per-bucket API calls.

### RDS (`rds`)

- **trust**: aggregate percentages for encryption, public accessibility,
  deletion protection, backup retention adequacy, Multi-AZ.
- **audit**: `instances[]` and `clusters[]` per-resource rows.
- **internal**: rows gain `latest_restorable_time` (point-in-time recovery
  target).

### Network (`network`)

- **trust**: aggregate percentages for SSH/RDP open-to-world.
- **audit**: `vpcs[]`, `security_groups[]` per-resource rows.
- **internal**: VPC rows gain flow-log provenance: `flow_logs_evaluated`,
  `flow_logs_enabled` when evaluated, and `flow_logs_error_code` when the
  status read failed. SG rows gain per-rule `ingress_rules[]` with CIDR
  blocks and source-SG references.

### Account Security (`account_security`)

Top-level booleans for each service (CloudTrail / Config / GuardDuty /
Security Hub / Inspector) at trust; per-resource inventories at audit;
per-rule / per-finding detail at internal.

- **CloudTrail**: trust includes trail-status evaluated / inferred / unknown
  counts. Organization shadow trails whose status read is blocked are counted
  as inferred coverage and tagged in `trails[]` at audit. `trails[]` is deduped
  by trail ARN and carries KMS, log-validation, organization-trail, and
  trail-status provenance flags; `kms_key_arn` + `cloudwatch_logs_arn` per
  trail land at internal.
- **Config**: `recorders[]` at audit; `rules[]` per-rule compliance state at
  internal.
- **GuardDuty**: `detectors[]` per-region at audit; `findings[]` per
  unarchived high-or-critical finding at internal.
- **Security Hub**: enabled-standards inventory + integration count at audit.
- **Inspector**: raw finding + resource counts at audit.

### IAM Identity Center (`identity_center`)

- **trust**: enabled flag, instance metadata, user / group / permission-set counts.
- **audit**: the full access model. `users[]` (id, login, display name,
  primary email; identity-system inventories are audit-level evidence, and no
  PII beyond the primary email is collected), `groups[]` with
  `member_user_ids`, `permission_sets[]` (name, session duration,
  managed-policy count, provisioned account IDs), and `account_assignments[]`
  (principal to permission set to account edges, meaningful only when
  `assignments_evaluated` is true, capped with truncation companions).
  Joining these reconstructs who can access which account with which
  permission set, entirely within the pack.
- **internal**: permission-set rows gain `managed_policy_arns` and
  `has_inline_policy`.

### Lambda (`lambda`)

- **trust**: function count, deprecated-runtime count.
- **audit**: `functions[]` per-function row (runtime, memory, timeout,
  has-VPC, has-function-URL with auth type, has-resource-policy,
  deprecated-runtime flag), plus `public_function_url_count` aggregate.
- **internal**: rows gain `arn`, `role_arn`, `kms_key_arn`, `layer_arns[]`,
  `architectures[]`, `package_type`, `env_var_names[]` (KEYS ONLY; values
  are never collected).

### EC2 (`ec2`)

- **trust**: aggregate counts for running instances, IMDSv2-required,
  public IPs, default-VPC residency, instances with at-least-one-unencrypted-volume.
- **audit**: `instances[]` per-instance row (type, state, launch time,
  image, VPC + subnet, in-default-VPC flag, public IP, IMDS config,
  security groups, root volume encrypted).
- **internal**: rows gain `iam_instance_profile_arn`, `key_name`, `tags`
  (capped at 50 per instance), `attached_volume_ids[]`.

### CloudWatch Logs (`cloudwatch_logs`)

- **trust**: log group count, count of groups without a retention policy,
  count using AWS-managed (vs customer-managed) KMS encryption.
- **audit**: `log_groups[]` per-group row (retention, stored bytes,
  creation time, has-customer-KMS).
- **internal**: rows gain `arn` and `kms_key_arn`.

### KMS (`kms`)

Scoped to CUSTOMER-managed keys only. AWS-managed keys offer no posture lever.

- **trust**: customer-managed key count, count of symmetric CMKs with
  rotation disabled, count pending deletion.
- **audit**: `keys[]` per-key row (state, usage, spec, origin, multi-region,
  creation/deletion dates, rotation flag, aliases).
- **internal**: rows gain `description`.

### Secrets Manager (`secrets_manager`)

Secret VALUES are never collected. Value-reading APIs are forbidden in
collector source by build-time lint.

- **trust**: secret count, count without auto-rotation, count without
  customer-managed KMS, count pending deletion.
- **audit**: `secrets[]` per-secret row (ARN, timestamps, rotation flag +
  period, has-customer-KMS, primary region, owning service).
- **internal**: rows gain `description` (borderline sensitive; customers
  occasionally embed context like "Stripe production"), `kms_key_arn`,
  `rotation_lambda_arn`, `tags`.

### SSM Parameter Store (`ssm_parameters`)

Parameter VALUES are never collected. Value-reading APIs are forbidden in
collector source by build-time lint.

- **trust**: parameter count, SecureString count, count of SecureStrings
  without customer-managed KMS.
- **audit**: `parameters[]` per-parameter row (type, data type, version,
  tier, last-modified date + user, has-customer-KMS).
- **internal**: rows gain `description` and `kms_key_arn`.

### WAF (`waf`)

- **trust**: web ACL count, coverage of internet-facing entry points
  (`internet_facing_alb_coverage_pct` over internet-facing application load
  balancers, `distribution_coverage_pct` over enabled CloudFront
  distributions), and `rate_limiting_enforced`: whether any web ACL with an
  attached resource has an active blocking rate-based rule.
  `regions_evaluated_count` and `cloudfront_scope_evaluated` record which
  scopes were actually read.
- **audit**: `web_acls[]` per-ACL rows: name, scope, region, default action,
  attached resource count, logging state, and per-rule detail (action, rate
  limit and aggregate key for rate-based rules, managed rule group names).
- **internal**: rows gain `arn`, `associated_resource_arns[]`, and
  `logging_destination_arn`, identifying the exact resources each web ACL is
  attached to.

## Artifact contract: null vs `[]` vs `[...]`

Level-gated array fields in the artifact follow a strict contract that lets
consumers read fields without consulting `collected_at_level`:

- **`null`**: the field was NOT collected at the active level. (Trust-only
  collection emits `null` for every audit / internal field.)
- **`[]`**: the field WAS collected; the fleet is empty.
- **`[...]`**: the field was collected and has rows.

The same contract applies to internal-level pointer fields like
`iam.credential_report`: `null` when not collected, a populated object
(possibly with an empty inner `users` array) when collected.

### Per-resource scalar fields use a different contract

Single-value optional fields on a per-resource row (for example,
`kms_key_arn` on a Lambda function, or `description` on a Secrets Manager
secret) use the standard JSON `omitempty` convention: the field is omitted
from the artifact when the underlying resource doesn't have that
attribute. This is **per-resource nullability**, not **per-level gating**,
and the surrounding array's presence already tells you the row was
collected.

## Truncation

Several inventories impose per-surface caps (e.g., 10,000 S3 buckets,
5,000 KMS keys) to keep artifact size bounded for very large estates.
When a cap is hit, the inventory carries two companion fields:

- `<inventory>_truncated`: `true` when the cap was applied.
- `<inventory>_dropped_count`: how many rows were dropped.

A diagnostic warning is also emitted at the top-level `diagnostics.warnings`.
Each surface defines its own truncation sort key so the most posture-relevant
rows survive (e.g., Lambda functions sort by `last_modified` DESC; KMS keys
by `creation_date` DESC; GuardDuty findings by severity DESC).

## Privacy and storage at higher levels

Some risks worth flagging when running at `internal`:

- **Internal-level packs contain identifying data** (user lists, group
  rosters, admin usernames, secret descriptions, IAM key references). Treat
  the resulting artifacts as you would treat any cloud-inventory export.
- **Downgrades leave stale data.** If you collect at `internal` Monday and
  switch to `trust` Tuesday, Monday's artifact still contains internal
  data. There is no automatic purge of historical packs.
- **Large estates at internal level can exceed default timeouts.** For
  accounts with thousands of resources, set a longer `--timeout` in
  epack.yaml.
