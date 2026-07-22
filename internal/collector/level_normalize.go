package collector

import "github.com/locktivity/epack/componentsdk"

// normalizeForLevel ensures every level-gated array is non-nil when collecting
// at that level. The per-region collectors and merge functions are intentionally
// nil-preserving (so trust-level output emits `null` for audit fields rather
// than misleading empty arrays); this pass flips nil→[] for audit/internal-level
// fields when those levels are active.
//
// The contract this enforces:
//   - At trust level, audit/internal fields emit as `null` ("not collected").
//   - At audit level, audit fields emit as `[]` ("collected, no rows") or
//     `[...]` ("collected, some rows"). Internal fields still emit `null`.
//   - At internal level, both audit and internal fields emit as `[]` or `[...]`.
//
// Consumers can therefore tell "field not collected at my level" (null) from
// "field collected, fleet is empty" ([]) without needing to read collected_at_level.
func normalizeForLevel(p *AccountPosture, level componentsdk.Level) {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return
	}

	if p.IAM.Users == nil {
		p.IAM.Users = []IAMUser{}
	}
	if p.IAM.Roles == nil {
		p.IAM.Roles = []IAMRole{}
	}
	if p.S3.Buckets == nil {
		p.S3.Buckets = []S3Bucket{}
	}
	if p.RDS.Instances == nil {
		p.RDS.Instances = []RDSInstance{}
	}
	if p.RDS.Clusters == nil {
		p.RDS.Clusters = []RDSCluster{}
	}
	if p.Network.VPCs == nil {
		p.Network.VPCs = []VPCSummary{}
	}
	if p.Network.SecurityGroups == nil {
		p.Network.SecurityGroups = []SecurityGroupSummary{}
	}
	if p.AccountSecurity.CloudTrail.Trails == nil {
		p.AccountSecurity.CloudTrail.Trails = []CloudTrailTrail{}
	}
	if p.AccountSecurity.Config.Recorders == nil {
		p.AccountSecurity.Config.Recorders = []ConfigRecorderRow{}
	}
	if p.AccountSecurity.GuardDuty.Detectors == nil {
		p.AccountSecurity.GuardDuty.Detectors = []GuardDutyDetectorRow{}
	}
	if p.AccountSecurity.SecurityHub.StandardsARNs == nil {
		p.AccountSecurity.SecurityHub.StandardsARNs = []string{}
	}
	if p.AccountSecurity.SecurityHub.ProductSubscriptions == nil {
		p.AccountSecurity.SecurityHub.ProductSubscriptions = []string{}
	}
	if p.IdentityCenter.PermissionSets == nil {
		p.IdentityCenter.PermissionSets = []IdentityCenterPermissionSetRow{}
	}
	if p.IdentityCenter.Users == nil {
		p.IdentityCenter.Users = []IdentityCenterUserRow{}
	}
	if p.IdentityCenter.Groups == nil {
		p.IdentityCenter.Groups = []IdentityCenterGroupRow{}
	}
	if p.IdentityCenter.AccountAssignments == nil {
		p.IdentityCenter.AccountAssignments = []IdentityCenterAssignmentRow{}
	}
	if p.Lambda.Functions == nil {
		p.Lambda.Functions = []LambdaFunctionRow{}
	}
	if p.EC2.Instances == nil {
		p.EC2.Instances = []EC2InstanceRow{}
	}
	if p.CloudWatchLogs.LogGroups == nil {
		p.CloudWatchLogs.LogGroups = []CloudWatchLogGroupRow{}
	}
	if p.KMS.Keys == nil {
		p.KMS.Keys = []KMSKeyRow{}
	}
	if p.SecretsManager.Secrets == nil {
		p.SecretsManager.Secrets = []SecretsManagerSecretRow{}
	}
	if p.SSMParameters.Parameters == nil {
		p.SSMParameters.Parameters = []SSMParameterRow{}
	}

	if !level.AtLeast(componentsdk.LevelInternal) {
		return
	}

	if p.IAM.CredentialReport == nil {
		p.IAM.CredentialReport = &IAMCredentialReport{Users: []IAMCredentialReportUser{}}
	}
	if p.AccountSecurity.Config.Rules == nil {
		p.AccountSecurity.Config.Rules = []ConfigRuleRow{}
	}
	if p.AccountSecurity.GuardDuty.Findings == nil {
		p.AccountSecurity.GuardDuty.Findings = []GuardDutyFindingRow{}
	}
}
