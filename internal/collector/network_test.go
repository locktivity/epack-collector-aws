package collector

import (
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

func TestAnalyzeSecurityGroupExposure(t *testing.T) {
	sg := aws.SecurityGroup{
		IngressRules: []aws.SecurityGroupRule{
			{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRBlocks: []string{"0.0.0.0/0"}},
			{Protocol: "tcp", FromPort: 3389, ToPort: 3389, CIDRBlocks: []string{"::/0"}},
			{Protocol: "tcp", FromPort: 80, ToPort: 80, CIDRBlocks: []string{"10.0.0.0/8"}},
		},
	}

	got := analyzeSecurityGroupExposure(sg)
	if !got.hasOpenSSH {
		t.Fatalf("expected hasOpenSSH=true")
	}
	if !got.hasOpenRDP {
		t.Fatalf("expected hasOpenRDP=true")
	}
}

func TestAnalyzeSecurityGroups(t *testing.T) {
	sgs := []aws.SecurityGroup{
		{
			IngressRules: []aws.SecurityGroupRule{
				{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRBlocks: []string{"0.0.0.0/0"}},
			},
		},
		{
			IngressRules: []aws.SecurityGroupRule{
				{Protocol: "tcp", FromPort: 3389, ToPort: 3389, CIDRBlocks: []string{"0.0.0.0/0"}},
			},
		},
		{
			IngressRules: []aws.SecurityGroupRule{
				{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRBlocks: []string{"10.0.0.0/8"}},
			},
		},
	}

	stats := analyzeSecurityGroups(sgs)
	if stats.openSSH != 1 {
		t.Fatalf("expected openSSH=1, got %d", stats.openSSH)
	}
	if stats.openRDP != 1 {
		t.Fatalf("expected openRDP=1, got %d", stats.openRDP)
	}
}

func TestWeightedAverage(t *testing.T) {
	if got := weightedAverage(50, 2, 100, 2); got != 75 {
		t.Fatalf("expected 75, got %d", got)
	}
	if got := weightedAverage(1, 0, 99, 0); got != 0 {
		t.Fatalf("expected 0 for zero total weight, got %d", got)
	}
}

func TestMergeNetworkMetrics(t *testing.T) {
	a := networkMetricsWithCounts{
		NetworkMetrics: NetworkMetrics{
			OpenToWorldSSH: 50,
			OpenToWorldRDP: 100,
		},
		vpcCount:           2,
		securityGroupCount: 2,
	}
	b := networkMetricsWithCounts{
		NetworkMetrics: NetworkMetrics{
			OpenToWorldSSH: 0,
			OpenToWorldRDP: 0,
		},
		vpcCount:           2,
		securityGroupCount: 2,
	}

	got := mergeNetworkMetrics(a, b)
	if got.OpenToWorldSSH != 25 {
		t.Fatalf("expected OpenToWorldSSH=25, got %d", got.OpenToWorldSSH)
	}
	if got.OpenToWorldRDP != 50 {
		t.Fatalf("expected OpenToWorldRDP=50, got %d", got.OpenToWorldRDP)
	}
	if got.vpcCount != 4 {
		t.Fatalf("expected vpcCount=4, got %d", got.vpcCount)
	}
	if got.securityGroupCount != 4 {
		t.Fatalf("expected securityGroupCount=4, got %d", got.securityGroupCount)
	}
}

func TestVPCSummaries_AuditOmitsFlowLogs(t *testing.T) {
	rows := vpcSummaries([]aws.VPC{
		{VPCID: "vpc-1", IsDefault: true, FlowLogsEnabled: true},
	}, "us-east-1", false)

	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].FlowLogsEnabled != nil {
		t.Fatalf("expected audit row to omit FlowLogsEnabled, got %+v", rows[0].FlowLogsEnabled)
	}
}

func TestVPCSummaries_InternalIncludesFlowLogsFalse(t *testing.T) {
	rows := vpcSummaries([]aws.VPC{
		{VPCID: "vpc-1", FlowLogsEnabled: false, FlowLogsEvaluated: true},
		{VPCID: "vpc-2", FlowLogsEnabled: true, FlowLogsEvaluated: true},
	}, "us-east-1", true)

	if rows[0].FlowLogsEnabled == nil || *rows[0].FlowLogsEnabled {
		t.Fatalf("expected internal row to include FlowLogsEnabled=false, got %+v", rows[0].FlowLogsEnabled)
	}
	if rows[0].FlowLogsEvaluated == nil || *rows[0].FlowLogsEvaluated != true {
		t.Fatalf("expected internal row to include FlowLogsEvaluated=true, got %+v", rows[0].FlowLogsEvaluated)
	}
	if rows[1].FlowLogsEnabled == nil || !*rows[1].FlowLogsEnabled {
		t.Fatalf("expected internal row to include FlowLogsEnabled=true, got %+v", rows[1].FlowLogsEnabled)
	}
}

func TestVPCSummaries_InternalSurfacesUnevaluatedFlowLogs(t *testing.T) {
	rows := vpcSummaries([]aws.VPC{
		{VPCID: "vpc-1", FlowLogsEvaluated: false, FlowLogsErrorCode: "UnauthorizedOperation"},
	}, "us-east-1", true)

	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].FlowLogsEnabled != nil {
		t.Fatalf("expected unevaluated flow logs to omit FlowLogsEnabled, got %+v", rows[0].FlowLogsEnabled)
	}
	if rows[0].FlowLogsEvaluated == nil || *rows[0].FlowLogsEvaluated {
		t.Fatalf("expected FlowLogsEvaluated=false, got %+v", rows[0].FlowLogsEvaluated)
	}
	if rows[0].FlowLogsErrorCode != "UnauthorizedOperation" {
		t.Fatalf("expected UnauthorizedOperation error code, got %q", rows[0].FlowLogsErrorCode)
	}
}

func TestMergeNetworkMetrics_ConcatenatesAuditInventories(t *testing.T) {
	a := networkMetricsWithCounts{
		NetworkMetrics: NetworkMetrics{
			VPCs:           []VPCSummary{{VPCID: "vpc-east", Region: "us-east-1"}},
			SecurityGroups: []SecurityGroupSummary{{GroupID: "sg-east-1", Region: "us-east-1"}},
		},
		vpcCount:           1,
		securityGroupCount: 1,
	}
	b := networkMetricsWithCounts{
		NetworkMetrics: NetworkMetrics{
			VPCs: []VPCSummary{
				{VPCID: "vpc-west-1", Region: "us-west-2"},
				{VPCID: "vpc-west-2", Region: "us-west-2"},
			},
			SecurityGroups: []SecurityGroupSummary{
				{GroupID: "sg-west-1", Region: "us-west-2"},
				{GroupID: "sg-west-2", Region: "us-west-2"},
				{GroupID: "sg-west-3", Region: "us-west-2"},
			},
		},
		vpcCount:           2,
		securityGroupCount: 3,
	}

	got := mergeNetworkMetrics(a, b)
	if len(got.VPCs) != 3 {
		t.Fatalf("expected 3 VPCs after merge, got %d", len(got.VPCs))
	}
	if len(got.SecurityGroups) != 4 {
		t.Fatalf("expected 4 SGs after merge, got %d", len(got.SecurityGroups))
	}
	if got.VPCs[0].VPCID != "vpc-east" || got.VPCs[1].VPCID != "vpc-west-1" {
		t.Errorf("merge did not preserve insertion order: %+v", got.VPCs)
	}
}

func TestMergeNetworkMetrics_EmptyAuditSlicesStayEmpty(t *testing.T) {
	a := networkMetricsWithCounts{vpcCount: 3}
	b := networkMetricsWithCounts{vpcCount: 2}

	got := mergeNetworkMetrics(a, b)
	if len(got.VPCs) != 0 || len(got.SecurityGroups) != 0 {
		t.Errorf("trust-only merge should not populate audit slices, got VPCs=%+v SGs=%+v", got.VPCs, got.SecurityGroups)
	}
}

func TestSGIngressRulesToInternal_ProjectsAllFields(t *testing.T) {
	in := []aws.SecurityGroupRule{
		{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRBlocks: []string{"0.0.0.0/0"}},
		{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRBlocks: []string{"10.0.0.0/8", "192.168.0.0/16"}},
		{Protocol: "-1", FromPort: 0, ToPort: 0, CIDRBlocks: nil}, // all-protocols rule with no CIDR (source-SG only — surfaces with empty CIDRs)
	}
	out := sgIngressRulesToInternal(in)
	if len(out) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(out))
	}
	if out[0].Protocol != "tcp" || out[0].FromPort != 22 || len(out[0].CIDRBlocks) != 1 {
		t.Errorf("rule 0 mis-projected: %+v", out[0])
	}
	if len(out[1].CIDRBlocks) != 2 || out[1].CIDRBlocks[0] != "10.0.0.0/8" {
		t.Errorf("rule 1 CIDRs mis-projected: %+v", out[1].CIDRBlocks)
	}
	if out[2].Protocol != "-1" || len(out[2].CIDRBlocks) != 0 {
		t.Errorf("rule 2 (all-protocols, no CIDR) mis-projected: %+v", out[2])
	}
}

func TestSGIngressRulesToInternal_NilInputReturnsNil(t *testing.T) {
	if out := sgIngressRulesToInternal(nil); out != nil {
		t.Errorf("expected nil for nil input (omitempty drops the field), got %v", out)
	}
}

func TestSGIngressRulesToInternal_DefensiveCopyCIDRs(t *testing.T) {
	// Mutating the input slice's CIDRBlocks after projection must not affect
	// the projected output (defensive copy via append(nil, ...)).
	cidrs := []string{"10.0.0.0/8"}
	in := []aws.SecurityGroupRule{{Protocol: "tcp", FromPort: 80, ToPort: 80, CIDRBlocks: cidrs}}
	out := sgIngressRulesToInternal(in)
	cidrs[0] = "MUTATED"
	if out[0].CIDRBlocks[0] != "10.0.0.0/8" {
		t.Errorf("projected CIDRs aliased input slice; got %q after mutation", out[0].CIDRBlocks[0])
	}
}

func TestSGIngressRulesToInternal_SurfacesSourceSGIDs(t *testing.T) {
	in := []aws.SecurityGroupRule{
		{Protocol: "-1", FromPort: 0, ToPort: 0, SourceSGIDs: []string{"sg-aaa", "sg-bbb"}},
		{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRBlocks: []string{"10.0.0.0/8"}, SourceSGIDs: []string{"sg-ccc"}},
	}
	out := sgIngressRulesToInternal(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(out))
	}
	if len(out[0].SourceSGIDs) != 2 || out[0].SourceSGIDs[0] != "sg-aaa" {
		t.Errorf("rule 0 SourceSGIDs mis-projected: %+v", out[0].SourceSGIDs)
	}
	if len(out[0].CIDRBlocks) != 0 {
		t.Errorf("rule 0 should have no CIDRBlocks (source-SG-only rule), got %v", out[0].CIDRBlocks)
	}
	if len(out[1].SourceSGIDs) != 1 || len(out[1].CIDRBlocks) != 1 {
		t.Errorf("rule 1 should have both CIDRs and SourceSGIDs, got %+v", out[1])
	}
}
