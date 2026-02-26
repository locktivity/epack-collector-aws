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
			OpenToWorldSSH:  50,
			OpenToWorldRDP:  100,
			FlowLogsEnabled: 100,
		},
		vpcCount:           2,
		securityGroupCount: 2,
	}
	b := networkMetricsWithCounts{
		NetworkMetrics: NetworkMetrics{
			OpenToWorldSSH:  0,
			OpenToWorldRDP:  0,
			FlowLogsEnabled: 0,
		},
		vpcCount:           2,
		securityGroupCount: 2,
	}

	got := mergeNetworkMetrics(a, b)
	if got.FlowLogsEnabled != 50 {
		t.Fatalf("expected FlowLogsEnabled=50, got %d", got.FlowLogsEnabled)
	}
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
