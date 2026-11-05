package collector

import (
	"net/http"
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

func TestAnalyzeSecurityGroupExposure(t *testing.T) {
	sg := aws.SecurityGroup{
		IngressRules: []aws.SecurityGroupRule{
			{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRBlocks: []string{"0.0.0.0/0"}},
			{Protocol: "tcp", FromPort: 3389, ToPort: 3389, CIDRBlocks: []string{"::/0"}},
			{Protocol: "tcp", FromPort: 80, ToPort: 80, CIDRBlocks: []string{"10.0.0.0/8"}},
		},
	}

	got := analyzeSecurityGroupExposure(sg, nil)
	if !got.hasOpenSSH {
		t.Fatalf("expected hasOpenSSH=true")
	}
	if !got.hasOpenRDP {
		t.Fatalf("expected hasOpenRDP=true")
	}
}

// A rule for all traffic (protocol -1) names no ports, so open to the world
// it exposes SSH and RDP alike.
func TestAnalyzeSecurityGroupExposure_AllTrafficOpenToWorld(t *testing.T) {
	open := aws.SecurityGroup{IngressRules: []aws.SecurityGroupRule{{Protocol: "-1", CIDRBlocks: []string{"::/0"}}}}
	if got := analyzeSecurityGroupExposure(open, nil); !got.hasOpenSSH || !got.hasOpenRDP {
		t.Fatalf("all traffic from ::/0: exposure = %+v, want SSH and RDP open", got)
	}

	internal := aws.SecurityGroup{IngressRules: []aws.SecurityGroupRule{{Protocol: "-1", CIDRBlocks: []string{"10.0.0.0/8"}}}}
	if got := analyzeSecurityGroupExposure(internal, nil); got.hasOpenSSH || got.hasOpenRDP {
		t.Fatalf("all traffic from 10.0.0.0/8: exposure = %+v, want neither open", got)
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

	stats := analyzeSecurityGroups(sgs, nil)
	if stats.openSSH != 1 {
		t.Fatalf("expected openSSH=1, got %d", stats.openSSH)
	}
	if stats.openRDP != 1 {
		t.Fatalf("expected openRDP=1, got %d", stats.openRDP)
	}
}

func TestMergeNetworkMetrics(t *testing.T) {
	a := networkMetricsWithCounts{
		vpcCount:           2,
		securityGroupCount: 2,
		openSSH:            1,
		openRDP:            2,
	}
	b := networkMetricsWithCounts{
		vpcCount:           2,
		securityGroupCount: 2,
	}

	got := mergeNetworkMetrics(a, b)
	got.finalize()
	if !pctIs(got.OpenToWorldSSH, 25) {
		t.Fatalf("expected OpenToWorldSSH=25, got %s", showPct(got.OpenToWorldSSH))
	}
	if !pctIs(got.OpenToWorldRDP, 50) {
		t.Fatalf("expected OpenToWorldRDP=50, got %s", showPct(got.OpenToWorldRDP))
	}
	if got.SecurityGroupCount != 4 {
		t.Fatalf("expected SecurityGroupCount=4, got %d", got.SecurityGroupCount)
	}
	if got.vpcCount != 4 {
		t.Fatalf("expected vpcCount=4, got %d", got.vpcCount)
	}
	if got.securityGroupCount != 4 {
		t.Fatalf("expected securityGroupCount=4, got %d", got.securityGroupCount)
	}

	// No security groups anywhere is no population, not 0% exposed.
	empty := networkMetricsWithCounts{}
	empty.finalize()
	if empty.OpenToWorldSSH != nil || empty.OpenToWorldRDP != nil {
		t.Fatalf("expected null exposure with no security groups, got %s and %s", showPct(empty.OpenToWorldSSH), showPct(empty.OpenToWorldRDP))
	}
}

func TestVPCSummaries_AuditOmitsFlowLogs(t *testing.T) {
	rows := vpcSummaries([]aws.VPC{
		{VPCID: "vpc-1", IsDefault: true, FlowLogsEnabled: true},
	}, "us-east-1", "111122223333", false)

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
	}, "us-east-1", "111122223333", true)

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
	}, "us-east-1", "111122223333", true)

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

// A participant cannot describe the flow logs of a VPC another account shares
// with it, so that VPC's flow logs are not evaluated.
func TestVPCSummaries_SharedVPCFlowLogsAreNotEvaluated(t *testing.T) {
	rows := vpcSummaries([]aws.VPC{
		{VPCID: "vpc-own", OwnerID: "111122223333", FlowLogsEvaluated: true},
		{VPCID: "vpc-shared", OwnerID: "999988887777", FlowLogsEvaluated: true},
	}, "us-east-1", "111122223333", true)

	if rows[0].Shared || rows[0].FlowLogsEnabled == nil || *rows[0].FlowLogsEnabled {
		t.Errorf("owned VPC with no flow log: shared = %v, flow_logs_enabled = %v, want false and false", rows[0].Shared, rows[0].FlowLogsEnabled)
	}
	if !rows[1].Shared || rows[1].FlowLogsEnabled != nil || rows[1].FlowLogsEvaluated == nil || *rows[1].FlowLogsEvaluated {
		t.Errorf("shared VPC: shared = %v, flow_logs_enabled = %v, flow_logs_evaluated = %v, want true, absent and false",
			rows[1].Shared, rows[1].FlowLogsEnabled, rows[1].FlowLogsEvaluated)
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

// A flow log whose delivery failed publishes nothing, so a VPC whose only flow
// log fails to deliver has no traffic captured.
func TestCollectVPCMetrics_FailedFlowLogDoesNotCapture(t *testing.T) {
	flowLog := func(status string) string {
		return "<flowLogSet><item><flowLogId>fl-1</flowLogId><resourceId>vpc-0kit</resourceId><flowLogStatus>ACTIVE</flowLogStatus>" +
			"<trafficType>ALL</trafficType><logDestinationType>cloud-watch-logs</logDestinationType><deliverLogsStatus>" + status +
			"</deliverLogsStatus></item></flowLogSet>"
	}
	for status, want := range map[string]bool{"SUCCESS": true, "FAILED": false} {
		t.Run(status, func(t *testing.T) {
			out := runOutput(t, replaceResponses(kitResponses(), ec2Response("aws.ec2.DescribeFlowLogs", flowLog(status))))
			var row *VPCSummary
			for i, v := range out.Accounts[0].Network.VPCs {
				if v.VPCID == "vpc-0kit" {
					row = &out.Accounts[0].Network.VPCs[i]
				}
			}
			if row == nil || row.FlowLogsEnabled == nil || *row.FlowLogsEnabled != want {
				t.Errorf("flow_logs_enabled = %+v, want %v", row, want)
			}
		})
	}
}

// sgReachableFromWeb is the kit's database group, which the RDS read asks
// for by ID.
const sgReachableFromWeb = "<item><groupId>sg-0db</groupId><groupName>database</groupName><groupDescription>database</groupDescription><vpcId>vpc-0kit</vpcId><ipPermissions>" +
	"<item><ipProtocol>tcp</ipProtocol><fromPort>5432</fromPort><toPort>5432</toPort><groups><item><groupId>sg-0web</groupId></item></groups></item>" +
	"</ipPermissions></item>"

// sshFromPrefixList is an ingress rule allowing SSH from the prefix list
// pl-0ssh.
const sshFromPrefixList = "<item><ipProtocol>tcp</ipProtocol><fromPort>22</fromPort><toPort>22</toPort>" +
	"<prefixListIds><item><prefixListId>pl-0ssh</prefixListId></item></prefixListIds></item>"

// runWithPrefixListGroup runs the kit with the region's security groups being
// the database group and sg-0ssh, whose one rule allows SSH from pl-0ssh.
// entries answers the read of the list's entries. The replay answers with the
// first response a call matches, so these come before the kit's own.
func runWithPrefixListGroup(t *testing.T, entries collectortest.Response) (componentsdk.InProcessResult, Output) {
	t.Helper()
	group := "<item><groupId>sg-0ssh</groupId><groupName>ssh</groupName><groupDescription>ssh</groupDescription><vpcId>vpc-0kit</vpcId>" +
		"<ipPermissions>" + sshFromPrefixList + "</ipPermissions></item>"
	responses := []collectortest.Response{
		ec2Response("aws.ec2.DescribeSecurityGroups", "<securityGroupInfo>"+sgReachableFromWeb+group+"</securityGroupInfo>"),
		entries,
	}
	return runWithGaps(t, kitConfig(), append(responses, kitResponses()...))
}

func prefixListEntries(cidrs ...string) collectortest.Response {
	entries := ""
	for _, c := range cidrs {
		entries += "<item><cidr>" + c + "</cidr></item>"
	}
	return ec2Response("aws.ec2.GetManagedPrefixListEntries", "<entrySet>"+entries+"</entrySet>")
}

func securityGroupNamed(t *testing.T, out Output, id string) SecurityGroupSummary {
	t.Helper()
	for _, sg := range out.Accounts[0].Network.SecurityGroups {
		if sg.GroupID == id {
			return sg
		}
	}
	t.Fatalf("no security group %s in %+v", id, out.Accounts[0].Network.SecurityGroups)
	return SecurityGroupSummary{}
}

// A rule whose source is a managed prefix list allows every CIDR block in the
// list, so a list holding 0.0.0.0/0 opens SSH to the world.
func TestCollectNetworkMetrics_PrefixListSourceOpenToWorld(t *testing.T) {
	for _, tc := range []struct {
		name string
		cidr string
		open bool
	}{
		{"list holding the world", "0.0.0.0/0", true},
		{"list holding a private range", "10.0.0.0/8", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, out := runWithPrefixListGroup(t, prefixListEntries(tc.cidr))
			network := out.Accounts[0].Network
			want := 0
			if tc.open {
				want = 1
			}
			if network.OpenToWorldSSHSecurityGroupCount != want {
				t.Errorf("open_to_world_ssh_security_group_count = %d, want %d", network.OpenToWorldSSHSecurityGroupCount, want)
			}
			row := securityGroupNamed(t, out, "sg-0ssh")
			if row.OpenToWorldSSH != tc.open {
				t.Errorf("sg-0ssh open_to_world_ssh = %v, want %v", row.OpenToWorldSSH, tc.open)
			}
			if len(row.IngressRules) != 1 || len(row.IngressRules[0].PrefixListIDs) != 1 || row.IngressRules[0].PrefixListIDs[0] != "pl-0ssh" {
				t.Errorf("sg-0ssh ingress rules = %+v, want one naming pl-0ssh", row.IngressRules)
			}
		})
	}
}

// When the list's entries cannot be read, whether the group is open is
// unknown, so the group's flag and the SSH counts are left out.
func TestCollectNetworkMetrics_UnreadPrefixListLeavesExposureOut(t *testing.T) {
	denied := ec2Response("aws.ec2.GetManagedPrefixListEntries", "")
	denied.Status = http.StatusForbidden
	denied.Body = `<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>You are not authorized to perform this operation.</Message></Error></Errors><RequestID>kit</RequestID></Response>`
	res, _ := runWithPrefixListGroup(t, denied)
	for _, pointer := range []string{
		"/accounts/0/network/open_to_world_ssh_security_group_count",
		"/accounts/0/network/open_to_world_ssh",
	} {
		if gapAt(res, awsPath, pointer) == nil {
			t.Errorf("no gap at %s", pointer)
		}
	}
	if gapAt(res, awsPath, "/accounts/0/network/open_to_world_rdp") != nil {
		t.Errorf("gap at open_to_world_rdp, want the RDP count kept: the rule covers only SSH")
	}
}
