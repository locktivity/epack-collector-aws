package collector

import (
	"cmp"
	"context"
	"errors"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// networkMetricsWithCounts is used internally to track counts for weighted averaging across regions.
type networkMetricsWithCounts struct {
	NetworkMetrics
	vpcCount           int
	securityGroupCount int
	openSSH            int
	openRDP            int
}

// finalize computes the exposure percentages from the merged counts, nil
// when there are no security groups.
func (m *networkMetricsWithCounts) finalize() {
	m.SecurityGroupCount = m.securityGroupCount
	m.OpenToWorldSSH = pctOf(m.openSSH, m.securityGroupCount)
	m.OpenToWorldSSHSecurityGroupCount = m.openSSH
	m.OpenToWorldRDP = pctOf(m.openRDP, m.securityGroupCount)
	m.OpenToWorldRDPSecurityGroupCount = m.openRDP
}

// collectNetworkMetrics collects network security metrics for a single region.
//
// At trust, only aggregate exposure percentages are populated. At audit,
// per-VPC and per-SG summary rows are surfaced. Flow log status is internal-only.
func (c *Collector) collectNetworkMetrics(ctx context.Context, client *aws.AWSClient, region string, accountID string, level componentsdk.Level) (*networkMetricsWithCounts, error) {
	result := &networkMetricsWithCounts{}

	// Collect VPC metrics
	if err := c.collectVPCMetrics(ctx, client, region, accountID, result, level); err != nil {
		return result, err
	}

	// Collect security group metrics
	if err := c.collectSecurityGroupMetrics(ctx, client, region, result, level); err != nil {
		return result, err
	}

	return result, nil
}

// collectVPCMetrics collects VPC-related metrics.
func (c *Collector) collectVPCMetrics(ctx context.Context, client *aws.AWSClient, region string, accountID string, result *networkMetricsWithCounts, level componentsdk.Level) error {
	includeFlowLogs := level.AtLeast(componentsdk.LevelInternal)
	vpcs, err := client.ListVPCs(ctx, region, includeFlowLogs)
	var flowLogsErr error
	if err != nil {
		var unavailable *aws.FlowLogsUnavailableError
		if !errors.As(err, &unavailable) {
			return err
		}
		flowLogsErr = err
		c.warn("account %s region %s: failed to collect VPC flow log status: %v", accountID, region, err)
	}

	result.vpcCount = len(vpcs)

	if level.AtLeast(componentsdk.LevelAudit) {
		rows := vpcSummaries(vpcs, region, accountID, includeFlowLogs)
		for i := range rows {
			rows[i].missing.add(flowLogsErr, "flow_logs_enabled")
		}
		result.VPCs = append(make([]VPCSummary, 0, len(rows)), rows...)
	}

	return nil
}

// vpcSummaries projects the VPCs onto their rows. A VPC another account owns
// and shares with this one is marked shared, and its flow logs are not
// evaluated, since a participant cannot describe them.
func vpcSummaries(vpcs []aws.VPC, region, accountID string, includeFlowLogs bool) []VPCSummary {
	rows := make([]VPCSummary, 0, len(vpcs))
	for _, vpc := range vpcs {
		row := VPCSummary{
			VPCID:     vpc.VPCID,
			Region:    region,
			IsDefault: vpc.IsDefault,
			Shared:    vpc.OwnerID != "" && accountID != "" && vpc.OwnerID != accountID,
		}
		switch {
		case !includeFlowLogs:
		case row.Shared:
			row.FlowLogsEvaluated = boolPtr(false)
		default:
			row.FlowLogsEvaluated = boolPtr(vpc.FlowLogsEvaluated)
			row.FlowLogsErrorCode = vpc.FlowLogsErrorCode
			if vpc.FlowLogsEvaluated {
				row.FlowLogsEnabled = boolPtr(vpc.FlowLogsEnabled)
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// collectSecurityGroupMetrics collects security group metrics.
func (c *Collector) collectSecurityGroupMetrics(ctx context.Context, client *aws.AWSClient, region string, result *networkMetricsWithCounts, level componentsdk.Level) error {
	sgs, err := client.ListSecurityGroups(ctx, region)
	if err != nil {
		return err
	}

	result.securityGroupCount = len(sgs)

	lists := c.readExposurePrefixLists(ctx, client, region, sgs)
	stats := analyzeSecurityGroups(sgs, lists)
	result.openSSH = stats.openSSH
	result.openRDP = stats.openRDP
	result.missing.addPartial(stats.sshErr, stats.sshUnknown, "open_to_world_ssh", "open_to_world_ssh_security_group_count")
	result.missing.addPartial(stats.rdpErr, stats.rdpUnknown, "open_to_world_rdp", "open_to_world_rdp_security_group_count")

	if level.AtLeast(componentsdk.LevelAudit) {
		result.SecurityGroups = make([]SecurityGroupSummary, 0, len(sgs))
		for _, sg := range sgs {
			exposure := analyzeSecurityGroupExposure(sg, lists)
			row := SecurityGroupSummary{
				GroupID:        sg.GroupID,
				GroupName:      sg.GroupName,
				Region:         region,
				VPCID:          sg.VPCID,
				IsDefault:      sg.IsDefault,
				OpenToWorldSSH: exposure.hasOpenSSH,
				OpenToWorldRDP: exposure.hasOpenRDP,
			}
			row.missing.add(exposure.sshErr, "open_to_world_ssh")
			row.missing.add(exposure.rdpErr, "open_to_world_rdp")
			if level.AtLeast(componentsdk.LevelInternal) {
				row.IngressRules = sgIngressRulesToInternal(sg.IngressRules)
			}
			result.SecurityGroups = append(result.SecurityGroups, row)
		}
	}

	return nil
}

// sgIngressRulesToInternal projects per-SG ingress rules onto the internal-level
// emission. CIDR, source-SG and prefix-list ingress are surfaced. A rule with
// none of them set (degenerate config) still gets a row, so the absence of
// allowed sources is visible.
func sgIngressRulesToInternal(in []aws.SecurityGroupRule) []SGIngressRule {
	if len(in) == 0 {
		return nil
	}
	out := make([]SGIngressRule, 0, len(in))
	for _, r := range in {
		row := SGIngressRule{
			Protocol: r.Protocol,
			FromPort: r.FromPort,
			ToPort:   r.ToPort,
		}
		if len(r.CIDRBlocks) > 0 {
			row.CIDRBlocks = append([]string(nil), r.CIDRBlocks...)
		}
		if len(r.SourceSGIDs) > 0 {
			row.SourceSGIDs = append([]string(nil), r.SourceSGIDs...)
		}
		if len(r.PrefixListIDs) > 0 {
			row.PrefixListIDs = append([]string(nil), r.PrefixListIDs...)
		}
		out = append(out, row)
	}
	return out
}

// prefixListRead is a managed prefix list's CIDR blocks, or why they could
// not be read.
type prefixListRead struct {
	cidrs []string
	err   error
}

// readExposurePrefixLists reads the entries of each managed prefix list that
// a rule covering SSH or RDP allows. A rule whose source is a prefix list
// allows every CIDR block in it.
func (c *Collector) readExposurePrefixLists(ctx context.Context, client *aws.AWSClient, region string, sgs []aws.SecurityGroup) map[string]prefixListRead {
	lists := map[string]prefixListRead{}
	for _, sg := range sgs {
		for _, rule := range sg.IngressRules {
			if !rule.IsSSH() && !rule.IsRDP() {
				continue
			}
			for _, id := range rule.PrefixListIDs {
				if _, seen := lists[id]; seen {
					continue
				}
				cidrs, err := client.GetManagedPrefixListCIDRs(ctx, region, id)
				if err != nil {
					c.warn("region %s: failed to read prefix list %s, so it is unknown whether the security groups that allow it are open to the world: %v", region, id, err)
				}
				lists[id] = prefixListRead{cidrs: cidrs, err: err}
			}
		}
	}
	return lists
}

// sgStats holds security group analysis results. sshUnknown and rdpUnknown
// count the groups whose exposure depends on a prefix list that could not be
// read, and sshErr and rdpErr say why.
type sgStats struct {
	openSSH    int
	openRDP    int
	sshUnknown int
	rdpUnknown int
	sshErr     error
	rdpErr     error
}

// analyzeSecurityGroups analyzes all security groups and returns statistics.
func analyzeSecurityGroups(sgs []aws.SecurityGroup, lists map[string]prefixListRead) sgStats {
	var stats sgStats

	for _, sg := range sgs {
		exposure := analyzeSecurityGroupExposure(sg, lists)

		if exposure.hasOpenSSH {
			stats.openSSH++
		}
		if exposure.hasOpenRDP {
			stats.openRDP++
		}
		if exposure.sshErr != nil {
			stats.sshUnknown++
			stats.sshErr = cmp.Or(stats.sshErr, exposure.sshErr)
		}
		if exposure.rdpErr != nil {
			stats.rdpUnknown++
			stats.rdpErr = cmp.Or(stats.rdpErr, exposure.rdpErr)
		}
	}

	return stats
}

// sgExposure represents what a security group exposes to the world. sshErr
// and rdpErr are set when the group is not known to be open and a rule
// covering the port allows a prefix list that could not be read.
type sgExposure struct {
	hasOpenSSH bool
	hasOpenRDP bool
	sshErr     error
	rdpErr     error
}

// analyzeSecurityGroupExposure checks what a single security group exposes.
// A rule is open to the world when its own CIDR blocks, or those of a prefix
// list it allows, include 0.0.0.0/0 or ::/0.
func analyzeSecurityGroupExposure(sg aws.SecurityGroup, lists map[string]prefixListRead) sgExposure {
	var exposure sgExposure

	for _, rule := range sg.IngressRules {
		open, err := ruleOpenToWorld(rule, lists)
		if rule.IsSSH() {
			exposure.hasOpenSSH = exposure.hasOpenSSH || open
			exposure.sshErr = cmp.Or(exposure.sshErr, err)
		}
		if rule.IsRDP() {
			exposure.hasOpenRDP = exposure.hasOpenRDP || open
			exposure.rdpErr = cmp.Or(exposure.rdpErr, err)
		}
	}
	if exposure.hasOpenSSH {
		exposure.sshErr = nil
	}
	if exposure.hasOpenRDP {
		exposure.rdpErr = nil
	}

	return exposure
}

// ruleOpenToWorld reports whether a rule allows traffic from anywhere. When
// it is not known to, err is why a prefix list it allows could not be read.
func ruleOpenToWorld(rule aws.SecurityGroupRule, lists map[string]prefixListRead) (bool, error) {
	if rule.IsOpenToWorld() {
		return true, nil
	}
	var err error
	for _, id := range rule.PrefixListIDs {
		list := lists[id]
		if aws.AnyWorldCIDR(list.cidrs) {
			return true, nil
		}
		err = cmp.Or(err, list.err)
	}
	return false, err
}

// mergeNetworkMetrics merges network metrics from multiple regions.
//
// Trust-level exposure aggregates are weighted-averaged across regions;
// audit-level per-VPC and per-SG inventories are concatenated.
func mergeNetworkMetrics(a, b networkMetricsWithCounts) networkMetricsWithCounts {
	result := a
	result.vpcCount += b.vpcCount
	result.securityGroupCount += b.securityGroupCount
	result.openSSH += b.openSSH
	result.openRDP += b.openRDP
	result.VPCs = appendRows(result.VPCs, b.VPCs)
	result.SecurityGroups = appendRows(result.SecurityGroups, b.SecurityGroups)
	result.missing.merge(b.missing)
	return result
}

func boolPtr(v bool) *bool {
	return &v
}
