package collector

import (
	"context"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// collectEC2Metrics collects EC2 posture for a single region. Issues three
// calls per region: DescribeInstances (always), DescribeVolumes (for encryption
// join), and ListVPCs (for default-VPC classification). All three are cheap
// paginated calls. Failures on volumes or VPCs degrade gracefully — we still
// emit instance rows with the affected fields left at zero values.
func (c *Collector) collectEC2Metrics(ctx context.Context, client *aws.AWSClient, region, accountID string, level componentsdk.Level) (*EC2Metrics, error) {
	instances, err := client.ListEC2Instances(ctx, region)
	if err != nil {
		return nil, err
	}

	volumes, err := client.ListEC2Volumes(ctx, region)
	if err != nil {
		c.warn("account %s region %s: failed to list EC2 volumes: %v", accountID, region, err)
		volumes = map[string]aws.EBSVolumeState{}
	}

	defaultVPCByID, err := defaultVPCLookup(ctx, client, region)
	if err != nil {
		c.warn("account %s region %s: failed to list VPCs for EC2 enrichment: %v", accountID, region, err)
		defaultVPCByID = map[string]bool{}
	}

	out := &EC2Metrics{}
	out.UnattachedVolumeCount, out.UnattachedUnencryptedVolumeCount = countUnattachedVolumes(volumes)
	for _, inst := range instances {
		if inst.State != "running" {
			continue
		}
		out.InstanceCount++
		if inst.HTTPTokens == IMDSHTTPTokensRequired {
			out.IMDSv2RequiredCount++
		}
		if inst.HasPublicIP {
			out.PublicIPCount++
		}
		if defaultVPCByID[inst.VPCID] {
			out.DefaultVPCCount++
		}
		if instanceHasUnencryptedVolume(inst, volumes) {
			out.InstancesWithUnencryptedVolumeCount++
		}
	}

	if !level.AtLeast(componentsdk.LevelAudit) {
		return out, nil
	}

	for _, inst := range instances {
		out.Instances = append(out.Instances, ec2InstanceToRow(inst, region, defaultVPCByID[inst.VPCID], volumes[inst.RootVolumeID].Encrypted, level))
	}
	return out, nil
}

func defaultVPCLookup(ctx context.Context, client *aws.AWSClient, region string) (map[string]bool, error) {
	vpcs, err := client.ListVPCs(ctx, region, false)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(vpcs))
	for _, v := range vpcs {
		if v.IsDefault {
			out[v.VPCID] = true
		}
	}
	return out, nil
}

func instanceHasUnencryptedVolume(inst aws.EC2Instance, volumes map[string]aws.EBSVolumeState) bool {
	for _, volID := range inst.AttachedVolumeIDs {
		if state, known := volumes[volID]; known && !state.Encrypted {
			return true
		}
	}
	return false
}

// countUnattachedVolumes reports volumes attached to nothing, and how many of
// those are unencrypted. Detached volumes keep their data and are invisible to
// the instance join, so they are where forgotten unencrypted data accumulates.
func countUnattachedVolumes(volumes map[string]aws.EBSVolumeState) (total, unencrypted int) {
	for _, state := range volumes {
		if state.Attached {
			continue
		}
		total++
		if !state.Encrypted {
			unencrypted++
		}
	}
	return total, unencrypted
}

// ec2InstanceToRow projects an aws.EC2Instance onto its audit-level row.
// Internal-level fields (iam_instance_profile_arn / key_name / tags /
// attached_volume_ids) are populated when level >= internal. Tags are capped
// at EC2InstanceTagsCap with stable insertion order — past the cap, tags are
// silently dropped (we have no useful sort key for tag entries).
func ec2InstanceToRow(inst aws.EC2Instance, region string, inDefaultVPC, rootVolumeEncrypted bool, level componentsdk.Level) EC2InstanceRow {
	row := EC2InstanceRow{
		InstanceID:          inst.InstanceID,
		Region:              region,
		InstanceType:        inst.InstanceType,
		State:               inst.State,
		ImageID:             inst.ImageID,
		VPCID:               inst.VPCID,
		SubnetID:            inst.SubnetID,
		InDefaultVPC:        inDefaultVPC,
		HasPublicIP:         inst.HasPublicIP,
		PublicIP:            inst.PublicIP,
		HTTPTokens:          inst.HTTPTokens,
		HTTPHopLimit:        inst.HTTPHopLimit,
		RootVolumeEncrypted: rootVolumeEncrypted,
	}
	if inst.LaunchTime != nil {
		row.LaunchTime = inst.LaunchTime.UTC().Format(time.RFC3339)
	}
	if len(inst.SecurityGroupIDs) > 0 {
		row.SecurityGroupIDs = append([]string(nil), inst.SecurityGroupIDs...)
	}
	if level.AtLeast(componentsdk.LevelInternal) {
		row.IAMInstanceProfileARN = inst.IAMInstanceProfileARN
		row.KeyName = inst.KeyName
		if len(inst.AttachedVolumeIDs) > 0 {
			row.AttachedVolumeIDs = append([]string(nil), inst.AttachedVolumeIDs...)
		}
		if len(inst.Tags) > 0 {
			row.Tags = truncateTags(inst.Tags, EC2InstanceTagsCap)
		}
	}
	return row
}

func truncateTags(in map[string]string, cap int) map[string]string {
	if len(in) <= cap {
		out := make(map[string]string, len(in))
		for k, v := range in {
			out[k] = v
		}
		return out
	}
	out := make(map[string]string, cap)
	i := 0
	for k, v := range in {
		if i >= cap {
			break
		}
		out[k] = v
		i++
	}
	return out
}

// mergeEC2Metrics combines per-region results into a fleet-wide metric block.
// Trust aggregates sum directly; instance rows concatenate. The cap is applied
// by the caller after all regions have been merged.
func mergeEC2Metrics(a, b EC2Metrics) EC2Metrics {
	return EC2Metrics{
		InstanceCount:                       a.InstanceCount + b.InstanceCount,
		IMDSv2RequiredCount:                 a.IMDSv2RequiredCount + b.IMDSv2RequiredCount,
		PublicIPCount:                       a.PublicIPCount + b.PublicIPCount,
		DefaultVPCCount:                     a.DefaultVPCCount + b.DefaultVPCCount,
		InstancesWithUnencryptedVolumeCount: a.InstancesWithUnencryptedVolumeCount + b.InstancesWithUnencryptedVolumeCount,
		Instances:                           append(append([]EC2InstanceRow(nil), a.Instances...), b.Instances...),
	}
}
