package collector

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// collectEC2Metrics collects EC2 posture for a single region. Issues three
// calls per region: DescribeInstances (always), DescribeVolumes (for encryption
// join), and ListVPCs (for default-VPC classification). All three are cheap
// paginated calls. A failure on volumes or VPCs leaves out only the values
// that read would have given; instance rows are still emitted.
func (c *Collector) collectEC2Metrics(ctx context.Context, client *aws.AWSClient, region, accountID string, level componentsdk.Level) (*EC2Metrics, error) {
	instances, err := client.ListEC2Instances(ctx, region)
	if err != nil {
		return nil, err
	}

	out := &EC2Metrics{}

	volumes, volumesErr := client.ListEC2Volumes(ctx, region)
	if volumesErr != nil {
		c.warn("account %s region %s: failed to list EC2 volumes: %v", accountID, region, volumesErr)
		volumes = map[string]aws.EBSVolumeState{}
		out.missing.add(volumesErr, "instances_with_unencrypted_volume_count", "unattached_volume_count", "unattached_unencrypted_volume_count")
	}

	defaultVPCByID, vpcErr := defaultVPCLookup(ctx, client, region)
	if vpcErr != nil {
		c.warn("account %s region %s: failed to list VPCs for EC2 enrichment: %v", accountID, region, vpcErr)
		defaultVPCByID = map[string]bool{}
		out.missing.add(vpcErr, "default_vpc_count")
	}

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

	out.Instances = make([]EC2InstanceRow, 0, len(instances))
	for _, inst := range instances {
		rootEncrypted, rootErr := rootVolumeEncryption(inst, volumes, volumesErr)
		row := ec2InstanceToRow(inst, region, defaultVPCByID[inst.VPCID], rootEncrypted, level)
		row.missing.add(vpcErr, "in_default_vpc")
		row.missing.add(rootErr, "root_volume_encrypted")
		out.Instances = append(out.Instances, row)
	}
	return out, nil
}

// errRootVolumeUnlisted is why root_volume_encrypted is left out when
// DescribeVolumes does not list an instance's root volume.
var errRootVolumeUnlisted = componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("DescribeVolumes does not list the instance's root volume"))

// rootVolumeEncryption reads whether inst's EBS root volume is encrypted from
// volumes, the region's volumes, which volumesErr says could not be listed.
// It is nil with no error for an instance whose root device is not an EBS
// volume.
func rootVolumeEncryption(inst aws.EC2Instance, volumes map[string]aws.EBSVolumeState, volumesErr error) (*bool, error) {
	if inst.RootVolumeID == "" {
		return nil, nil
	}
	if volumesErr != nil {
		return nil, volumesErr
	}
	state, ok := volumes[inst.RootVolumeID]
	if !ok {
		return nil, errRootVolumeUnlisted
	}
	return &state.Encrypted, nil
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
// at EC2InstanceTagsCap, as truncateTags keeps them.
func ec2InstanceToRow(inst aws.EC2Instance, region string, inDefaultVPC bool, rootVolumeEncrypted *bool, level componentsdk.Level) EC2InstanceRow {
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

// truncateTags keeps at most cap of a resource's tags. Tags with the aws:
// prefix do not count against AWS's limit of 50, so a resource can carry
// more than 50. Past the cap, the resource's own tags are kept before aws:
// tags, each in key order, so the same tags are kept on every collection.
func truncateTags(in map[string]string, cap int) map[string]string {
	if len(in) <= cap {
		out := make(map[string]string, len(in))
		for k, v := range in {
			out[k] = v
		}
		return out
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int {
		if aSystem, bSystem := strings.HasPrefix(a, "aws:"), strings.HasPrefix(b, "aws:"); aSystem != bSystem {
			if aSystem {
				return 1
			}
			return -1
		}
		return strings.Compare(a, b)
	})
	out := make(map[string]string, cap)
	for _, k := range keys[:cap] {
		out[k] = in[k]
	}
	return out
}

// mergeEC2Metrics combines per-region results into a fleet-wide metric block.
// Trust aggregates sum directly; instance rows concatenate. The cap is applied
// by the caller after all regions have been merged.
func mergeEC2Metrics(a, b EC2Metrics) EC2Metrics {
	merged := EC2Metrics{
		InstanceCount:                       a.InstanceCount + b.InstanceCount,
		IMDSv2RequiredCount:                 a.IMDSv2RequiredCount + b.IMDSv2RequiredCount,
		PublicIPCount:                       a.PublicIPCount + b.PublicIPCount,
		DefaultVPCCount:                     a.DefaultVPCCount + b.DefaultVPCCount,
		InstancesWithUnencryptedVolumeCount: a.InstancesWithUnencryptedVolumeCount + b.InstancesWithUnencryptedVolumeCount,
		UnattachedVolumeCount:               a.UnattachedVolumeCount + b.UnattachedVolumeCount,
		UnattachedUnencryptedVolumeCount:    a.UnattachedUnencryptedVolumeCount + b.UnattachedUnencryptedVolumeCount,
		Instances:                           append(append([]EC2InstanceRow(nil), a.Instances...), b.Instances...),
		missing:                             a.missing,
	}
	merged.missing.merge(b.missing)
	return merged
}
