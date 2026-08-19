package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// ListEC2Instances returns running and stopped EC2 instances in the given
// region. Filtered to exclude terminated instances (they're transient AWS
// bookkeeping rows that don't reflect ongoing posture).
func (c *AWSClient) ListEC2Instances(ctx context.Context, region string) ([]EC2Instance, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := ec2.NewFromConfig(cfg)

	var instances []EC2Instance
	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing ec2 instances in %s: %w", region, err)
		}
		for _, res := range out.Reservations {
			for _, inst := range res.Instances {
				state := ""
				if inst.State != nil {
					state = string(inst.State.Name)
				}
				if state == "terminated" {
					continue
				}
				instances = append(instances, projectEC2Instance(inst, state))
			}
		}
	}
	return instances, nil
}

func projectEC2Instance(inst ec2types.Instance, state string) EC2Instance {
	row := EC2Instance{
		InstanceID:   aws.ToString(inst.InstanceId),
		InstanceType: string(inst.InstanceType),
		State:        state,
		LaunchTime:   inst.LaunchTime,
		ImageID:      aws.ToString(inst.ImageId),
		VPCID:        aws.ToString(inst.VpcId),
		SubnetID:     aws.ToString(inst.SubnetId),
		KeyName:      aws.ToString(inst.KeyName),
	}
	if ip := aws.ToString(inst.PublicIpAddress); ip != "" {
		row.HasPublicIP = true
		row.PublicIP = ip
	}
	if inst.MetadataOptions != nil {
		row.HTTPTokens = string(inst.MetadataOptions.HttpTokens)
		row.HTTPHopLimit = int(aws.ToInt32(inst.MetadataOptions.HttpPutResponseHopLimit))
	}
	if inst.IamInstanceProfile != nil {
		row.IAMInstanceProfileARN = aws.ToString(inst.IamInstanceProfile.Arn)
	}
	for _, sg := range inst.SecurityGroups {
		row.SecurityGroupIDs = append(row.SecurityGroupIDs, aws.ToString(sg.GroupId))
	}
	rootDevice := aws.ToString(inst.RootDeviceName)
	for _, m := range inst.BlockDeviceMappings {
		if m.Ebs == nil {
			continue
		}
		volID := aws.ToString(m.Ebs.VolumeId)
		row.AttachedVolumeIDs = append(row.AttachedVolumeIDs, volID)
		if aws.ToString(m.DeviceName) == rootDevice {
			row.RootVolumeID = volID
		}
	}
	if len(inst.Tags) > 0 {
		row.Tags = make(map[string]string, len(inst.Tags))
		for _, t := range inst.Tags {
			row.Tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
	}
	return row
}

// ListEC2Volumes returns a volumeID→encrypted map for every EBS volume in the
// region. The encryption flag is the only volume attribute we surface; full
// Volume objects aren't needed and would significantly bloat memory in
// volume-heavy regions; two booleans per volume keeps that property.
func (c *AWSClient) ListEC2Volumes(ctx context.Context, region string) (map[string]EBSVolumeState, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := ec2.NewFromConfig(cfg)

	out := map[string]EBSVolumeState{}
	paginator := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing ec2 volumes in %s: %w", region, err)
		}
		for _, v := range page.Volumes {
			out[aws.ToString(v.VolumeId)] = EBSVolumeState{
				Encrypted: aws.ToBool(v.Encrypted),
				Attached:  len(v.Attachments) > 0,
			}
		}
	}
	return out, nil
}
