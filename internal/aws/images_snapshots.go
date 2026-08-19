package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// EBSSnapshot is an owned snapshot's encryption state.
type EBSSnapshot struct {
	SnapshotID string
	Encrypted  bool
	VolumeSize int32
}

// MachineImage is an owned AMI's exposure and encryption state. Public comes
// straight from DescribeImages, so no per-image attribute call is needed.
type MachineImage struct {
	ImageID    string
	Name       string
	Public     bool
	CreateDate string

	// HasUnencryptedVolume is stated as the finding rather than as an
	// "encrypted" flag, because an instance-store image has no EBS device at
	// all and calling that encrypted would overstate it.
	HasUnencryptedVolume bool
}

// ListOwnedSnapshots returns snapshots this account owns.
//
// The owner filter is not optional. DescribeSnapshots without one returns every
// publicly restorable snapshot in AWS, which is millions of rows belonging to
// strangers.
func (c *AWSClient) ListOwnedSnapshots(ctx context.Context, region string) ([]EBSSnapshot, error) {
	return c.describeSnapshots(ctx, region, nil)
}

// ListPublicOwnedSnapshots returns the subset of this account's snapshots that
// anyone can restore. Restorable by "all" is how AWS expresses public, and
// pairing it with the owner filter answers the exposure question in one call
// rather than a DescribeSnapshotAttribute per snapshot.
func (c *AWSClient) ListPublicOwnedSnapshots(ctx context.Context, region string) ([]EBSSnapshot, error) {
	return c.describeSnapshots(ctx, region, []string{"all"})
}

func (c *AWSClient) describeSnapshots(ctx context.Context, region string, restorableBy []string) ([]EBSSnapshot, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeSnapshotsInput{OwnerIds: []string{"self"}}
	if len(restorableBy) > 0 {
		input.RestorableByUserIds = restorableBy
	}

	var snapshots []EBSSnapshot
	paginator := ec2.NewDescribeSnapshotsPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing EBS snapshots in %s: %w", region, err)
		}
		for _, s := range page.Snapshots {
			snapshots = append(snapshots, EBSSnapshot{
				SnapshotID: aws.ToString(s.SnapshotId),
				Encrypted:  aws.ToBool(s.Encrypted),
				VolumeSize: aws.ToInt32(s.VolumeSize),
			})
		}
	}
	return snapshots, nil
}

// ListOwnedImages returns AMIs this account owns, with exposure and encryption.
// An image is treated as encrypted only when every EBS block device is.
func (c *AWSClient) ListOwnedImages(ctx context.Context, region string) ([]MachineImage, error) {
	cfg := c.cfg.Copy()
	cfg.Region = region
	client := ec2.NewFromConfig(cfg)

	var images []MachineImage
	paginator := ec2.NewDescribeImagesPaginator(client, &ec2.DescribeImagesInput{
		Owners: []string{"self"},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing AMIs in %s: %w", region, err)
		}
		for _, img := range page.Images {
			images = append(images, MachineImage{
				ImageID:              aws.ToString(img.ImageId),
				Name:                 aws.ToString(img.Name),
				Public:               aws.ToBool(img.Public),
				HasUnencryptedVolume: hasUnencryptedBlockDevice(img),
				CreateDate:           aws.ToString(img.CreationDate),
			})
		}
	}
	return images, nil
}

// hasUnencryptedBlockDevice reports whether any EBS device on the image is
// unencrypted. An image with no EBS devices contributes nothing either way.
func hasUnencryptedBlockDevice(img types.Image) bool {
	for _, mapping := range img.BlockDeviceMappings {
		if mapping.Ebs == nil {
			continue
		}
		if !aws.ToBool(mapping.Ebs.Encrypted) {
			return true
		}
	}
	return false
}
