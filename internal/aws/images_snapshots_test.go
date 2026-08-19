package aws

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// An instance-store image has no EBS device, so it is neither a finding nor
// falsely reported as encrypted.
func TestHasUnencryptedBlockDevice(t *testing.T) {
	ebs := func(encrypted bool) types.BlockDeviceMapping {
		return types.BlockDeviceMapping{Ebs: &types.EbsBlockDevice{Encrypted: aws.Bool(encrypted)}}
	}

	tests := []struct {
		name string
		img  types.Image
		want bool
	}{
		{name: "no block devices at all", img: types.Image{}, want: false},
		{name: "every device encrypted", img: types.Image{BlockDeviceMappings: []types.BlockDeviceMapping{ebs(true), ebs(true)}}, want: false},
		{name: "one device unencrypted", img: types.Image{BlockDeviceMappings: []types.BlockDeviceMapping{ebs(true), ebs(false)}}, want: true},
		{name: "non-EBS mapping is ignored", img: types.Image{BlockDeviceMappings: []types.BlockDeviceMapping{{}}}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasUnencryptedBlockDevice(tt.img); got != tt.want {
				t.Fatalf("hasUnencryptedBlockDevice() = %v, want %v", got, tt.want)
			}
		})
	}
}
