package collector

import (
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// A failed exposure check must never merge into an account-level "nothing is
// public", so the unknown flag propagates while the counts still sum.
func TestMergeStoredImageMetricsPropagatesUnknownExposure(t *testing.T) {
	clean := StoredImageMetrics{SnapshotCount: 4, PublicSnapshotCount: 0, ImageCount: 2}
	failed := StoredImageMetrics{SnapshotCount: 1, SnapshotExposureUnknown: true}

	got := mergeStoredImageMetrics(clean, failed)

	if got.SnapshotCount != 5 {
		t.Errorf("SnapshotCount = %d, want 5", got.SnapshotCount)
	}
	if !got.SnapshotExposureUnknown {
		t.Error("SnapshotExposureUnknown = false, want true when any region failed")
	}
	if got.ImageExposureUnknown {
		t.Error("ImageExposureUnknown = true, want false when no image lookup failed")
	}
}

func TestMergeStoredImageMetricsConcatenatesExposedRows(t *testing.T) {
	a := StoredImageMetrics{
		PublicSnapshotCount: 1,
		PublicSnapshots:     []PublicResourceRow{{ID: "snap-1", Region: "us-east-1"}},
	}
	b := StoredImageMetrics{
		PublicImageCount: 1,
		PublicImages:     []PublicResourceRow{{ID: "ami-1", Region: "eu-west-1", Name: "base"}},
	}

	got := mergeStoredImageMetrics(a, b)

	if len(got.PublicSnapshots) != 1 || len(got.PublicImages) != 1 {
		t.Fatalf("rows = %d snapshots and %d images, want 1 each", len(got.PublicSnapshots), len(got.PublicImages))
	}
	if got.PublicSnapshotCount != 1 || got.PublicImageCount != 1 {
		t.Errorf("counts = %d and %d, want 1 each", got.PublicSnapshotCount, got.PublicImageCount)
	}
}

// A disabled AMI is still owned, and DescribeImages returns it only when the
// request sets IncludeDisabled, which the collector does.
func TestCollectStoredImages_DisabledAMIsAreOwned(t *testing.T) {
	live := "<item><imageId>ami-0live</imageId><name>live</name><isPublic>false</isPublic><imageState>available</imageState><creationDate>2025-12-01T00:00:00.000Z</creationDate>" +
		"<blockDeviceMapping><item><deviceName>/dev/xvda</deviceName><ebs><snapshotId>snap-0kit</snapshotId><encrypted>true</encrypted><volumeSize>8</volumeSize></ebs></item></blockDeviceMapping></item>"
	disabled := "<item><imageId>ami-0off</imageId><name>retired</name><isPublic>false</isPublic><imageState>disabled</imageState><creationDate>2024-01-01T00:00:00.000Z</creationDate>" +
		"<blockDeviceMapping><item><deviceName>/dev/xvda</deviceName><ebs><snapshotId>snap-0old</snapshotId><encrypted>false</encrypted><volumeSize>8</volumeSize></ebs></item></blockDeviceMapping></item>"
	responses := append([]collectortest.Response{
		ec2ItemResponse("aws.ec2.DescribeImages", map[string]string{"Owner.1": "self", "IncludeDisabled": "true"}, "<imagesSet>"+live+disabled+"</imagesSet>"),
		ec2ItemResponse("aws.ec2.DescribeImages", map[string]string{"Owner.1": "self"}, "<imagesSet>"+live+"</imagesSet>"),
	}, kitResponses()...)
	doc := runDetailed(t, responses)
	expectValues(t, doc, map[string]any{
		"/accounts/0/stored_images/image_count":                          2,
		"/accounts/0/stored_images/images_with_unencrypted_volume_count": 1,
	})
}

// ebsImage is a DescribeImages item for an AMI backed by one EBS volume.
func ebsImage(id, state, public, encrypted string) string {
	return "<item><imageId>" + id + "</imageId><name>" + id + "</name><isPublic>" + public + "</isPublic><imageState>" + state + "</imageState>" +
		"<rootDeviceType>ebs</rootDeviceType><creationDate>2025-12-01T00:00:00.000Z</creationDate>" +
		"<blockDeviceMapping><item><deviceName>/dev/xvda</deviceName><ebs><snapshotId>snap-0" + id + "</snapshotId><encrypted>" + encrypted +
		"</encrypted><volumeSize>8</volumeSize></ebs></item></blockDeviceMapping></item>"
}

func runWithImages(t *testing.T, items ...string) any {
	t.Helper()
	return runDetailed(t, replaceResponses(kitResponses(),
		ec2Response("aws.ec2.DescribeImages", "<imagesSet>"+strings.Join(items, "")+"</imagesSet>")))
}

// An instance-store AMI has no EBS volume, so its public row has no encrypted
// value. The row of a public AMI with an unencrypted volume has encrypted
// false.
func TestCollectStoredImages_PublicImageEncryption(t *testing.T) {
	const store = "<item><imageId>ami-0store</imageId><name>ami-0store</name><isPublic>true</isPublic><imageState>available</imageState>" +
		"<rootDeviceType>instance-store</rootDeviceType><creationDate>2020-01-01T00:00:00.000Z</creationDate><blockDeviceMapping/></item>"
	doc := runWithImages(t, store)
	expectValues(t, doc, map[string]any{
		"/accounts/0/stored_images/public_image_count":                   1,
		"/accounts/0/stored_images/images_with_unencrypted_volume_count": 0,
		"/accounts/0/stored_images/public_images/0/id":                   "ami-0store",
		"/accounts/0/stored_images/public_images/0/encrypted":            nil,
	})

	doc = runWithImages(t, ebsImage("ami-0ebs", "available", "true", "false"))
	expectValues(t, doc, map[string]any{
		"/accounts/0/stored_images/public_images/0/id":        "ami-0ebs",
		"/accounts/0/stored_images/public_images/0/encrypted": false,
	})
}

// DescribeImages still returns an AMI for a short time after it is
// deregistered. Nobody can launch it, so it is not an owned image. A
// disabled AMI is still owned.
func TestCollectStoredImages_DeregisteredAMIsAreNotOwned(t *testing.T) {
	doc := runWithImages(t,
		ebsImage("ami-0live", "available", "false", "true"),
		ebsImage("ami-0gone", "deregistered", "true", "false"),
		ebsImage("ami-0off", "disabled", "true", "false"),
	)
	expectValues(t, doc, map[string]any{
		"/accounts/0/stored_images/image_count":                          2,
		"/accounts/0/stored_images/public_image_count":                   1,
		"/accounts/0/stored_images/images_with_unencrypted_volume_count": 1,
		"/accounts/0/stored_images/public_images/0/id":                   "ami-0off",
		"/accounts/0/stored_images/public_images/1":                      nil,
	})
}
