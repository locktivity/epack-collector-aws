package collector

import (
	"context"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// collectStoredImageMetrics collects owned EBS snapshots and AMIs for a region.
//
// Three paginated calls, no per-resource fan-out: snapshots, snapshots that are
// publicly restorable, and images. Public exposure comes from DescribeImages
// directly and from the restorable-by-all snapshot query, so neither
// DescribeSnapshotAttribute nor DescribeImageAttribute is needed.
func (c *Collector) collectStoredImageMetrics(ctx context.Context, client *aws.AWSClient, region, accountID string, level componentsdk.Level) (*StoredImageMetrics, error) {
	snapshots, err := client.ListOwnedSnapshots(ctx, region)
	if err != nil {
		return nil, err
	}

	out := &StoredImageMetrics{SnapshotCount: len(snapshots)}
	for _, s := range snapshots {
		if !s.Encrypted {
			out.UnencryptedSnapshotCount++
		}
	}

	audit := level.AtLeast(componentsdk.LevelAudit)
	public, err := client.ListPublicOwnedSnapshots(ctx, region)
	if err != nil {
		// The exposure question is the sharper one, so a failure here must not
		// be readable as "nothing is public".
		c.warn("account %s region %s: failed to check snapshot public exposure: %v", accountID, region, err)
		out.SnapshotExposureUnknown = true
		out.missing.add(err, "public_snapshot_count")
		if audit {
			out.missing.add(err, "public_snapshots")
		}
	} else {
		out.PublicSnapshotCount = len(public)
	}

	images, err := client.ListOwnedImages(ctx, region)
	if err != nil {
		c.warn("account %s region %s: failed to collect AMIs: %v", accountID, region, err)
		out.ImageExposureUnknown = true
		out.missing.add(err, "image_count", "images_with_unencrypted_volume_count", "public_image_count")
		if audit {
			out.missing.add(err, "public_images")
		}
		images = nil
	}

	out.ImageCount = len(images)
	for _, img := range images {
		if img.Public {
			out.PublicImageCount++
		}
		if img.HasUnencryptedVolume {
			out.ImagesWithUnencryptedVolumeCount++
		}
	}

	if !audit {
		return out, nil
	}

	// Only the exposed resources get rows. A public snapshot or AMI is
	// actionable and rare; the full inventory is neither.
	out.PublicSnapshots = []PublicResourceRow{}
	out.PublicImages = []PublicResourceRow{}
	for _, s := range public {
		out.PublicSnapshots = append(out.PublicSnapshots, PublicResourceRow{ID: s.SnapshotID, Region: region, Encrypted: s.Encrypted})
	}
	for _, img := range images {
		if !img.Public {
			continue
		}
		out.PublicImages = append(out.PublicImages, PublicResourceRow{
			ID: img.ImageID, Name: img.Name, Region: region, Encrypted: !img.HasUnencryptedVolume, CreatedAt: img.CreateDate,
		})
	}
	return out, nil
}

// mergeStoredImageMetrics combines per-region results. Unknown flags OR: one
// region failing leaves the account's exposure unproven.
func mergeStoredImageMetrics(a, b StoredImageMetrics) StoredImageMetrics {
	merged := StoredImageMetrics{
		SnapshotCount:                    a.SnapshotCount + b.SnapshotCount,
		UnencryptedSnapshotCount:         a.UnencryptedSnapshotCount + b.UnencryptedSnapshotCount,
		PublicSnapshotCount:              a.PublicSnapshotCount + b.PublicSnapshotCount,
		SnapshotExposureUnknown:          a.SnapshotExposureUnknown || b.SnapshotExposureUnknown,
		ImageCount:                       a.ImageCount + b.ImageCount,
		ImagesWithUnencryptedVolumeCount: a.ImagesWithUnencryptedVolumeCount + b.ImagesWithUnencryptedVolumeCount,
		PublicImageCount:                 a.PublicImageCount + b.PublicImageCount,
		ImageExposureUnknown:             a.ImageExposureUnknown || b.ImageExposureUnknown,
		PublicSnapshots:                  appendRows(a.PublicSnapshots, b.PublicSnapshots),
		PublicImages:                     appendRows(a.PublicImages, b.PublicImages),
		missing:                          a.missing,
	}
	merged.missing.merge(b.missing)
	return merged
}
