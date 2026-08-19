package collector

import "testing"

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
