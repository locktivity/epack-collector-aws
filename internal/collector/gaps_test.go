package collector

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

func TestLeaveOutCoveredNullsEveryCoveredValue(t *testing.T) {
	gaps := newGapLog(&componentsdk.Recorder{})
	failed := errors.New("listing failed")
	gaps.leaveOut(failed, "/accounts/0/iam/mfa_enabled", "/accounts/0/s3/buckets/1/region", "/accounts/0/rds")
	gaps.leaveOut(nil, "/accounts/0/iam/iam_user_count")

	doc, err := gaps.leaveOutCovered(awsPath, map[string]any{"accounts": []any{map[string]any{
		"iam": map[string]any{"mfa_enabled": 0, "iam_user_count": 0},
		"s3":  map[string]any{"buckets": []any{map[string]any{"region": "us-east-1"}, map[string]any{"region": ""}}},
		"rds": map[string]any{"database_count": 0},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(doc)
	want := `{"accounts":[{"iam":{"iam_user_count":0,"mfa_enabled":null},"rds":null,"s3":{"buckets":[{"region":"us-east-1"},{"region":null}]}}]}`
	if string(got) != want {
		t.Errorf("leaveOutCovered() = %s, want %s", got, want)
	}
}

func TestNullAtLeavesAbsentValuesAbsent(t *testing.T) {
	doc := map[string]any{"iam": map[string]any{}}
	nullAt(doc, "/iam/users")
	nullAt(doc, "/s3/buckets/0")
	if _, present := doc["iam"].(map[string]any)["users"]; present {
		t.Error("nullAt added a value that was absent")
	}
	if _, present := doc["s3"]; present {
		t.Error("nullAt created a parent that was absent")
	}
}

func TestGapsCoverNestedValuesAndMirror(t *testing.T) {
	rec := &componentsdk.Recorder{}
	gaps := newGapLog(rec)
	failed := errors.New("regions unreadable")
	gaps.leaveOut(failed, "/accounts/0/network")

	if !gaps.covered("/accounts/0/network/open_to_world_ssh") {
		t.Error("a gap on a surface should cover the values inside it")
	}
	if gaps.covered("/accounts/0/networks") {
		t.Error("a gap should not cover a sibling whose name it prefixes")
	}
	if !gaps.mirror("/accounts/0/network/open_to_world_ssh", "/accounts/0/network/ssh_open_to_world_pct") {
		t.Fatal("mirror found no gap to copy")
	}
	var normalized []componentsdk.Gap
	for _, g := range rec.Gaps() {
		if g.Path == cloudPosturePath {
			normalized = append(normalized, g)
		}
	}
	if len(normalized) != 1 || normalized[0].Pointer != "/accounts/0/network/ssh_open_to_world_pct" || normalized[0].Detail != failed.Error() {
		t.Errorf("normalized gaps = %+v, want the network gap mirrored at the normalized pointer", normalized)
	}
	if gaps.mirror("/accounts/0/iam/mfa_enabled", "/accounts/0/iam/mfa_coverage_pct") {
		t.Error("mirror copied a gap that does not exist")
	}
}

func TestUnreadAddsUpUnmeasuredItems(t *testing.T) {
	var u unread
	first := errors.New("first")
	u.addPartial(first, 1, "versioning_enabled")
	u.addPartial(errors.New("second"), 2, "versioning_enabled")
	u.add(nil, "logging_enabled")

	if len(u.fields) != 1 {
		t.Fatalf("fields = %+v, want one: a nil error marks nothing", u.fields)
	}
	if f := u.fields[0]; f.unmeasured != 3 || f.err != first {
		t.Errorf("field = %+v, want 3 unmeasured with the first error", f)
	}
}
