package collector

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

// The cross-cutting per-level contract is enforced by
// TestStrictSuperset_ContractAcrossLevels in strict_superset_test.go, which
// is table-driven over the canonical lists of gated paths. The tests here
// cover the few things that test doesn't:
//   - PreservesAlreadyPopulated: idempotence of the normalizer.
//   - illustrative null/[] shape checks on a single field.

func TestNormalizeForLevel_PreservesAlreadyPopulated(t *testing.T) {
	p := &AccountPosture{
		IAM: IAMMetrics{
			Users: []IAMUser{{UserName: "alice"}},
		},
	}
	normalizeForLevel(p, componentsdk.LevelAudit)
	if len(p.IAM.Users) != 1 || p.IAM.Users[0].UserName != "alice" {
		t.Errorf("normalizer must not overwrite already-populated slices")
	}
}

// Marshalled-shape illustration: at audit level, the JSON contains "users":
// [] for an empty fleet, NOT a missing key or "users": null.
func TestNormalizeForLevel_AuditEmitsEmptyArrayNotNull(t *testing.T) {
	p := &AccountPosture{AccountID: "x"}
	normalizeForLevel(p, componentsdk.LevelAudit)
	b, err := json.Marshal(p.IAM)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"users":[]`) {
		t.Errorf("audit-empty IAM should marshal users as `[]`, got: %s", b)
	}
	if strings.Contains(string(b), `"users":null`) {
		t.Errorf("audit-empty IAM should NOT marshal users as `null`, got: %s", b)
	}
}

// And at trust level, the same field marshals as null (clearly "not collected").
func TestNormalizeForLevel_TrustEmitsNull(t *testing.T) {
	p := &AccountPosture{AccountID: "x"}
	normalizeForLevel(p, componentsdk.LevelTrust)
	b, err := json.Marshal(p.IAM)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"users":null`) {
		t.Errorf("trust-level IAM should marshal users as `null`, got: %s", b)
	}
}
