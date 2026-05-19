package collector

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

// auditGatedJSONPaths enumerates every level-gated field that MUST be present
// (as a JSON array or object, never as `null`) when the collector runs at
// audit level. Paths use the JSON-tag form so they map directly to the
// emitted artifact shape that consumers will read.
//
// When adding a new surface, append the audit-level array's path here AND
// register the corresponding init in normalizeForLevel. The TestStrictSuperset
// table-driven tests will fail loudly if you do one without the other.
var auditGatedJSONPaths = []string{
	"iam.users",
	"iam.roles",
	"s3.buckets",
	"rds.instances",
	"rds.clusters",
	"network.vpcs",
	"network.security_groups",
	"account_security.cloudtrail.trails",
	"account_security.config.recorders",
	"account_security.guardduty.detectors",
	"account_security.security_hub.standards_arns",
	"account_security.security_hub.product_subscriptions",
	"identity_center.permission_sets",
	"lambda.functions",
	"ec2.instances",
	"cloudwatch_logs.log_groups",
	"kms.keys",
	"secrets_manager.secrets",
	"ssm_parameters.parameters",
}

// internalGatedJSONPaths is the analogous list for internal-only fields.
var internalGatedJSONPaths = []string{
	"iam.credential_report",
	"account_security.config.rules",
	"account_security.guardduty.findings",
	"identity_center.users",
	"identity_center.groups",
}

// TestStrictSuperset_ContractAcrossLevels marshals an empty AccountPosture
// at each level and verifies the gated-field contract for every registered
// path:
//   - trust: every gated path emits as `null` (not collected at this level).
//   - audit: every audit-gated path emits as a JSON array/object (collected);
//     every internal-gated path emits as `null`.
//   - internal: every gated path emits as a JSON array/object.
//
// This is the cross-cutting regression guard: a future surface that adds a
// new level-gated field but forgets to register it in normalizeForLevel will
// fail loudly here, as will a renamed field that drifts out of sync with
// the JSON tags.
func TestStrictSuperset_ContractAcrossLevels(t *testing.T) {
	tests := []struct {
		name        string
		level       componentsdk.Level
		wantNonNull []string
		wantNullToo []string
	}{
		{
			name:        "trust",
			level:       componentsdk.LevelTrust,
			wantNullToo: append([]string{}, append(auditGatedJSONPaths, internalGatedJSONPaths...)...),
		},
		{
			name:        "audit",
			level:       componentsdk.LevelAudit,
			wantNonNull: auditGatedJSONPaths,
			wantNullToo: internalGatedJSONPaths,
		},
		{
			name:        "internal",
			level:       componentsdk.LevelInternal,
			wantNonNull: append([]string{}, append(auditGatedJSONPaths, internalGatedJSONPaths...)...),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &AccountPosture{}
			normalizeForLevel(p, tc.level)

			b, err := json.Marshal(p)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var asMap map[string]any
			if err := json.Unmarshal(b, &asMap); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			for _, path := range tc.wantNonNull {
				value, found := lookupJSONPath(asMap, path)
				if !found {
					t.Errorf("%s level: path %q missing from artifact", tc.name, path)
					continue
				}
				if value == nil {
					t.Errorf("%s level: %q expected non-null, got null", tc.name, path)
				}
			}
			for _, path := range tc.wantNullToo {
				value, found := lookupJSONPath(asMap, path)
				if !found {
					t.Errorf("%s level: path %q missing from artifact", tc.name, path)
					continue
				}
				if value != nil {
					t.Errorf("%s level: %q expected null, got %v", tc.name, path, value)
				}
			}
		})
	}
}

// TestStrictSuperset_PathsAreUnique catches the common typo of duplicating a
// path in the audit and internal lists.
func TestStrictSuperset_PathsAreUnique(t *testing.T) {
	seen := map[string]string{}
	for _, p := range auditGatedJSONPaths {
		if other, dup := seen[p]; dup {
			t.Errorf("duplicate path %q (already seen in %s)", p, other)
		}
		seen[p] = "auditGatedJSONPaths"
	}
	for _, p := range internalGatedJSONPaths {
		if other, dup := seen[p]; dup {
			t.Errorf("duplicate path %q (already seen in %s)", p, other)
		}
		seen[p] = "internalGatedJSONPaths"
	}
}

// TestOutput_CollectedAtLevelMarshalsCorrectly is a smoke check that the
// top-level CollectedAtLevel field round-trips through JSON. Consumers rely
// on this field as a fallback when interpreting fields whose null-vs-[]
// distinction is ambiguous (e.g., per-resource scalars that we treat as
// per-resource nullable rather than per-level gated).
func TestOutput_CollectedAtLevelMarshalsCorrectly(t *testing.T) {
	for _, level := range []componentsdk.Level{componentsdk.LevelTrust, componentsdk.LevelAudit, componentsdk.LevelInternal} {
		out := NewOutput()
		out.CollectedAtLevel = string(level)
		b, err := json.Marshal(out)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		want := `"collected_at_level":"` + string(level) + `"`
		if !strings.Contains(string(b), want) {
			t.Errorf("level %s: expected %s in output, got: %s", level, want, b)
		}
	}
}

// lookupJSONPath walks a parsed-JSON map by dotted path. Returns the final
// value and a found flag. Intermediate non-object values fail the lookup.
func lookupJSONPath(root map[string]any, path string) (any, bool) {
	parts := strings.Split(path, ".")
	var cur any = root
	for _, part := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, exists := m[part]
		if !exists {
			return nil, false
		}
		cur = v
	}
	return cur, true
}
