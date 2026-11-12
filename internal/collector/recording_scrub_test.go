package collector

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// kitCanonicalID replaces each S3 canonical user ID in a recording. A
// canonical ID stands for an AWS account, and Record's own rules take its 64
// hex characters for a SHA-256 digest. The collector only reports these IDs
// and never compares them, so one fake for every ID changes no reading.
var kitCanonicalID = strings.Repeat("0", 63) + "1"

// kitStoreIDHex is the hex part of the kit's identity store ID, which
// also prefixes the IDs of the users and groups of an older identity store.
var kitStoreIDHex = strings.TrimPrefix(kitStoreID, "d-")

// recordScrubPatterns remove from a recording the sandbox's identifiers
// other than its account ID, which SANDBOX_ACCOUNT_ID names: the S3
// canonical user IDs and display names of bucket owners and grantees, and
// the IDs of the account's IAM Identity Center instance and identity store.
var recordScrubPatterns = []collectortest.ScrubPattern{
	{Pattern: canonicalID, Replace: "<ID>" + kitCanonicalID + "</ID>"},
	{Pattern: regexp.MustCompile(`<DisplayName>[^<]*</DisplayName>`), Replace: "<DisplayName>kit</DisplayName>"},
	{Pattern: identityStoreID, Replace: kitStoreID},
	{Pattern: identityStoreMemberID, Replace: kitStoreIDHex + "-$1"},
	{Pattern: ssoInstanceID, Replace: "ssoins-1111222233334444"},
}

var (
	canonicalID           = regexp.MustCompile(`<ID>[0-9a-f]{64}</ID>`)
	identityStoreID       = regexp.MustCompile(`\bd-[0-9a-f]{10}\b`)
	identityStoreMemberID = regexp.MustCompile(`\b[0-9a-f]{10}-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
	ssoInstanceID         = regexp.MustCompile(`\bssoins-[0-9a-f]{16}\b`)

	// recordedCanonicalID finds a canonical ID in a recording, where the
	// XML body is a JSON string that may escape its angle brackets.
	recordedCanonicalID   = regexp.MustCompile(`ID(?:>|\\u003e)([0-9a-f]{64})`)
	recordedStoreMemberID = regexp.MustCompile(`\b([0-9a-f]{10})-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
)

func TestRecordScrubPatterns(t *testing.T) {
	owner := "<Owner><ID>79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be</ID><DisplayName>sandbox-root</DisplayName></Owner>"
	for in, want := range map[string]string{
		owner: "<Owner><ID>" + kitCanonicalID + "</ID><DisplayName>kit</DisplayName></Owner>",
		`{"InstanceArn":"arn:aws:sso:::instance/ssoins-7223a1b2c3d4e5f6","IdentityStoreId":"d-90679a1b2c","Status":"ACTIVE"}`: `{"InstanceArn":"` + kitInstanceARN + `","IdentityStoreId":"` + kitStoreID + `","Status":"ACTIVE"}`,
		`{"UserId":"90679a1b2c-4a3b0d9c-1f2e-4d5c-8b7a-0123456789ab","UserName":"epack-sandbox-idc-user-1"}`:                  `{"UserId":"` + kitStoreIDHex + `-4a3b0d9c-1f2e-4d5c-8b7a-0123456789ab","UserName":"epack-sandbox-idc-user-1"}`,
	} {
		got := in
		for _, p := range recordScrubPatterns {
			got = p.Pattern.ReplaceAllString(got, p.Replace)
		}
		if got != want {
			t.Errorf("scrubbed %s to %s, want %s", in, got, want)
		}
	}
}

// TestRecordingsScrubbed fails while a committed recording still holds an S3
// canonical user ID, or an ID of an Identity Center instance or identity
// store, other than the kit's.
func TestRecordingsScrubbed(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "recordings", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range recordedCanonicalID.FindAllSubmatch(raw, -1) {
			if string(m[1]) != kitCanonicalID {
				t.Errorf("%s: holds an S3 canonical user ID", path)
			}
		}
		for _, id := range identityStoreID.FindAll(raw, -1) {
			if string(id) != kitStoreID {
				t.Errorf("%s: holds an identity store ID", path)
			}
		}
		for _, m := range recordedStoreMemberID.FindAllSubmatch(raw, -1) {
			if string(m[1]) != kitStoreIDHex {
				t.Errorf("%s: holds an identity store's ID in a user or group ID", path)
			}
		}
		for _, id := range ssoInstanceID.FindAll(raw, -1) {
			if !strings.HasSuffix(kitInstanceARN, string(id)) {
				t.Errorf("%s: holds an Identity Center instance ID", path)
			}
		}
	}
}
