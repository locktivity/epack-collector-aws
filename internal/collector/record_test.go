//go:build record

package collector

import (
	"net/url"
	"os"
	"regexp"
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

// TestRecord records a sandbox, an AWS account kept with known settings, to
// testdata/recordings/aws.json for the collectortest suite. It signs in as a
// GitHub Actions job does, trading the job's identity token for a session
// of the account's epack-sandbox-collector role. It reads the account from
// SANDBOX_ACCOUNT_ID, and the token request's URL and bearer token from
// ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN, which a
// job with id-token: write gets, and skips when any is not set. The account
// becomes the kit's, the value of any other SANDBOX_ variable becomes a
// stable fake, and Record writes nothing if one remains. The recording asks
// the kit's token URL for the identity token, so the suite replays the
// sign-in:
//
//	SANDBOX_ACCOUNT_ID=... go test -tags record -run 'TestRecord/^aws$' -count=1 ./internal/collector/
func TestRecord(t *testing.T) {
	t.Run("aws", func(t *testing.T) {
		account := os.Getenv("SANDBOX_ACCOUNT_ID")
		requestURL, requestToken := os.Getenv(aws.GitHubTokenRequestURLEnv), os.Getenv(aws.GitHubTokenRequestTokenEnv)
		if account == "" || requestURL == "" || requestToken == "" {
			t.Skip("set SANDBOX_ACCOUNT_ID, " + aws.GitHubTokenRequestURLEnv + ", and " + aws.GitHubTokenRequestTokenEnv + " to record")
		}
		requested, err := url.Parse(requestURL)
		if err != nil {
			t.Fatalf("%s: %v", aws.GitHubTokenRequestURLEnv, err)
		}
		kit, err := url.Parse(kitTokenURL)
		if err != nil {
			t.Fatal(err)
		}
		isolateAWSEnvironment(t)
		report, err := collectortest.Record(collectortest.RecordOptions{
			Spec: Spec("record", "collectortest"),
			Run:  Run,
			Config: map[string]any{
				"auth_mode": "oidc",
				"role_arn":  "arn:aws:iam::" + account + ":role/epack-sandbox-collector",
				"level":     "audit",
				"regions":   []any{"us-east-1", "us-west-2"},
			},
			Secrets: map[string]string{
				aws.GitHubTokenRequestURLEnv:   requestURL,
				aws.GitHubTokenRequestTokenEnv: requestToken,
			},
			Out: "testdata/recordings/aws.json",
			Scrub: collectortest.ScrubRules{
				Identifiers: collectortest.EnvIdentifiers("SANDBOX_", map[string]string{"SANDBOX_ACCOUNT_ID": kitAccountID}),
				Literals:    map[string]string{requested.Host: kit.Host, requested.Path: kit.Path},
				// The SDK names each role session by the time in nanoseconds,
				// so no replay sends the recorded name.
				Patterns: []collectortest.ScrubPattern{{Pattern: regexp.MustCompile(`,"RoleSessionName":"[0-9]+"`), Replace: ""}},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if report.ExitCode != 0 {
			t.Errorf("the recorded run exited %d: %+v", report.ExitCode, report.Failure)
		}
		t.Logf("recorded %d responses", report.Responses)
	})
}
