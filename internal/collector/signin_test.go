package collector

import (
	"net/http"
	"testing"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

// useAccessKeys gives the SDK's default chain static access keys, as an
// operator's environment does.
func useAccessKeys(t *testing.T) {
	t.Helper()
	isolateAWSEnvironment(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "kit-access-key-id")
	t.Setenv("AWS_SECRET_ACCESS_KEY", kitSecretKey)
}

// stsRejected answers an STS call with the error AWS sends for credentials it
// does not accept.
func stsRejected(op string, status int, code, message string) collectortest.Response {
	return collectortest.Response{
		Operation: op, Method: http.MethodPost, URL: kitSTSURL, Status: status, Header: xmlHeader(),
		Body: "<ErrorResponse><Error><Type>Sender</Type><Code>" + code + "</Code><Message>" + message + "</Message></Error><RequestId>kit-request</RequestId></ErrorResponse>",
	}
}

func TestRunRecordsTheSignInMethod(t *testing.T) {
	t.Run("role assumed with the job's identity token", func(t *testing.T) {
		isolateAWSEnvironment(t)
		res := runKit(t, kitConfig(), kitSecrets(), kitResponses())
		if res.ExitCode != 0 || res.Result == nil {
			t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
		}
		got := res.Result.SignedInAs
		if got == nil || got.Kind != "role" || got.AuthMethod != componentsdk.AuthWorkloadIdentity || got.TenantID != kitAccountID {
			t.Fatalf("signed_in_as = %+v, want the role session, signed in with %q", got, componentsdk.AuthWorkloadIdentity)
		}
	})

	t.Run("static access keys", func(t *testing.T) {
		useAccessKeys(t)
		responses := replaceResponses(kitResponses(), queryResponse("aws.sts.GetCallerIdentity", kitSTSURL,
			"<Arn>arn:aws:iam::111122223333:user/epack-collector</Arn><UserId>AIDAKITEXAMPLE</UserId><Account>"+kitAccountID+"</Account>"))
		res := runKit(t, map[string]any{"level": "trust"}, nil, responses)
		if res.ExitCode != 0 || res.Result == nil {
			t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
		}
		got := res.Result.SignedInAs
		if got == nil || got.Kind != "user" || got.AuthMethod != componentsdk.AuthAccessKey {
			t.Fatalf("signed_in_as = %+v, want the IAM user, signed in with %q", got, componentsdk.AuthAccessKey)
		}
	})
}

// A credential AWS rejects fails the run with auth_failed and exit 3, and
// emits no evidence, however the collector signed in.
func TestRejectedCredentialFailsTheRun(t *testing.T) {
	invalidKey := "The security token included in the request is invalid."
	cases := []struct {
		name      string
		keys      bool
		config    map[string]any
		secrets   map[string]string
		responses []collectortest.Response
	}{
		{
			name:    "identity token",
			config:  kitConfig(),
			secrets: kitSecrets(),
			responses: []collectortest.Response{
				kitSignInResponses()[0],
				stsRejected("aws.sts.AssumeRoleWithWebIdentity", http.StatusBadRequest, "InvalidIdentityToken", "Incorrect token audience"),
			},
		},
		{
			name:      "access keys",
			keys:      true,
			config:    map[string]any{"level": "trust"},
			responses: []collectortest.Response{stsRejected("aws.sts.GetCallerIdentity", http.StatusForbidden, "InvalidClientTokenId", invalidKey)},
		},
		{
			name:      "access keys assuming a role",
			keys:      true,
			config:    map[string]any{"level": "trust", "auth_mode": "assume_role", "role_arn": kitRoleARN},
			responses: []collectortest.Response{stsRejected("aws.sts.AssumeRole", http.StatusForbidden, "InvalidClientTokenId", invalidKey)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.keys {
				useAccessKeys(t)
			} else {
				isolateAWSEnvironment(t)
			}
			res := runKit(t, tc.config, tc.secrets, tc.responses)
			if res.ExitCode != 3 || res.Failure == nil || res.Failure.Code != componentsdk.CodeAuthFailed {
				t.Fatalf("exit %d, failure %+v; want exit 3 with auth_failed", res.ExitCode, res.Failure)
			}
			if len(res.Artifacts) != 0 {
				t.Errorf("a rejected credential emitted %d artifacts", len(res.Artifacts))
			}
		})
	}
}
