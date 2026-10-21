package collector

import (
	"context"
	"strings"
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// githubOIDC is what a GitHub Actions job with identity tokens enabled sets.
var githubOIDC = aws.OIDCEnv{RequestURL: "https://example.com/token", RequestToken: "gha_token"}

func TestResolveAuthMode(t *testing.T) {
	t.Run("returns empty string when no role ARNs", func(t *testing.T) {
		c := newTestCollector(Config{})
		accounts := []AccountConfig{{}, {}}

		mode, err := c.resolveAuthMode(accounts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mode != "" {
			t.Fatalf("expected empty auth mode for no role ARNs, got %q", mode)
		}
	})

	t.Run("uses explicit auth_mode from config", func(t *testing.T) {
		c := newTestCollector(Config{AuthMode: AuthModeAssumeRole})
		accounts := []AccountConfig{{RoleARN: "arn:aws:iam::123456789012:role/test"}}

		mode, err := c.resolveAuthMode(accounts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mode != AuthModeAssumeRole {
			t.Fatalf("expected assume_role, got %q", mode)
		}
	})

	t.Run("errors when explicit OIDC requested but unavailable", func(t *testing.T) {

		c := newTestCollector(Config{AuthMode: AuthModeOIDC})
		accounts := []AccountConfig{{RoleARN: "arn:aws:iam::123456789012:role/test"}}

		_, err := c.resolveAuthMode(accounts)
		if err == nil {
			t.Fatal("expected error when OIDC requested but unavailable")
		}
	})

	t.Run("errors on invalid auth_mode value", func(t *testing.T) {
		c := newTestCollector(Config{AuthMode: "assum_role"}) // typo
		accounts := []AccountConfig{{RoleARN: "arn:aws:iam::123456789012:role/test"}}

		_, err := c.resolveAuthMode(accounts)
		if err == nil {
			t.Fatal("expected error for invalid auth_mode")
		}
		if !strings.Contains(err.Error(), "invalid auth_mode") {
			t.Fatalf("expected 'invalid auth_mode' error, got: %v", err)
		}
	})

	t.Run("defaults to assume_role when auth_mode not specified", func(t *testing.T) {
		c := newTestCollector(Config{})
		accounts := []AccountConfig{{RoleARN: "arn:aws:iam::123456789012:role/test"}}

		mode, err := c.resolveAuthMode(accounts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mode != AuthModeAssumeRole {
			t.Fatalf("expected assume_role (default), got %q", mode)
		}
	})

	t.Run("uses OIDC when explicitly requested and available", func(t *testing.T) {
		c := newTestCollector(Config{AuthMode: AuthModeOIDC, OIDC: githubOIDC})
		accounts := []AccountConfig{{RoleARN: "arn:aws:iam::123456789012:role/test"}}

		mode, err := c.resolveAuthMode(accounts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mode != AuthModeOIDC {
			t.Fatalf("expected oidc, got %q", mode)
		}
	})
}

func TestInitializeAuth(t *testing.T) {
	t.Run("skips OIDC init when mode is assume_role", func(t *testing.T) {

		c := newTestCollector(Config{AuthMode: AuthModeAssumeRole})
		accounts := []AccountConfig{{RoleARN: "arn:aws:iam::123456789012:role/test"}}

		mode, warnings, err := c.initializeAuth(accounts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mode != AuthModeAssumeRole {
			t.Fatalf("expected assume_role, got %q", mode)
		}
		if len(warnings) != 0 {
			t.Fatalf("expected no warnings, got %v", warnings)
		}
	})

	t.Run("signs in with the identity token in OIDC mode", func(t *testing.T) {
		isolateAWSEnvironment(t)
		c := newTestCollector(Config{AuthMode: AuthModeOIDC, OIDC: githubOIDC})
		accounts := []AccountConfig{{RoleARN: "arn:aws:iam::123456789012:role/test"}}

		mode, _, err := c.initializeAuth(accounts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mode != AuthModeOIDC {
			t.Fatalf("expected oidc, got %q", mode)
		}
		client, err := c.createClient(context.Background(), accounts[0], mode)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := client.AuthMethod(); got != componentsdk.AuthWorkloadIdentity {
			t.Fatalf("auth method %q, want %q", got, componentsdk.AuthWorkloadIdentity)
		}
	})

	t.Run("generates warnings for external_id in OIDC mode", func(t *testing.T) {
		c := newTestCollector(Config{AuthMode: AuthModeOIDC, OIDC: githubOIDC})
		accounts := []AccountConfig{
			{RoleARN: "arn:aws:iam::123456789012:role/test1", ExternalID: "ext123"},
			{RoleARN: "arn:aws:iam::123456789012:role/test2"},
			{RoleARN: "arn:aws:iam::123456789012:role/test3", ExternalID: "ext456"},
		}

		_, warnings, err := c.initializeAuth(accounts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(warnings) != 2 {
			t.Fatalf("expected 2 warnings for external_id, got %d: %v", len(warnings), warnings)
		}
	})

	t.Run("no warnings when no external_ids in OIDC mode", func(t *testing.T) {
		c := newTestCollector(Config{AuthMode: AuthModeOIDC, OIDC: githubOIDC})
		accounts := []AccountConfig{
			{RoleARN: "arn:aws:iam::123456789012:role/test1"},
			{RoleARN: "arn:aws:iam::123456789012:role/test2"},
		}

		_, warnings, err := c.initializeAuth(accounts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(warnings) != 0 {
			t.Fatalf("expected no warnings, got %v", warnings)
		}
	})
}

func TestFormatAccountError(t *testing.T) {
	t.Run("formats error with role ARN", func(t *testing.T) {
		acct := AccountConfig{RoleARN: "arn:aws:iam::123456789012:role/test"}
		msg := formatAccountError(acct, &testError{msg: "connection failed"})
		if msg != "failed to collect account (arn:aws:iam::123456789012:role/test): connection failed" {
			t.Fatalf("unexpected error message: %s", msg)
		}
	})

	t.Run("formats error with default credentials", func(t *testing.T) {
		acct := AccountConfig{}
		msg := formatAccountError(acct, &testError{msg: "timeout"})
		if msg != "failed to collect account (default credentials): timeout" {
			t.Fatalf("unexpected error message: %s", msg)
		}
	})
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestResolveAuthMode_OIDCTokenFile(t *testing.T) {
	t.Run("errors when oidc has neither GitHub's token endpoint nor a token file", func(t *testing.T) {
		c := newTestCollector(Config{AuthMode: AuthModeOIDC})
		accounts := []AccountConfig{{RoleARN: "arn:aws:iam::123456789012:role/test"}}

		_, err := c.resolveAuthMode(accounts)
		if err == nil || !strings.Contains(err.Error(), "ACTIONS_ID_TOKEN_REQUEST_URL") || !strings.Contains(err.Error(), "AWS_WEB_IDENTITY_TOKEN_FILE") {
			t.Fatalf("expected an error naming both token sources, got: %v", err)
		}
	})

	t.Run("reads the token file outside GitHub Actions and warns about external_id", func(t *testing.T) {
		c := newTestCollector(Config{AuthMode: AuthModeOIDC, OIDC: aws.OIDCEnv{TokenFile: "/var/run/token"}})
		accounts := []AccountConfig{{RoleARN: "arn:aws:iam::123456789012:role/test", ExternalID: "ext"}}

		mode, warnings, err := c.initializeAuth(accounts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mode != AuthModeOIDC {
			t.Fatalf("expected oidc, got %q", mode)
		}
		if tokens := c.config.OIDC.TokenSource(context.Background(), nil); tokens == nil {
			t.Fatal("expected a file token source, got none")
		} else if _, ok := tokens.(*aws.FileTokenSource); !ok {
			t.Fatalf("expected a file token source, got %T", tokens)
		}
		if len(warnings) != 1 || !strings.Contains(warnings[0], "ignored in OIDC mode") {
			t.Fatalf("expected one external_id warning, got %v", warnings)
		}
	})
}
