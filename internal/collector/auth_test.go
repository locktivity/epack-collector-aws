package collector

import (
	"strings"
	"testing"
)

func TestResolveAuthMode(t *testing.T) {
	t.Run("returns empty string when no role ARNs", func(t *testing.T) {
		c := &Collector{config: Config{}}
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
		c := &Collector{config: Config{AuthMode: AuthModeAssumeRole}}
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
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

		c := &Collector{config: Config{AuthMode: AuthModeOIDC}}
		accounts := []AccountConfig{{RoleARN: "arn:aws:iam::123456789012:role/test"}}

		_, err := c.resolveAuthMode(accounts)
		if err == nil {
			t.Fatal("expected error when OIDC requested but unavailable")
		}
	})

	t.Run("errors on invalid auth_mode value", func(t *testing.T) {
		c := &Collector{config: Config{AuthMode: "assum_role"}} // typo
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
		c := &Collector{config: Config{}}
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
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/token")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "gha_token")

		c := &Collector{config: Config{AuthMode: AuthModeOIDC}}
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
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

		c := &Collector{config: Config{AuthMode: AuthModeAssumeRole}}
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
		if c.tokenSource != nil {
			t.Fatal("expected nil token source for assume_role mode")
		}
	})

	t.Run("initializes token source for OIDC mode", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/token")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "gha_token")

		c := &Collector{config: Config{AuthMode: AuthModeOIDC}}
		accounts := []AccountConfig{{RoleARN: "arn:aws:iam::123456789012:role/test"}}

		mode, _, err := c.initializeAuth(accounts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mode != AuthModeOIDC {
			t.Fatalf("expected oidc, got %q", mode)
		}
		if c.tokenSource == nil {
			t.Fatal("expected token source to be initialized for OIDC mode")
		}
	})

	t.Run("generates warnings for external_id in OIDC mode", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/token")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "gha_token")

		c := &Collector{config: Config{AuthMode: AuthModeOIDC}}
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
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/token")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "gha_token")

		c := &Collector{config: Config{AuthMode: AuthModeOIDC}}
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
