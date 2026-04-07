package aws

import (
	"strings"
	"testing"
	"time"

	securityhubtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

func TestRegionForRoleARN(t *testing.T) {
	tests := []struct {
		name     string
		roleARN  string
		expected string
	}{
		{
			name:     "standard AWS partition",
			roleARN:  "arn:aws:iam::123456789012:role/EpackCollectorRole",
			expected: DefaultRegionAWS,
		},
		{
			name:     "GovCloud partition",
			roleARN:  "arn:aws-us-gov:iam::123456789012:role/EpackCollectorRole",
			expected: DefaultRegionGov,
		},
		{
			name:     "China partition",
			roleARN:  "arn:aws-cn:iam::123456789012:role/EpackCollectorRole",
			expected: DefaultRegionChina,
		},
		{
			name:     "empty ARN falls back to standard",
			roleARN:  "",
			expected: DefaultRegionAWS,
		},
		{
			name:     "malformed ARN falls back to standard",
			roleARN:  "not-an-arn",
			expected: DefaultRegionAWS,
		},
		{
			name:     "partial ARN prefix falls back to standard",
			roleARN:  "arn:aws-fake:iam::123456789012:role/Role",
			expected: DefaultRegionAWS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := regionForRoleARN(tt.roleARN)
			if got != tt.expected {
				t.Errorf("regionForRoleARN(%q) = %q, want %q", tt.roleARN, got, tt.expected)
			}
		})
	}
}

func TestDefaultRegionConstants(t *testing.T) {
	// Verify the constants are valid AWS regions
	if DefaultRegionAWS != "us-east-1" {
		t.Errorf("DefaultRegionAWS = %q, want us-east-1", DefaultRegionAWS)
	}
	if DefaultRegionGov != "us-gov-west-1" {
		t.Errorf("DefaultRegionGov = %q, want us-gov-west-1", DefaultRegionGov)
	}
	if DefaultRegionChina != "cn-north-1" {
		t.Errorf("DefaultRegionChina = %q, want cn-north-1", DefaultRegionChina)
	}
}

func TestCISLevelsForFinding(t *testing.T) {
	t.Run("level 1 only", func(t *testing.T) {
		levels := cisLevelsForFinding([]string{"CIS AWS Foundations Benchmark v1.4.0 Level 1"})
		if len(levels) != 1 || levels[0] != 1 {
			t.Fatalf("expected [1], got %v", levels)
		}
	})

	t.Run("level 2 only", func(t *testing.T) {
		levels := cisLevelsForFinding([]string{"CIS AWS Foundations Benchmark v1.4.0 Level 2"})
		if len(levels) != 1 || levels[0] != 2 {
			t.Fatalf("expected [2], got %v", levels)
		}
	})

	t.Run("both levels", func(t *testing.T) {
		levels := cisLevelsForFinding([]string{"Level I", "Level II"})
		if len(levels) != 2 || levels[0] != 1 || levels[1] != 2 {
			t.Fatalf("expected [1 2], got %v", levels)
		}
	})

	t.Run("no level tags", func(t *testing.T) {
		levels := cisLevelsForFinding([]string{"NIST 800-53 AC-2"})
		if len(levels) != 0 {
			t.Fatalf("expected no levels, got %v", levels)
		}
	})
}

func TestCISControlIDForFinding(t *testing.T) {
	finding := securityhubtypes.AwsSecurityFinding{
		GeneratorId: strptr("generator/control-id"),
		Compliance: &securityhubtypes.Compliance{
			SecurityControlId: strptr("S3.8"),
		},
	}

	if got := cisControlIDForFinding(finding); got != "S3.8" {
		t.Fatalf("expected SecurityControlId, got %q", got)
	}

	finding.Compliance.SecurityControlId = nil
	if got := cisControlIDForFinding(finding); got != "generator/control-id" {
		t.Fatalf("expected GeneratorId fallback, got %q", got)
	}
}

func TestCISStatusSeverity(t *testing.T) {
	if cisStatusSeverity(securityhubtypes.ComplianceStatusFailed) <= cisStatusSeverity(securityhubtypes.ComplianceStatusWarning) {
		t.Fatalf("expected FAILED to outrank WARNING")
	}
	if cisStatusSeverity(securityhubtypes.ComplianceStatusWarning) <= cisStatusSeverity(securityhubtypes.ComplianceStatusPassed) {
		t.Fatalf("expected WARNING to outrank PASSED")
	}
	if cisStatusSeverity(securityhubtypes.ComplianceStatusPassed) <= cisStatusSeverity(securityhubtypes.ComplianceStatusNotAvailable) {
		t.Fatalf("expected PASSED to outrank NOT_AVAILABLE")
	}
}

func strptr(v string) *string {
	return &v
}

func TestParseTime(t *testing.T) {
	if got := parseTime(""); !got.IsZero() {
		t.Fatalf("expected zero time for empty string")
	}
	if got := parseTime("N/A"); !got.IsZero() {
		t.Fatalf("expected zero time for N/A")
	}
	if got := parseTime("not_supported"); !got.IsZero() {
		t.Fatalf("expected zero time for not_supported")
	}
	if got := parseTime("no_information"); !got.IsZero() {
		t.Fatalf("expected zero time for no_information")
	}

	ts := "2026-02-26T15:11:02Z"
	got := parseTime(ts)
	if got.IsZero() {
		t.Fatalf("expected parsed time for %q", ts)
	}
	if got.Format(time.RFC3339) != ts {
		t.Fatalf("unexpected parsed timestamp: %s", got.Format(time.RFC3339))
	}
}

func TestParseTimePtr(t *testing.T) {
	if got := parseTimePtr(""); got != nil {
		t.Fatalf("expected nil for empty time")
	}
	if got := parseTimePtr("2026-02-26T15:11:02Z"); got == nil {
		t.Fatalf("expected non-nil for valid timestamp")
	}
}

func TestGetCol(t *testing.T) {
	row := []string{"alice", "true"}
	colIndex := map[string]int{
		"user":       0,
		"mfa_active": 1,
		"bad_index":  5,
	}

	if got := getCol(row, colIndex, "user"); got != "alice" {
		t.Fatalf("expected user=alice, got %q", got)
	}
	if got := getCol(row, colIndex, "missing"); got != "" {
		t.Fatalf("expected empty value for missing column, got %q", got)
	}
	if got := getCol(row, colIndex, "bad_index"); got != "" {
		t.Fatalf("expected empty value for out-of-range index, got %q", got)
	}
}

func TestParseCredentialReport(t *testing.T) {
	csvContent := strings.Join([]string{
		"user,arn,user_creation_time,mfa_active,password_enabled,access_key_1_active,access_key_1_last_rotated,access_key_2_active,access_key_2_last_rotated,cert_1_active,cert_2_active,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_last_used_region,access_key_2_last_used_service,password_last_used,password_last_changed,password_next_rotation,access_key_1_last_used_date,access_key_2_last_used_date,cert_1_last_rotated,cert_2_last_rotated",
		"<root_account>,arn:aws:iam::123456789012:root,2026-01-01T00:00:00Z,true,true,false,N/A,false,N/A,false,false,us-east-1,signin.amazonaws.com,N/A,N/A,2026-02-20T00:00:00Z,2026-02-01T00:00:00Z,N/A,N/A,N/A,N/A,N/A",
		"alice,arn:aws:iam::123456789012:user/alice,2026-01-02T00:00:00Z,false,true,true,2026-02-10T00:00:00Z,false,N/A,false,false,us-east-1,s3,us-east-1,ec2,2026-02-20T00:00:00Z,2026-02-01T00:00:00Z,N/A,2026-02-25T00:00:00Z,N/A,N/A,N/A",
	}, "\n")

	report, err := parseCredentialReport([]byte(csvContent))
	if err != nil {
		t.Fatalf("parseCredentialReport returned error: %v", err)
	}

	if len(report.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(report.Users))
	}

	root := report.Users[0]
	if !root.IsRootUser() {
		t.Fatalf("expected first row to be root user")
	}
	if !root.MFAActive {
		t.Fatalf("expected root MFA active=true")
	}

	alice := report.Users[1]
	if alice.User != "alice" {
		t.Fatalf("expected second user to be alice, got %q", alice.User)
	}
	if !alice.AccessKey1Active {
		t.Fatalf("expected alice access_key_1_active=true")
	}
	if alice.AccessKey1LastRotated == nil {
		t.Fatalf("expected alice access_key_1_last_rotated to be parsed")
	}
}

func TestParseCredentialReportErrorsAndEmpty(t *testing.T) {
	if _, err := parseCredentialReport([]byte("\"unterminated")); err == nil {
		t.Fatalf("expected CSV parse error for malformed content")
	}

	report, err := parseCredentialReport([]byte("user,arn\n"))
	if err != nil {
		t.Fatalf("expected no error for header-only report, got %v", err)
	}
	if len(report.Users) != 0 {
		t.Fatalf("expected zero users for header-only report")
	}
}

func TestIsGitHubActionsOIDCAvailable(t *testing.T) {
	t.Run("not available when env vars missing", func(t *testing.T) {
		// Clear any existing values
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

		if IsGitHubActionsOIDCAvailable() {
			t.Fatal("expected OIDC to be unavailable when env vars are empty")
		}
	})

	t.Run("not available when only URL set", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/token")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

		if IsGitHubActionsOIDCAvailable() {
			t.Fatal("expected OIDC to be unavailable when only URL is set")
		}
	})

	t.Run("not available when only token set", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "gha_token")

		if IsGitHubActionsOIDCAvailable() {
			t.Fatal("expected OIDC to be unavailable when only token is set")
		}
	})

	t.Run("available when both env vars set", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/token")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "gha_token")

		if !IsGitHubActionsOIDCAvailable() {
			t.Fatal("expected OIDC to be available when both env vars are set")
		}
	})
}

func TestNewGitHubOIDCTokenSource(t *testing.T) {
	ts := NewGitHubOIDCTokenSource()
	if ts == nil {
		t.Fatal("expected non-nil token source")
	}
	if ts.cachedToken != "" {
		t.Fatal("expected empty cached token on new source")
	}
	if !ts.cachedAt.IsZero() {
		t.Fatal("expected zero cachedAt on new source")
	}
}

func TestGitHubOIDCTokenSource_CachingBehavior(t *testing.T) {
	t.Run("returns error when OIDC not available", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

		ts := NewGitHubOIDCTokenSource()
		_, err := ts.GetIdentityToken()
		if err == nil {
			t.Fatal("expected error when OIDC env vars not set")
		}
		if !strings.Contains(err.Error(), "OIDC not available") {
			t.Fatalf("expected OIDC not available error, got: %v", err)
		}
	})

	t.Run("uses cached token within TTL", func(t *testing.T) {
		ts := NewGitHubOIDCTokenSource()
		// Manually set a cached token
		ts.cachedToken = "cached_jwt_token"
		ts.cachedAt = time.Now()

		token, err := ts.GetIdentityToken()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(token) != "cached_jwt_token" {
			t.Fatalf("expected cached token, got: %s", token)
		}
	})

	t.Run("refetches token after TTL expires", func(t *testing.T) {
		// This test verifies the cache is bypassed after TTL
		// We can't easily mock the HTTP call, but we can verify the logic
		ts := NewGitHubOIDCTokenSource()
		ts.cachedToken = "old_token"
		ts.cachedAt = time.Now().Add(-tokenCacheTTL - time.Minute) // Expired

		// Without valid env vars, this should attempt to fetch and fail
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

		_, err := ts.GetIdentityToken()
		if err == nil {
			t.Fatal("expected error when cache expired and env vars not set")
		}
		// This proves the cache was bypassed
	})
}
