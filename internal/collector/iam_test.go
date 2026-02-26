package collector

import (
	"net/url"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

func TestHasRotatedKeys(t *testing.T) {
	now := time.Now()
	threshold := now.AddDate(0, 0, -AccessKeyAgeThreshold)
	recent := now.AddDate(0, 0, -30)
	old := now.AddDate(0, 0, -120)

	if hasRotatedKeys(aws.CredentialReportUser{
		AccessKey1Active:      true,
		AccessKey1LastRotated: &recent,
	}, threshold) != true {
		t.Fatalf("expected recent active key to be considered rotated")
	}

	if hasRotatedKeys(aws.CredentialReportUser{
		AccessKey1Active:      true,
		AccessKey1LastRotated: &old,
	}, threshold) != false {
		t.Fatalf("expected old active key to be considered unrotated")
	}

	if hasRotatedKeys(aws.CredentialReportUser{
		AccessKey1Active: true,
	}, threshold) != false {
		t.Fatalf("expected nil key rotation timestamp to be unrotated")
	}
}

func TestProcessCredentialReport(t *testing.T) {
	now := time.Now()
	recent := now.AddDate(0, 0, -30)
	old := now.AddDate(0, 0, -120)

	report := &aws.CredentialReport{
		Users: []aws.CredentialReportUser{
			{
				User:             "<root_account>",
				MFAActive:        true,
				AccessKey1Active: false,
				AccessKey2Active: false,
			},
			{
				User:                  "alice",
				MFAActive:             true,
				AccessKey1Active:      true,
				AccessKey1LastRotated: &recent,
			},
			{
				User:                  "bob",
				MFAActive:             false,
				AccessKey1Active:      true,
				AccessKey1LastRotated: &old,
			},
		},
	}

	c := &Collector{}
	metrics := &IAMMetrics{}
	c.processCredentialReport(report, metrics)

	if !metrics.IAMUsersPresent {
		t.Fatalf("expected IAMUsersPresent=true")
	}
	if metrics.MFAEnabled != 50 {
		t.Fatalf("expected MFAEnabled=50, got %d", metrics.MFAEnabled)
	}
	if metrics.AccessKeysRotated != 50 {
		t.Fatalf("expected AccessKeysRotated=50, got %d", metrics.AccessKeysRotated)
	}
	if !metrics.RootMFAEnabled {
		t.Fatalf("expected RootMFAEnabled=true")
	}
	if metrics.RootAccessKeysExist {
		t.Fatalf("expected RootAccessKeysExist=false")
	}
}

func TestHasExternalTrust(t *testing.T) {
	current := "203984714075"

	sameAccountPolicy := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::203984714075:root"}}]}`
	encodedSame := url.QueryEscape(sameAccountPolicy)
	if hasExternalTrust(encodedSame, current) {
		t.Fatalf("expected same-account trust to be non-external")
	}

	externalPolicy := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"}}]}`
	encodedExternal := url.QueryEscape(externalPolicy)
	if !hasExternalTrust(encodedExternal, current) {
		t.Fatalf("expected external-account trust to be detected")
	}

	wildcardPolicy := `{"Statement":[{"Effect":"Allow","Principal":"*"}]}`
	encodedWildcard := url.QueryEscape(wildcardPolicy)
	if !hasExternalTrust(encodedWildcard, current) {
		t.Fatalf("expected wildcard trust to be detected as external")
	}
}

func TestExtractPrincipals(t *testing.T) {
	if got := extractPrincipals("arn:aws:iam::111111111111:root"); len(got) != 1 {
		t.Fatalf("expected 1 principal from string, got %v", got)
	}

	principalMap := map[string]any{
		"AWS": []any{
			"arn:aws:iam::111111111111:root",
			"arn:aws:iam::222222222222:root",
		},
	}

	got := extractPrincipals(principalMap)
	if len(got) != 2 {
		t.Fatalf("expected 2 principals from map, got %v", got)
	}

	if out := extractPrincipals(123); out != nil {
		t.Fatalf("expected nil for unsupported principal type, got %v", out)
	}
}

func TestHasExternalPrincipal(t *testing.T) {
	current := "203984714075"

	if hasExternalPrincipal("arn:aws:iam::203984714075:root", current) {
		t.Fatalf("expected same-account principal to be non-external")
	}
	if !hasExternalPrincipal("arn:aws:iam::111111111111:root", current) {
		t.Fatalf("expected external principal to be detected")
	}
	if !hasExternalPrincipal("*", current) {
		t.Fatalf("expected wildcard principal to be treated as external")
	}
}
