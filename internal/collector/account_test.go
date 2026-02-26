package collector

import (
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

func TestMergeCISLevelCompliance(t *testing.T) {
	target := &CISComplianceByLevel{
		PassedControls:       1,
		FailedControls:       2,
		WarningControls:      3,
		NotAvailableControls: 4,
	}

	source := aws.SecurityHubCISCompliance{
		PassedControls:       10,
		FailedControls:       20,
		WarningControls:      30,
		NotAvailableControls: 40,
	}

	mergeCISLevelCompliance(target, source)

	if target.PassedControls != 11 {
		t.Fatalf("expected passed_controls=11, got %d", target.PassedControls)
	}
	if target.FailedControls != 22 {
		t.Fatalf("expected failed_controls=22, got %d", target.FailedControls)
	}
	if target.WarningControls != 33 {
		t.Fatalf("expected warning_controls=33, got %d", target.WarningControls)
	}
	if target.NotAvailableControls != 44 {
		t.Fatalf("expected not_available_controls=44, got %d", target.NotAvailableControls)
	}
}

func TestFinalizeCISLevelCompliance(t *testing.T) {
	t.Run("failed controls", func(t *testing.T) {
		level := &CISComplianceByLevel{
			PassedControls: 2,
			FailedControls: 1,
		}

		finalizeCISLevelCompliance(level)

		if !level.Enabled {
			t.Fatalf("expected enabled=true")
		}
		if level.CompliancePercent != 66 {
			t.Fatalf("expected compliance_percent=66, got %d", level.CompliancePercent)
		}
		if level.ComplianceState != "FAILED" {
			t.Fatalf("expected compliance_state=FAILED, got %s", level.ComplianceState)
		}
	})

	t.Run("not available only", func(t *testing.T) {
		level := &CISComplianceByLevel{
			NotAvailableControls: 3,
		}

		finalizeCISLevelCompliance(level)

		if !level.Enabled {
			t.Fatalf("expected enabled=true")
		}
		if level.CompliancePercent != 0 {
			t.Fatalf("expected compliance_percent=0, got %d", level.CompliancePercent)
		}
		if level.ComplianceState != "NOT_AVAILABLE" {
			t.Fatalf("expected compliance_state=NOT_AVAILABLE, got %s", level.ComplianceState)
		}
	})

	t.Run("empty", func(t *testing.T) {
		level := &CISComplianceByLevel{}

		finalizeCISLevelCompliance(level)

		if level.Enabled {
			t.Fatalf("expected enabled=false")
		}
		if level.ComplianceState != "UNKNOWN" {
			t.Fatalf("expected compliance_state=UNKNOWN, got %s", level.ComplianceState)
		}
	})
}

func TestCISComplianceStatePrecedence(t *testing.T) {
	tests := []struct {
		name         string
		passed       int
		failed       int
		warning      int
		notAvailable int
		want         string
	}{
		{name: "failed wins", passed: 10, failed: 1, warning: 2, notAvailable: 3, want: "FAILED"},
		{name: "warning wins when no failed", passed: 10, failed: 0, warning: 2, notAvailable: 3, want: "WARNING"},
		{name: "passed wins when no failed or warning", passed: 10, failed: 0, warning: 0, notAvailable: 3, want: "PASSED"},
		{name: "not available only", passed: 0, failed: 0, warning: 0, notAvailable: 3, want: "NOT_AVAILABLE"},
		{name: "empty", passed: 0, failed: 0, warning: 0, notAvailable: 0, want: "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cisComplianceState(tt.passed, tt.failed, tt.warning, tt.notAvailable)
			if got != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, got)
			}
		})
	}
}

func TestCISStandardHelpers(t *testing.T) {
	if !isCISStandard("arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0") {
		t.Fatalf("expected CIS standard ARN to be detected")
	}
	if isCISStandard("arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0") {
		t.Fatalf("did not expect non-CIS standard ARN to be detected as CIS")
	}

	gotID := standardIDFromARN("arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0")
	wantID := "standards/cis-aws-foundations-benchmark/v/1.4.0"
	if gotID != wantID {
		t.Fatalf("expected standard id %q, got %q", wantID, gotID)
	}

	if standardIDFromARN("invalid-arn") != "" {
		t.Fatalf("expected empty standard id for invalid ARN")
	}
}
