package aws

import "testing"

func TestMatchesGuardDutyFindings(t *testing.T) {
	tests := []struct {
		name                string
		pattern             string
		wantMatch           bool
		wantFiltersSeverity bool
	}{
		{
			name:      "source alone selects findings",
			pattern:   `{"source":["aws.guardduty"]}`,
			wantMatch: true,
		},
		{
			name:      "detail-type alone selects findings",
			pattern:   `{"detail-type":["GuardDuty Finding"]}`,
			wantMatch: true,
		},
		{
			name:      "the console-generated pattern has both",
			pattern:   `{"source":["aws.guardduty"],"detail-type":["GuardDuty Finding"]}`,
			wantMatch: true,
		},
		{
			name:                "severity constraint is reported",
			pattern:             `{"source":["aws.guardduty"],"detail":{"severity":[{"numeric":[">=",7]}]}}`,
			wantMatch:           true,
			wantFiltersSeverity: true,
		},
		{
			name:      "detail constraint on another field is not a severity filter",
			pattern:   `{"source":["aws.guardduty"],"detail":{"type":["UnauthorizedAccess:EC2/SSHBruteForce"]}}`,
			wantMatch: true,
		},
		{
			name:      "guardduty among several sources still matches",
			pattern:   `{"source":["aws.securityhub","aws.guardduty"]}`,
			wantMatch: true,
		},
		{
			name:    "another service's rule",
			pattern: `{"source":["aws.ec2"]}`,
		},
		{
			name:    "prefix matcher objects are deliberately not recognised",
			pattern: `{"source":[{"prefix":"aws.guard"}]}`,
		},
		{
			name:    "schedule rules have no pattern",
			pattern: "",
		},
		{
			name:    "unparseable pattern",
			pattern: `{"source":`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, filtersSeverity := matchesGuardDutyFindings(tt.pattern)
			if match != tt.wantMatch {
				t.Errorf("matches = %v, want %v", match, tt.wantMatch)
			}
			if filtersSeverity != tt.wantFiltersSeverity {
				t.Errorf("filtersSeverity = %v, want %v", filtersSeverity, tt.wantFiltersSeverity)
			}
		})
	}
}

func TestEventTargetKind(t *testing.T) {
	tests := []struct {
		arn  string
		want string
	}{
		{"arn:aws:sns:us-east-1:123456789012:security-alerts", "sns"},
		{"arn:aws:lambda:us-east-1:123456789012:function:notify-slack", "lambda"},
		{"arn:aws:events:us-east-1:999999999999:event-bus/central-security", "event_bus"},
		{"arn:aws:events:us-east-1:123456789012:api-destination/pagerduty/abc-123", "api_destination"},
		{"arn:aws:sqs:us-east-1:123456789012:findings-queue", "sqs"},
		{"arn:aws:ssm:us-east-1:123456789012:document/run-remediation", "other"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := eventTargetKind(tt.arn); got != tt.want {
				t.Errorf("eventTargetKind(%q) = %q, want %q", tt.arn, got, tt.want)
			}
		})
	}
}
