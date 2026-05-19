package aws

import (
	"testing"
)

func TestParseLambdaTime_HandlesAWSFormatAndRFC3339(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "aws default format", input: "2024-05-14T10:00:00.000+0000", want: "2024-05-14T10:00:00Z"},
		{name: "rfc3339 nano fallback", input: "2024-05-14T10:00:00.123456789Z", want: "2024-05-14T10:00:00Z"},
		{name: "rfc3339 fallback", input: "2024-05-14T10:00:00Z", want: "2024-05-14T10:00:00Z"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLambdaTime(tt.input)
			if got == nil {
				t.Fatalf("expected non-nil time for input %q", tt.input)
			}
			if got.UTC().Format("2006-01-02T15:04:05Z") != tt.want {
				t.Errorf("input=%q: got=%v want=%s", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseLambdaTime_NilForGarbageOrEmpty(t *testing.T) {
	if parseLambdaTime("") != nil {
		t.Errorf("expected nil for empty input")
	}
	if parseLambdaTime("not a timestamp") != nil {
		t.Errorf("expected nil for garbage input")
	}
}
