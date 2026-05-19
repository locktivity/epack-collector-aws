package collector

import (
	"errors"
	"strings"

	"github.com/aws/smithy-go"
)

// warnAccessDenied records a structured per-surface AccessDenied warning.
//
// Use this when a collector's API call returns AccessDenied / UnauthorizedOperation
// and the surface should be skipped (not the whole run). The surface's pointer field
// stays nil so omitempty keeps it out of the artifact; the diagnostic in the output
// carries the missing-permission detail so the customer knows what to grant.
//
// The format is stable so consumers can grep / parse:
//
//	account <id>: surface <name>: access denied (missing permission: <iam-action>)
func (c *Collector) warnAccessDenied(accountID, surface, missingPermission string) {
	c.warn("account %s: surface %s: access denied (missing permission: %s)",
		accountID, surface, missingPermission)
}

// isAccessDeniedErr returns true if err is an AWS AccessDenied /
// UnauthorizedOperation response. Callers use this to distinguish missing IAM
// permissions (which should skip the surface gracefully and emit a diagnostic)
// from transient or unexpected errors (which surface as warnings without a
// missing-permission hint).
func isAccessDeniedErr(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation":
			return true
		}
	}
	// Some SDK error strings don't surface as smithy.APIError but still carry
	// the keyword. Fall back to substring match as a last resort.
	msg := err.Error()
	return strings.Contains(msg, "AccessDenied") || strings.Contains(msg, "UnauthorizedOperation")
}
