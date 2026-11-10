package collector

import (
	"errors"
	"strconv"
	"strings"

	"github.com/aws/smithy-go"
	"github.com/locktivity/epack/componentsdk"
)

// accountName is the account being collected: id is the account ID STS
// returned, which warnings pass as their account, and name is how a trust
// run's warnings name the account instead.
type accountName struct {
	id   string
	name string
}

// trustAccountName names the account at a 1-based position in the
// configuration in a trust run's diagnostics, which hold no account ID or
// role ARN: by its configured label, as the default credentials' account, or
// by its position. It reads after "account", as in account "production",
// account (default credentials), or account 2.
func trustAccountName(acct AccountConfig, position int) string {
	switch {
	case acct.Label != "":
		return strconv.Quote(acct.Label)
	case acct.RoleARN == "":
		return "(default credentials)"
	}
	return strconv.Itoa(position)
}

// named is a warning argument that names one of the account's resources, such
// as a bucket or an IAM user. A warning at audit and internal levels writes
// name, and a trust run's warning writes trust, which says what kind of
// resource it is without naming it.
type named struct {
	name  string
	trust string
}

func (n named) String() string { return n.name }

// trustArgs returns a warning's arguments as a trust run writes them, naming
// nothing that identifies the company's accounts or resources: the account
// being collected as trustAccountName names it, an error by its code alone,
// since AWS's messages often hold the caller's role ARN and the account ID,
// and a named resource by its kind.
func (c *Collector) trustArgs(args []any) []any {
	out := make([]any, len(args))
	for i, arg := range args {
		switch v := arg.(type) {
		case error:
			out[i] = errorCode(v)
		case named:
			out[i] = v.trust
		case string:
			if c.account.id != "" && v == c.account.id {
				out[i] = c.account.name
			} else {
				out[i] = v
			}
		default:
			out[i] = arg
		}
	}
	return out
}

// errorCode names err in a trust run's diagnostics: by AWS's error code, or
// by its componentsdk code when AWS sent none, such as timeout.
func errorCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		if code := strings.TrimSpace(apiErr.ErrorCode()); code != "" {
			return code
		}
	}
	return string(componentsdk.Classify(err))
}

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

func apiErrorCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		if code := strings.TrimSpace(apiErr.ErrorCode()); code != "" {
			return code
		}
	}
	if err != nil {
		return "NonAPIError"
	}
	return ""
}
