package aws

import (
	"errors"
	"regexp"

	"github.com/aws/smithy-go"
)

// Denial is what an AWS access denied message says about the call it refused.
type Denial struct {
	// Action is the IAM action the message names, such as iam:ListUsers.
	Action string

	// ExplicitIn names the policy that denies the action explicitly, as the
	// message does, such as "a service control policy". An explicit deny
	// overrides any allow, so allowing the action elsewhere does not help.
	ExplicitIn string

	// NotAllowedBy names the kind of policy that allows the action nowhere,
	// as the message does, such as "identity-based policy", or "" when the
	// message gives no reason.
	NotAllowedBy string
}

var (
	deniedActionPattern = regexp.MustCompile(`not authorized to perform: ([a-z0-9-]+:[A-Za-z0-9]+)`)
	explicitDenyPattern = regexp.MustCompile(`with an explicit deny in (an? [A-Za-z -]+?)(?:[:.,;]|$)`)
	notAllowedPattern   = regexp.MustCompile(`because no ([A-Za-z -]+?) allows the `)
)

// DenialOf reads the denial in the message of err's AWS error, as AWS writes
// it: "User: ... is not authorized to perform: iam:ListUsers because no
// identity-based policy allows the iam:ListUsers action". It reports false
// when err carries no AWS error or its message names no action, as S3's
// "Access Denied" for another account's bucket does not.
func DenialOf(err error) (Denial, bool) {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return Denial{}, false
	}
	message := apiErr.ErrorMessage()
	action := deniedActionPattern.FindStringSubmatch(message)
	if action == nil {
		return Denial{}, false
	}
	d := Denial{Action: action[1]}
	if m := explicitDenyPattern.FindStringSubmatch(message); m != nil {
		d.ExplicitIn = m[1]
	} else if m := notAllowedPattern.FindStringSubmatch(message); m != nil {
		d.NotAllowedBy = m[1]
	}
	return d, true
}
