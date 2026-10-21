package collector

import (
	"fmt"
	"strings"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// allowIn is where to allow an action that no policy of a kind allows, by
// the kind AWS's message names. Any other kind is named as AWS names it.
var allowIn = map[string]string{
	"":                       "the collector's IAM policy",
	"identity-based policy":  "the collector's IAM policy",
	"service control policy": "the organization's service control policies",
	"permissions boundary":   "the collector's permissions boundary",
	"resource-based policy":  "the resource's policy",
}

// permissionOptions returns, for a gap AWS denied, the warning that says what
// to allow and where, and the IAM action as the missing permission, both from
// AWS's message. An explicit deny overrides any allow, so its gap names no
// permission to grant, and its warning says which policy denies the action.
func permissionOptions(err error) []componentsdk.GapOption {
	if componentsdk.Classify(err) != componentsdk.CodePermissionDenied {
		return nil
	}
	denial, ok := aws.DenialOf(err)
	if !ok {
		return nil
	}
	if denial.ExplicitIn != "" {
		policy := strings.ToUpper(denial.ExplicitIn[:1]) + denial.ExplicitIn[1:]
		return []componentsdk.GapOption{componentsdk.Warning(fmt.Sprintf("%s denies %s, and an explicit deny overrides any allow.", policy, denial.Action))}
	}
	where, ok := allowIn[denial.NotAllowedBy]
	if !ok {
		where = "the " + denial.NotAllowedBy
	}
	return []componentsdk.GapOption{
		componentsdk.Warning(fmt.Sprintf("Allow %s in %s.", denial.Action, where)),
		componentsdk.MissingPermission(denial.Action),
	}
}
