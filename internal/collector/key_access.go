package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/locktivity/epack/componentsdk"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

// readOnlyVerbs begin the names of the actions that only read, after the
// service prefix, as AWS names its List and Read actions
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_understand-policy-summary-access-level-summaries.html,
// https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html).
// Action names are not case-sensitive.
var readOnlyVerbs = []string{"get", "list", "describe", "head", "batchget", "search", "lookup", "scan", "query", "select", "view"}

// readOnlyPolicies end the ARNs of the AWS managed policies that AWS
// describes as read-only access. Their documents also allow actions named
// with other verbs that AWS counts as reads, such as logs:StartQuery and
// sqs:Receive*, so they are taken as read-only by name and not read
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_job-functions.html).
var readOnlyPolicies = []string{
	":iam::aws:policy/ReadOnlyAccess",
	":iam::aws:policy/ViewOnlyAccess",
	":iam::aws:policy/SecurityAudit",
}

// anySource are the address sets that hold every address. A source
// condition over a set that holds one limits nothing.
var anySource = []string{"0.0.0.0/0", "::/0"}

// errBoundaryNotEvaluated is why an access key of a user with a permissions
// boundary is unmeasured, unless its identity policies already decide.
var errBoundaryNotEvaluated = componentsdk.CodeError(componentsdk.CodeNotRead,
	errors.New("an IAM user with an active access key has a permissions boundary, which can narrow what its identity policies allow, and the collector does not evaluate it"))

// iamKeyAccess counts the account's active access keys that are
// unrestricted, with full access and no IP limit, and those that can write.
// The root user's keys are both. A key whose user's policies could not be
// read, or whose user has a permissions boundary, is unknown on a value its
// known policies do not decide, and counted in unknownUnrestricted or
// unknownWrite. err is the first failed read that left a key unknown, or
// errBoundaryNotEvaluated when only boundaries did. read is false when the
// credential report could not be read, so there were no keys to evaluate.
type iamKeyAccess struct {
	read                              bool
	unrestricted, write               int
	unknownUnrestricted, unknownWrite int
	err                               error
}

// collectKeyAccess evaluates the active access keys in the credential
// report. Each IAM user with one has its identity policies read: the
// managed policies attached to it and its groups, from the default version
// of each, the inline policies of each, and its permissions boundary. The
// root user's keys have full access that no IAM policy narrows, so they are
// counted without a read. A nil report evaluates nothing.
func collectKeyAccess(policies *iamPolicies, report *aws.CredentialReport) iamKeyAccess {
	out := iamKeyAccess{}
	if report == nil {
		return out
	}
	out.read = true
	boundary := false
	for _, user := range report.Users {
		keys := 0
		for _, active := range []bool{user.AccessKey1Active, user.AccessKey2Active} {
			if active {
				keys++
			}
		}
		if keys == 0 {
			continue
		}
		if user.IsRootUser() {
			out.unrestricted += keys
			out.write += keys
			continue
		}
		v := policies.verdictOf(user.User)
		for _, c := range []struct {
			s              signal
			known, unknown *int
		}{{v.unrestricted, &out.unrestricted, &out.unknownUnrestricted}, {v.write, &out.write, &out.unknownWrite}} {
			switch {
			case c.s == signalYes:
				*c.known += keys
			case c.s == signalUnknown && v.err != nil:
				*c.unknown += keys
				if out.err == nil {
					out.err = v.err
				}
			case c.s == signalUnknown:
				*c.unknown += keys
				boundary = true
			}
		}
	}
	if out.err == nil && boundary {
		out.err = errBoundaryNotEvaluated
	}
	return out
}

// keyVerdict is whether an IAM user's access keys are unrestricted and
// whether they can write, and the failed read that left either unknown.
type keyVerdict struct {
	unrestricted, write signal
	err                 error
}

// verdictOf reads the user's identity policies and its permissions
// boundary, and evaluates what they let its access keys do. When a read
// fails, a value is known only when the policies that were read decide it:
// a deny of every action decides both, and a deny that takes back full
// access or limits the source decides that the key is not unrestricted.
// When the user has a permissions boundary, which only narrows what the
// identity policies allow, a value is known only when they do not allow it.
func (p *iamPolicies) verdictOf(user string) keyVerdict {
	var (
		statements []policyStatement
		readOnly   bool
		failed     error
	)
	fail := func(err error) {
		if failed == nil {
			failed = err
		}
	}
	collect := func(set policySet, inline func(name string) documentRead) {
		if set.err != nil {
			fail(set.err)
			return
		}
		for _, arn := range set.attached {
			if awsManaged(arn, readOnlyPolicies) {
				readOnly = true
				continue
			}
			d := p.managedDocument(arn)
			fail(d.err)
			statements = append(statements, d.statements...)
		}
		for _, name := range set.inline {
			d := inline(name)
			fail(d.err)
			statements = append(statements, d.statements...)
		}
	}
	collect(p.user(user), func(name string) documentRead { return p.userDocument(user, name) })
	groups := p.groupsOf(user)
	fail(groups.err)
	for _, g := range groups.names {
		collect(p.group(g), func(name string) documentRead { return p.groupDocument(g, name) })
	}
	boundary, err := p.boundaryOf(user)
	fail(err)

	reach := evaluateKeyPolicies(statements, readOnly)
	v := keyVerdict{unrestricted: signalOf(reach.unrestricted()), write: signalOf(reach.write)}
	switch {
	case failed != nil:
		v.err = failed
		if !reach.denyAll {
			v.write = signalUnknown
		}
		if !reach.denyAll && !reach.narrowed && !reach.sourceDeny {
			v.unrestricted = signalUnknown
		}
	case boundary:
		if v.unrestricted == signalYes {
			v.unrestricted = signalUnknown
		}
		if v.write == signalYes {
			v.write = signalUnknown
		}
	}
	return v
}

func signalOf(b bool) signal {
	if b {
		return signalYes
	}
	return signalNo
}

// documentRead is a policy document's statements, or why it could not be
// read.
type documentRead struct {
	statements []policyStatement
	err        error
}

// managedDocument reads the default version of the managed policy arn.
func (p *iamPolicies) managedDocument(arn string) documentRead {
	return p.document("managed/"+arn, named{"managed policy " + arn, "a managed policy"}, func() (string, error) {
		return p.client.GetPolicyDocument(p.ctx, arn)
	})
}

// userDocument reads the IAM user's inline policy called name.
func (p *iamPolicies) userDocument(user, name string) documentRead {
	return p.document("user/"+user+"/"+name, named{"inline policy " + name + " of IAM user " + user, "an inline policy of an IAM user"}, func() (string, error) {
		return p.client.GetUserPolicyDocument(p.ctx, user, name)
	})
}

// groupDocument reads the IAM group's inline policy called name.
func (p *iamPolicies) groupDocument(group, name string) documentRead {
	return p.document("group/"+group+"/"+name, named{"inline policy " + name + " of IAM group " + group, "an inline policy of an IAM group"}, func() (string, error) {
		return p.client.GetGroupPolicyDocument(p.ctx, group, name)
	})
}

// document reads and parses the policy document key names, once.
func (p *iamPolicies) document(key string, what named, read func() (string, error)) documentRead {
	if d, ok := p.documents[key]; ok {
		return d
	}
	var d documentRead
	text, err := read()
	if err == nil {
		d.statements, err = parsePolicy(text)
	}
	if err != nil {
		d = documentRead{err: err}
		p.warn(what, err)
	}
	p.documents[key] = d
	return d
}

// boundaryOf reports whether the IAM user has a permissions boundary.
func (p *iamPolicies) boundaryOf(user string) (bool, error) {
	arn, err := p.client.GetUserPermissionsBoundary(p.ctx, user)
	if err != nil {
		p.warn(named{"the permissions boundary of IAM user " + user, "the permissions boundary of an IAM user"}, err)
		return false, err
	}
	return arn != "", nil
}

// keyReach is what a user's identity policies let its access keys do.
// full is an allow of every action on every resource that no deny takes
// back. sourceLimited is true when the requests are limited to a set of
// addresses, by a deny of every action from outside it or by a source
// condition on every allow. denyAll is a deny of every action on every
// resource with no condition, which leaves the keys no permission.
// narrowed is a deny other than the source limit, which takes back full
// access, and sourceDeny is the source limit's deny.
type keyReach struct {
	full, write, sourceLimited    bool
	denyAll, narrowed, sourceDeny bool
}

func (r keyReach) unrestricted() bool { return r.full && !r.sourceLimited }

// evaluateKeyPolicies evaluates the statements of a user's identity
// policies for a request signed with one of its access keys. readOnly is
// true when one of readOnlyPolicies is attached, which allows reads with no
// condition.
//
// A statement applies unless one of its MFA conditions fails: such a
// request carries neither aws:MultiFactorAuthPresent nor
// aws:MultiFactorAuthAge, so only an IfExists or ForAllValues operator, or
// Null true, holds on them. An aws:SourceIp condition is evaluated as a
// limit to a set of addresses, and a set that holds 0.0.0.0/0 or ::/0
// limits nothing. Other conditions are not evaluated: an allow with one
// still counts, and a deny with one takes back full access but is no deny
// of everything or source limit.
func evaluateKeyPolicies(statements []policyStatement, readOnly bool) keyReach {
	var r keyReach
	allows, sourceAllows := 0, 0
	if readOnly {
		allows++
	}
	for _, s := range statements {
		c := s.keyConditions()
		if !c.applies || (s.Action == nil && s.NotAction == nil) || (s.NotAction != nil && holdsEvery(s.NotAction)) {
			continue
		}
		every := holdsEvery(s.Action) && holdsEvery(s.Resource) && s.NotResource == nil
		switch {
		case strings.EqualFold(s.Effect, "Allow"):
			allows++
			if c.sourceIn {
				sourceAllows++
			}
			r.full = r.full || every
			r.write = r.write || s.NotAction != nil || slices.ContainsFunc(s.Action, writes)
		case strings.EqualFold(s.Effect, "Deny"):
			switch {
			case every && c.sourceNotIn && !c.sourceIn && !c.other:
				r.sourceDeny = true
			case every && !c.sourceNotIn && !c.sourceIn && !c.other:
				r.denyAll = true
			default:
				r.narrowed = true
			}
		}
	}
	if r.denyAll {
		return keyReach{denyAll: true}
	}
	r.full = r.full && !r.narrowed
	r.write = r.write || r.full
	r.sourceLimited = r.sourceDeny || (allows > 0 && sourceAllows == allows)
	return r
}

// writes reports whether an action pattern covers an action that is not
// read-only. A pattern is read-only when its name after the service prefix
// starts with one of readOnlyVerbs before any wildcard, so s3:Get* reads and
// s3:* and * write.
func writes(action string) bool {
	_, name, ok := strings.Cut(action, ":")
	if !ok {
		return true
	}
	name = strings.ToLower(name)
	if i := strings.IndexAny(name, "*?"); i >= 0 {
		name = name[:i]
	}
	return !slices.ContainsFunc(readOnlyVerbs, func(verb string) bool { return strings.HasPrefix(name, verb) })
}

// keyConditions is how a statement's conditions bear on a request signed
// with an access key. applies is false when an MFA condition fails, or an
// aws:SourceIp condition can never hold. sourceIn is an IpAddress condition
// on aws:SourceIp, and sourceNotIn a NotIpAddress one, each over addresses
// that limit. other is a condition that is not evaluated.
type keyConditions struct {
	applies, sourceIn, sourceNotIn, other bool
}

func (s policyStatement) keyConditions() keyConditions {
	c := keyConditions{applies: true}
	for operator, keys := range s.Condition {
		op := strings.ToLower(operator)
		forAll := strings.HasPrefix(op, "forallvalues:")
		op = strings.TrimPrefix(strings.TrimPrefix(op, "forallvalues:"), "foranyvalue:")
		ifExists := strings.HasSuffix(op, "ifexists")
		op = strings.TrimSuffix(op, "ifexists")
		for key, values := range keys {
			switch strings.ToLower(key) {
			case "aws:multifactorauthpresent", "aws:multifactorauthage":
				switch {
				case op == "null":
					c.applies = c.applies && slices.ContainsFunc(values, func(v string) bool { return strings.EqualFold(v, "true") })
				case !ifExists && !forAll:
					c.applies = false
				}
			case "aws:sourceip":
				everywhere := slices.ContainsFunc(values, func(v string) bool { return slices.Contains(anySource, v) })
				switch {
				case op == "ipaddress" && !everywhere:
					c.sourceIn = true
				case op == "notipaddress" && everywhere:
					c.applies = false
				case op == "notipaddress":
					c.sourceNotIn = true
				case op != "ipaddress":
					c.other = true
				}
			default:
				c.other = true
			}
		}
	}
	return c
}

// holdsEvery reports whether an Action or Resource list holds *, every
// action or resource.
func holdsEvery(list flexibleStrings) bool { return slices.Contains(list, "*") }

// parsePolicy reads a policy document's statements, with the grammar the
// bucket policy check reads.
func parsePolicy(text string) ([]policyStatement, error) {
	var doc struct {
		Statement policyStatements `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		return nil, componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("the policy document does not follow the IAM policy grammar: %w", err))
	}
	return doc.Statement, nil
}
