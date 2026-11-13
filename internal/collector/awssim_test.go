package collector

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// simRosterPath is the aws sandbox's roster in v1 form, which cmd/derive in
// epack-collector-sandboxes converts from sandboxes/aws/roster.json and the
// refresh workflow commits here, beside the recording it keeps current.
const (
	simRosterPath    = "testdata/simulator/aws.roster.json"
	simRecordingPath = "testdata/recordings/aws.json"
)

// simBase is the sandbox's roster, with the settings it has no term for
// rendered as the sandbox sets them. pab-absent has no public access block,
// and pab-combined blocks public ACLs and leaves public policies to the
// account's block (s3.tf). trail-2 records write events alone, with event
// selectors of its own, and leaves out global service events
// (cloudtrail.tf).
func simBase(t testing.TB) *roster.Roster {
	t.Helper()
	r, err := roster.Load(simRosterPath)
	if err != nil {
		t.Fatal(err)
	}
	for i := range r.Storage {
		switch st := &r.Storage[i]; {
		case strings.HasSuffix(st.Key, "-pab-absent"):
			simulate.SetExtra(&st.Extra, "public_access_block", "absent")
		case strings.HasSuffix(st.Key, "-pab-combined"):
			simulate.SetExtra(&st.Extra, "public_access_block", "acls")
		}
	}
	for i := range r.Cloud.Accounts[0].AuditLogs {
		if l := &r.Cloud.Accounts[0].AuditLogs[i]; l.Key == "epack-sandbox-trail-2-single-region" {
			simulate.SetExtra(&l.Extra, "event_selectors", "write_only")
			simulate.SetExtra(&l.Extra, "global_service_events", false)
		}
	}
	return r
}

// simXMLHeader marks a response whose body is an XML body in the JSON form,
// which Collect writes back as XML.
const simXMLHeader = "X-Simulator-Xml"

// simRecording is the sandbox's recording with its XML bodies in the JSON
// form: its answers, to replay the calls the roster doesn't drive and to
// copy recorded items from, and the shapes every simulated answer keeps.
type simRecording struct {
	responses []collectortest.Response
	config    map[string]any
	at        time.Time
	shapes    *simulate.Recorded
}

func loadSimRecording(t testing.TB) *simRecording {
	t.Helper()
	data, err := os.ReadFile(simRecordingPath)
	if err != nil {
		t.Fatal(err)
	}
	var file map[string]json.RawMessage
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	var responses []map[string]json.RawMessage
	if err := json.Unmarshal(file["responses"], &responses); err != nil {
		t.Fatal(err)
	}
	xmlBodies := map[int]bool{}
	for i, resp := range responses {
		var body string
		if json.Unmarshal(resp["body"], &body) != nil || !strings.HasPrefix(strings.TrimSpace(body), "<") {
			continue
		}
		doc, err := simXMLDecode(body)
		if err != nil {
			t.Fatalf("%s response %d: %v", simRecordingPath, i, err)
		}
		resp["body"] = json.RawMessage(simJSON(doc))
		xmlBodies[i] = true
	}
	file["responses"] = json.RawMessage(simJSON(responses))
	path := filepath.Join(t.TempDir(), "aws.json")
	if err := os.WriteFile(path, []byte(simJSON(file)), 0o600); err != nil {
		t.Fatal(err)
	}
	sc, err := collectortest.LoadScenario(path)
	if err != nil {
		t.Fatal(err)
	}
	shapes, err := simulate.LoadRecorded(path)
	if err != nil {
		t.Fatal(err)
	}
	var head struct {
		RecordedAt time.Time `json:"recorded_at"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		t.Fatal(err)
	}
	for i := range sc.Responses {
		if xmlBodies[i] {
			sc.Responses[i].Header = simWithXMLMark(sc.Responses[i].Header)
		}
	}
	return &simRecording{responses: sc.Responses, config: sc.Config, at: head.RecordedAt, shapes: shapes}
}

func simWithXMLMark(h http.Header) http.Header {
	h = h.Clone()
	if h == nil {
		h = http.Header{}
	}
	h.Set(simXMLHeader, "1")
	if h.Get("Content-Type") == "" {
		h.Set("Content-Type", "application/xml")
	}
	return h
}

// simWriteXML writes each body in the JSON form back as XML.
func simWriteXML(t testing.TB, responses []collectortest.Response) []collectortest.Response {
	t.Helper()
	out := slices.Clone(responses)
	for i, r := range out {
		if r.Header.Get(simXMLHeader) == "" {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(r.Body), &doc); err != nil {
			t.Fatalf("%s: %v", r.Operation, err)
		}
		body, err := simXMLEncode(doc)
		if err != nil {
			t.Fatalf("%s: %v", r.Operation, err)
		}
		out[i].Body = body
		out[i].Header = r.Header.Clone()
		out[i].Header.Del(simXMLHeader)
	}
	return out
}

// simDriven are the operations the simulator answers from the roster. It
// answers the rest with the recording's answers.
var simDriven = map[string]bool{
	"aws.sts.GetCallerIdentity":              true,
	"aws.iam.GetCredentialReport":            true,
	"aws.iam.GetAccountSummary":              true,
	"aws.iam.ListMFADevices":                 true,
	"aws.iam.ListSAMLProviders":              true,
	"aws.iam.ListAttachedUserPolicies":       true,
	"aws.iam.ListUserPolicies":               true,
	"aws.iam.ListGroupsForUser":              true,
	"aws.iam.ListAttachedGroupPolicies":      true,
	"aws.iam.ListGroupPolicies":              true,
	"aws.identitystore.ListUsers":            true,
	"aws.identitystore.ListGroups":           true,
	"aws.identitystore.ListGroupMemberships": true,
	"aws.s3.ListBuckets":                     true,
	"aws.s3.GetBucketLocation":               true,
	"aws.s3.GetPublicAccessBlock":            true,
	"aws.s3.GetBucketEncryption":             true,
	"aws.ec2.DescribeSecurityGroups":         true,
	"aws.cloudtrail.DescribeTrails":          true,
	"aws.cloudtrail.GetTrailStatus":          true,
	"aws.rds.DescribeDBInstances":            true,
	"aws.kms.ListKeys":                       true,
	"aws.kms.DescribeKey":                    true,
	"aws.kms.GetKeyRotationStatus":           true,
	// Identity Center's roles, which the collector lists under their own
	// path. The recording answers the full role listing.
	"aws.iam.ListRoles/" + identityCenterRolePath: true,
}

const (
	simIAMNamespace = "https://iam.amazonaws.com/doc/2010-05-08/"
	simIAMURL       = "https://iam.amazonaws.com/?"
)

// awsSim answers every call a run makes for the roster's one cloud
// account, at now. The account's ID stands in for the recording's, in its
// answers' URLs, requests and bodies as well. A call the roster doesn't
// drive gets the recording's answer, and the ones it drives come first, so
// a narrower request, such as Identity Center's role listing, gets its own
// answer before the recording's broader one.
type awsSim struct {
	r       *roster.Roster
	rec     *simRecording
	now     time.Time
	account *roster.CloudAccount
	out     []collectortest.Response
}

func newAWSSim(t testing.TB, r *roster.Roster, rec *simRecording, now time.Time) []collectortest.Response {
	t.Helper()
	if r.Cloud == nil || len(r.Cloud.Accounts) != 1 {
		t.Fatal("the AWS simulator answers for a roster with one cloud account")
	}
	s := &awsSim{r: r, rec: rec, now: now, account: &r.Cloud.Accounts[0]}
	s.signIn()
	s.iam()
	s.identityCenter()
	s.s3()
	s.securityGroups()
	s.cloudTrail()
	s.rds()
	s.kms()
	for _, resp := range rec.responses {
		if simDriven[resp.Operation] || simDriven[resp.Operation+"/"+simPathPrefix(resp)] {
			continue
		}
		s.out = append(s.out, s.rewrite(resp))
	}
	return s.out
}

func simPathPrefix(r collectortest.Response) string {
	var body map[string]any
	_ = json.Unmarshal([]byte(r.RequestBody), &body)
	prefix, _ := body["PathPrefix"].(string)
	return prefix
}

// rewrite gives a recorded answer the roster's account ID.
func (s *awsSim) rewrite(r collectortest.Response) collectortest.Response {
	swap := func(v string) string { return strings.ReplaceAll(v, kitAccountID, s.account.ID) }
	r.URL, r.RequestBody, r.Body = swap(r.URL), swap(r.RequestBody), swap(r.Body)
	return r
}

// recorded returns a copy of a recorded answer to op, with the roster's
// account ID, and its body in the JSON form or as JSON: the first the first
// pick accepts, else the first the next pick accepts, and so on. A nil pick
// accepts every answer.
func (s *awsSim) recorded(op string, picks ...func(collectortest.Response) bool) (collectortest.Response, map[string]any) {
	if len(picks) == 0 {
		picks = append(picks, nil)
	}
	for _, pick := range picks {
		for _, r := range s.rec.responses {
			if r.Operation != op || (pick != nil && !pick(s.rewrite(r))) {
				continue
			}
			r = s.rewrite(r)
			var body map[string]any
			if err := json.Unmarshal([]byte(r.Body), &body); err != nil {
				panic(fmt.Sprintf("simulator: %s's recorded body is not an object: %v", op, err))
			}
			return r, body
		}
	}
	panic("simulator: the recording holds no answer to " + op)
}

func (s *awsSim) add(r collectortest.Response, body map[string]any) {
	if r.Header.Get(simXMLHeader) != "" {
		r.Body = simXMLBody(body)
	} else {
		r.Body = simJSON(body)
	}
	s.out = append(s.out, r)
}

// simFirst follows path through a body, taking the first element of each
// list on the way, and returns the object it ends at.
func simFirst(body map[string]any, path ...string) map[string]any {
	node := any(body)
	for _, name := range path {
		m, ok := node.(map[string]any)
		if !ok {
			panic("simulator: no object above " + name)
		}
		node = m[name]
		if list, ok := node.([]any); ok && len(list) > 0 {
			node = list[0]
		}
	}
	m, ok := node.(map[string]any)
	if !ok {
		panic(fmt.Sprintf("simulator: %v holds no object", path))
	}
	return m
}

// simItems returns copies of the items of the list at path, its last name
// the items' own.
func simItems(body map[string]any, path ...string) []map[string]any {
	parent := simFirst(body, path[:len(path)-1]...)
	list, _ := parent[path[len(path)-1]].([]any)
	var out []map[string]any
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, simCopy(m))
		}
	}
	return out
}

// simPick returns a copy of the first item whose field holds value, and
// true, or of the first item and false. A recorded resource the roster
// still has keeps its IDs, dates and settings the roster has no term for,
// and another is built from the first.
func simPick(items []map[string]any, field, value string) (map[string]any, bool) {
	for _, item := range items {
		if simText(item[field]) == value {
			return simCopy(item), true
		}
	}
	return simCopy(items[0]), false
}

// simText is a field's text, in the JSON form or as JSON.
func simText(v any) string {
	if list, ok := v.([]any); ok && len(list) > 0 {
		v = list[0]
	}
	s, _ := v.(string)
	return s
}

func simNonNil(items []any) []any {
	if items == nil {
		return []any{}
	}
	return items
}

func simCopy(m map[string]any) map[string]any {
	var out map[string]any
	if err := json.Unmarshal([]byte(simJSON(m)), &out); err != nil {
		panic(err)
	}
	return out
}

// simList is a list element in the JSON form: an empty element for no
// items, as AWS sends one.
func simList(member string, items []any) any {
	if len(items) == 0 {
		return ""
	}
	return map[string]any{member: items}
}

// simQuery answers a Query protocol call of op with result, for the calls
// whose form body holds request.
func simQuery(op, endpoint, namespace string, request map[string]any, result map[string]any) (collectortest.Response, map[string]any) {
	action := actionOf(op)
	fields := map[string]any{"Action": action}
	maps.Copy(fields, request)
	r := collectortest.Response{
		Operation: op, Method: http.MethodPost, URL: endpoint, RequestBody: simJSON(fields),
		Header: simWithXMLMark(http.Header{"Content-Type": []string{"text/xml"}}),
	}
	body := map[string]any{action + "Response": map[string]any{
		"@xmlns": namespace, action + "Result": result,
		"ResponseMetadata": map[string]any{"RequestId": simulate.UUID("request", op+simJSON(request))},
	}}
	return r, body
}

func (s *awsSim) days(n int) string { return s.now.AddDate(0, 0, -n).UTC().Format(time.RFC3339) }

// regions are the regions the run scans, the config's, and home is the
// first of them, where a resource with no region extra is.
func (s *awsSim) regions() []string {
	var out []string
	for _, v := range s.rec.config["regions"].([]any) {
		out = append(out, v.(string))
	}
	return out
}

func (s *awsSim) home() string { return s.regions()[0] }

// regionOf is the region extra of an entry, or home.
func (s *awsSim) regionOf(e roster.Extra) string {
	region := s.home()
	simulate.Extra(e, "region", &region)
	return region
}

func (s *awsSim) signIn() {
	r, body := s.recorded("aws.sts.GetCallerIdentity", nil)
	result := simFirst(body, "GetCallerIdentityResponse", "GetCallerIdentityResult")
	result["Account"] = s.account.ID
	s.add(r, body)
}

// iamUsers are the account's IAM users, every local account of it but the
// root user, in the roster's order.
func (s *awsSim) iamUsers() []roster.Account {
	var out []roster.Account
	for _, a := range s.r.Accounts {
		if a.CloudAccount == s.account.Key && s.r.Terms.AccountKinds[a.Kind] != roster.KindRoot {
			out = append(out, a)
		}
	}
	return out
}

func (s *awsSim) root() (roster.Account, bool) {
	for _, a := range s.r.Accounts {
		if a.CloudAccount == s.account.Key && s.r.Terms.AccountKinds[a.Kind] == roster.KindRoot {
			return a, true
		}
	}
	return roster.Account{}, false
}

func (s *awsSim) hasMFA(a roster.Account) bool { return s.r.MFAClass(a) != roster.MFANone }

// hasPassword reports whether a signs in with a password: a login the
// roster's terms map to local.
func (s *awsSim) hasPassword(a roster.Account) bool {
	return slices.ContainsFunc(a.Logins, func(l string) bool { return s.r.Terms.LoginMethods[l] == roster.LoginLocal })
}

// keysOf are an account's access keys, the credentials it owns, at most
// two as IAM allows.
func (s *awsSim) keysOf(owner string) []roster.MachineCredential {
	var out []roster.MachineCredential
	for _, m := range s.r.Cloud.Credentials {
		if m.Owner == owner {
			out = append(out, m)
		}
	}
	if len(out) > 2 {
		panic("simulator: IAM user " + owner + " holds more than two access keys")
	}
	return out
}

// simReportHeader is the credential report's header, as IAM writes it.
var simReportHeader = []string{
	"user", "arn", "user_creation_time", "password_enabled", "password_last_used", "password_last_changed", "password_next_rotation",
	"mfa_active", "access_key_1_active", "access_key_1_last_rotated", "access_key_1_last_used_date", "access_key_1_last_used_region",
	"access_key_1_last_used_service", "access_key_2_active", "access_key_2_last_rotated", "access_key_2_last_used_date",
	"access_key_2_last_used_region", "access_key_2_last_used_service", "cert_1_active", "cert_1_last_rotated", "cert_2_active", "cert_2_last_rotated",
}

// credentialReport is the account's credential report: the root user's
// row, then one for each IAM user. A user's password is last used when it
// last signed in, and each of its access keys was last rotated when it was
// made. IAM marks a never-used password no_information and a value that
// doesn't apply N/A. Root's password never needs rotating, so its next
// rotation is not_supported.
func (s *awsSim) credentialReport() string {
	var rows [][]string
	created := s.days(400)
	row := func(name, arn string, password, mfa bool, signedIn *int, keys []roster.MachineCredential) []string {
		passwordEnabled, lastUsed, changed := "false", "N/A", "N/A"
		if password {
			passwordEnabled, lastUsed, changed = "true", "no_information", created
			if signedIn != nil {
				lastUsed = s.days(*signedIn)
			}
		}
		out := []string{name, arn, created, passwordEnabled, lastUsed, changed, "N/A", strconv.FormatBool(mfa)}
		for i := range 2 {
			if i >= len(keys) {
				out = append(out, "false", "N/A", "N/A", "N/A", "N/A")
				continue
			}
			k := keys[i]
			rotated, used, region, service := created, "N/A", "N/A", "N/A"
			if k.CreatedDaysAgo != nil {
				rotated = s.days(*k.CreatedDaysAgo)
			}
			if k.LastUsedDaysAgo != nil {
				used, region, service = s.days(*k.LastUsedDaysAgo), s.home(), "sts"
			}
			out = append(out, strconv.FormatBool(k.Active), rotated, used, region, service)
		}
		return append(out, "false", "N/A", "false", "N/A")
	}
	if root, ok := s.root(); ok {
		r := row("<root_account>", "arn:aws:iam::"+s.account.ID+":root", s.hasPassword(root), s.hasMFA(root), root.SignedInDaysAgo, s.keysOf(root.Key))
		r[6] = "not_supported"
		rows = append(rows, r)
	}
	for _, a := range s.iamUsers() {
		rows = append(rows, row(a.Key, s.userARN(a.Key), s.hasPassword(a), s.hasMFA(a), a.SignedInDaysAgo, s.keysOf(a.Key)))
	}
	var b strings.Builder
	b.WriteString(strings.Join(simReportHeader, ","))
	for _, r := range rows {
		b.WriteString("\n" + strings.Join(r, ","))
	}
	return b.String()
}

func (s *awsSim) userARN(name string) string { return "arn:aws:iam::" + s.account.ID + ":user/" + name }

// iam answers the credential report, the account summary, the IAM users'
// MFA devices and policies, and the SAML providers and Identity Center
// roles the account's identity providers make.
func (s *awsSim) iam() {
	r, body := s.recorded("aws.iam.GetCredentialReport", nil)
	result := simFirst(body, "GetCredentialReportResponse", "GetCredentialReportResult")
	result["GeneratedTime"] = s.now.UTC().Format(time.RFC3339)
	result["Content"] = base64.StdEncoding.EncodeToString([]byte(s.credentialReport()))
	s.add(r, body)

	r, body = s.recorded("aws.iam.GetAccountSummary", nil)
	root, hasRoot := s.root()
	users := s.iamUsers()
	flag := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}
	mfaDevices := 0
	if hasRoot && s.hasMFA(root) {
		mfaDevices++
	}
	for _, a := range users {
		if s.hasMFA(a) {
			mfaDevices++
		}
	}
	summary := map[string]string{
		"Users":                             strconv.Itoa(len(users)),
		"MFADevicesInUse":                   strconv.Itoa(mfaDevices),
		"AccountMFAEnabled":                 flag(hasRoot && s.hasMFA(root)),
		"AccountPasswordPresent":            flag(hasRoot && s.hasPassword(root)),
		"AccountAccessKeysPresent":          flag(hasRoot && slices.ContainsFunc(s.keysOf(root.Key), func(m roster.MachineCredential) bool { return m.Active })),
		"AccountSigningCertificatesPresent": "0",
	}
	for _, entry := range simFirst(body, "GetAccountSummaryResponse", "GetAccountSummaryResult", "SummaryMap")["entry"].([]any) {
		e := entry.(map[string]any)
		if v, ok := summary[e["key"].([]any)[0].(string)]; ok {
			e["value"] = []any{v}
		}
	}
	s.add(r, body)

	for _, a := range users {
		if !s.hasMFA(a) {
			continue
		}
		r, body := s.recorded("aws.iam.ListMFADevices", func(r collectortest.Response) bool {
			return strings.Contains(r.RequestBody, `"UserName":"`+a.Key+`"`)
		}, nil)
		r.RequestBody = simJSON(map[string]any{"Action": "ListMFADevices", "UserName": a.Key, "Version": "2010-05-08"})
		device := simFirst(body, "ListMFADevicesResponse", "ListMFADevicesResult", "MFADevices", "member")
		if simText(device["UserName"]) != a.Key || simText(device["SerialNumber"]) != s.mfaSerial(a) {
			device["UserName"], device["SerialNumber"], device["EnableDate"] = a.Key, s.mfaSerial(a), s.days(30)
		}
		s.add(r, body)
	}

	s.policies(users)
	s.signInPaths()
}

// mfaSerial is an IAM user's MFA device serial: a FIDO security key's ARN
// for phishing-resistant MFA, a hardware token's serial for a method named
// hardware, and a virtual device's ARN otherwise, as IAM names each.
func (s *awsSim) mfaSerial(a roster.Account) string {
	switch {
	case s.r.MFAClass(a) == roster.MFAPhishingResistant:
		return "arn:aws:iam::" + s.account.ID + ":u2f/user/" + a.Key + "/security-key-" + simulate.Base62("", 26, "u2f", a.Key)
	case slices.ContainsFunc(a.Methods, func(m string) bool { return strings.Contains(m, "hardware") }):
		return "GAHT" + simulate.Base62("", 8, "token", a.Key)
	}
	return "arn:aws:iam::" + s.account.ID + ":mfa/" + a.Key
}

// iamGroups are the roster's groups that hold IAM users. A group whose
// members are directory accounts is an Identity Center group.
func (s *awsSim) iamGroups() []roster.Group {
	local := map[string]bool{}
	for _, a := range s.iamUsers() {
		local[a.Key] = true
	}
	var out []roster.Group
	for _, g := range s.r.Groups {
		if slices.ContainsFunc(g.Members, func(m string) bool { return local[m] }) {
			out = append(out, g)
		}
	}
	return out
}

// simPolicyARN is the ARN of an IAM managed policy, a cloud role in the
// roster: AWS managed unless the entry's customer_policies extra names it.
func (s *awsSim) simPolicyARN(name string, e roster.Extra) string {
	var customer []string
	simulate.Extra(e, "customer_policies", &customer)
	if slices.Contains(customer, name) {
		return "arn:aws:iam::" + s.account.ID + ":policy/" + name
	}
	return "arn:aws:iam::aws:policy/" + name
}

// policies answers the policy reads of the IAM users with a password,
// whom the collector checks for administrator access. A user's or group's
// cloud roles are its attached managed policies, and its inline_policies
// extra names its inline policies. The groups are those that hold IAM
// users.
func (s *awsSim) policies(users []roster.Account) {
	attached := func(op, field, name string, roles []string, e roster.Extra) {
		var items []any
		for _, role := range roles {
			items = append(items, map[string]any{"PolicyName": role, "PolicyArn": s.simPolicyARN(role, e)})
		}
		r, body := simQuery(op, simIAMURL, simIAMNamespace, map[string]any{field: name},
			map[string]any{"IsTruncated": "false", "AttachedPolicies": simList("member", items)})
		s.add(r, body)
	}
	inline := func(op, field, name string, e roster.Extra) {
		var names []string
		simulate.Extra(e, "inline_policies", &names)
		r, body := simQuery(op, simIAMURL, simIAMNamespace, map[string]any{field: name},
			map[string]any{"IsTruncated": "false", "PolicyNames": simList("member", simulate.Each(names, func(n string) any { return n }))})
		s.add(r, body)
	}
	groups := s.iamGroups()
	for _, a := range users {
		if !s.hasPassword(a) {
			continue
		}
		attached("aws.iam.ListAttachedUserPolicies", "UserName", a.Key, a.CloudRoles, a.Extra)
		inline("aws.iam.ListUserPolicies", "UserName", a.Key, a.Extra)
		var items []any
		for _, g := range groups {
			if slices.Contains(g.Members, a.Key) {
				items = append(items, map[string]any{
					"Path": "/", "GroupName": g.Key, "GroupId": "AGPA" + simulate.Base62("", 17, "group", g.Key),
					"Arn": "arn:aws:iam::" + s.account.ID + ":group/" + g.Key, "CreateDate": s.days(400),
				})
			}
		}
		r, body := simQuery("aws.iam.ListGroupsForUser", simIAMURL, simIAMNamespace, map[string]any{"UserName": a.Key},
			map[string]any{"IsTruncated": "false", "Groups": simList("member", items)})
		s.add(r, body)
	}
	for _, g := range groups {
		if !slices.ContainsFunc(users, func(a roster.Account) bool { return s.hasPassword(a) && slices.Contains(g.Members, a.Key) }) {
			continue
		}
		attached("aws.iam.ListAttachedGroupPolicies", "GroupName", g.Key, g.CloudRoles, g.Extra)
		inline("aws.iam.ListGroupPolicies", "GroupName", g.Key, g.Extra)
	}
}

// signInPaths answers the SAML providers the account trusts and the roles
// Identity Center makes in it. A saml identity provider is a SAML provider
// named by its key. A workforce one, which IAM Identity Center makes when
// it gives people access to the account, adds its AWSSSO_ SAML provider
// and an AWSReservedSSO_ role.
func (s *awsSim) signInPaths() {
	var providers, roles []any
	for _, p := range s.account.IdentityProviders {
		name := p.Key
		switch s.r.Terms.CloudIdentityProviders[p.Kind] {
		case roster.IdPWorkforce:
			name = "AWSSSO_" + simulate.Base62("", 16, "sso", p.Key) + "_DO_NOT_DELETE"
			roleName := identityCenterRolePrefix + "AdministratorAccess_" + simulate.Base62("", 16, "sso-role", p.Key)
			roles = append(roles, map[string]any{
				"Path": identityCenterRolePath, "RoleName": roleName, "RoleId": "AROA" + simulate.Base62("", 17, "role", p.Key),
				"Arn":        "arn:aws:iam::" + s.account.ID + ":role" + identityCenterRolePath + roleName,
				"CreateDate": s.days(30), "MaxSessionDuration": "43200",
				"AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%7D",
			})
		case roster.IdPSAML:
		default:
			continue
		}
		providers = append(providers, map[string]any{
			"Arn": "arn:aws:iam::" + s.account.ID + ":saml-provider/" + name, "ValidUntil": "2126-01-01T00:00:00Z", "CreateDate": s.days(30),
		})
	}
	r, body := s.recorded("aws.iam.ListSAMLProviders", nil)
	simFirst(body, "ListSAMLProvidersResponse", "ListSAMLProvidersResult")["SAMLProviderList"] = simList("member", providers)
	s.add(r, body)

	r, body = s.recorded("aws.iam.ListRoles", func(r collectortest.Response) bool { return simPathPrefix(r) == identityCenterRolePath })
	simFirst(body, "ListRolesResponse", "ListRolesResult")["Roles"] = simList("member", roles)
	s.add(r, body)
}

// directory are the people in Identity Center's directory: the enabled
// accounts that are no cloud account's own, in the roster's order.
func (s *awsSim) directory() []roster.Account {
	var out []roster.Account
	for _, a := range s.r.Accounts {
		if a.CloudAccount == "" && a.Enabled {
			out = append(out, a)
		}
	}
	return out
}

// identityCenter answers the directory of the account's Identity Center
// instance, which the recording's ListInstances names: its users, its
// groups and their members. A user's external_id extra is the ID an
// identity provider's SCIM provisioning gave it.
func (s *awsSim) identityCenter() {
	people := s.directory()
	ids := map[string]string{}
	userResp, users := s.recorded("aws.identitystore.ListUsers", nil)
	recordedUsers := simItems(users, "Users")
	var items []any
	for _, a := range people {
		u, recorded := simPick(recordedUsers, "UserName", a.Key)
		id, _ := u["UserId"].(string)
		if !recorded {
			id = simulate.UUID("idc-user", a.Key)
			u["UserId"], u["UserName"], u["DisplayName"] = id, a.Key, a.Key
			u["UserArn"] = "arn:aws:identitystore:::user/" + id
			u["Emails"] = []any{map[string]any{"Primary": true, "Value": a.Key + "@example.com"}}
		}
		ids[a.Key] = id
		delete(u, "ExternalIds")
		var external string
		simulate.Extra(a.Extra, "external_id", &external)
		if external != "" {
			u["ExternalIds"] = []any{map[string]any{"Issuer": "https://scim.example.com", "Id": external}}
		}
		items = append(items, u)
	}
	users["Users"] = simNonNil(items)
	s.add(userResp, users)

	groupResp, groups := s.recorded("aws.identitystore.ListGroups", nil)
	recordedGroups := simItems(groups, "Groups")
	memberResp, memberships := s.recorded("aws.identitystore.ListGroupMemberships", nil)
	recordedMemberships := simItems(memberships, "GroupMemberships")
	var groupItems []any
	for _, g := range s.r.Groups {
		if !slices.ContainsFunc(g.Members, func(m string) bool { return ids[m] != "" }) {
			continue
		}
		item, recorded := simPick(recordedGroups, "DisplayName", g.Key)
		id, _ := item["GroupId"].(string)
		if !recorded {
			id = simulate.UUID("idc-group", g.Key)
			item["GroupId"], item["DisplayName"], item["GroupArn"] = id, g.Key, "arn:aws:identitystore:::group/"+id
		}
		groupItems = append(groupItems, item)

		var members []any
		for _, m := range g.Members {
			if ids[m] == "" {
				continue
			}
			ms := simCopy(recordedMemberships[0])
			for _, rm := range recordedMemberships {
				if who, _ := rm["MemberId"].(map[string]any); rm["GroupId"] == id && who["UserId"] == ids[m] {
					ms = simCopy(rm)
				}
			}
			if who, _ := ms["MemberId"].(map[string]any); ms["GroupId"] != id || who["UserId"] != ids[m] {
				mid := simulate.UUID("idc-membership", g.Key+"/"+m)
				ms["GroupId"], ms["MemberId"], ms["MembershipId"] = id, map[string]any{"UserId": ids[m]}, mid
				ms["MembershipArn"] = "arn:aws:identitystore:::membership/" + mid
			}
			members = append(members, ms)
		}
		r := memberResp
		var request map[string]any
		_ = json.Unmarshal([]byte(r.RequestBody), &request)
		request["GroupId"] = id
		r.RequestBody = simJSON(request)
		s.add(r, map[string]any{"GroupMemberships": simNonNil(members)})
	}
	groups["Groups"] = simNonNil(groupItems)
	s.add(groupResp, groups)
}

// simConfig runs the collector as the sandbox's recording does, at the
// audit level over its two regions, as the role in the roster's account.
func simConfig(rec *simRecording, accountID string) map[string]any {
	config := maps.Clone(rec.config)
	config["role_arn"] = strings.ReplaceAll(config["role_arn"].(string), kitAccountID, accountID)
	return config
}

// simArtifacts are the normalized artifacts Derive gives values for. The
// sandbox roster has no scanning block, so vuln-scanning has none.
var simArtifacts = []simulate.Artifact{
	{Schema: roster.CloudPosture, Path: cloudPosturePath},
	{Schema: roster.AccessPosture, Prefix: "access-posture:", Path: accessPosturePath},
}

// simHarness runs the collector against the simulated account and checks
// each answer's shape against the sandbox's recording, at the time the
// recording was made.
func simHarness(t *testing.T, standing simulate.Differences) simulate.Harness {
	isolateAWSEnvironment(t)
	rec := loadSimRecording(t)
	var config map[string]any
	return simulate.Harness{
		Simulate: func(r *roster.Roster, _ int) []collectortest.Response {
			config = simConfig(rec, r.Cloud.Accounts[0].ID)
			return newAWSSim(t, r, rec, rec.at)
		},
		Collect: func(t *testing.T, responses []collectortest.Response) componentsdk.InProcessResult {
			return simulate.InProcess(t, Spec("test", "simulator"), Run, componentsdk.InProcessOptions{
				Config: config, Secrets: kitSecrets(), Clock: func() time.Time { return rec.at },
			}, simWriteXML(t, responses))
		},
		Artifacts:  simArtifacts,
		Standing:   standing,
		Recorded:   rec.shapes,
		Unrecorded: simUnrecorded,
		Coverage:   true,
		Uncompared: simUncompared,
	}
}
