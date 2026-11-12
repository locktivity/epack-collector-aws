package collector

import (
	"errors"
	"fmt"

	"github.com/locktivity/epack/componentsdk"
)

// AccessPosture is the evidencepack/access-posture@v1 artifact for every
// account collected. The sections hold totals across the accounts, and from
// the audit level scopes holds each account alone. Members are the IAM users
// with a console password in each account's credential report, and the
// users of the organization's IAM Identity Center. Admins are the IAM users
// with an AWS managed policy in adminPolicies. Credentials are the IAM
// users' active access keys. A value left out has a gap, and the counts and
// scopes are written from the audit level only.
type AccessPosture struct {
	SchemaVersion string            `json:"schema_version"`
	CollectedAt   string            `json:"collected_at"`
	Provider      string            `json:"provider"`
	SystemType    string            `json:"system_type"`
	SignIn        AccessSignIn      `json:"sign_in,omitzero"`
	Members       AccessMembers     `json:"members,omitzero"`
	Admins        AccessAdmins      `json:"admins,omitzero"`
	Root          AccessRoot        `json:"root,omitzero"`
	Credentials   AccessCredentials `json:"credentials,omitzero"`
	Scopes        []AccessScope     `json:"scopes,omitempty"`
}

// AccessSignIn is how people sign in. AWS has no setting that requires SSO
// or MFA for everyone, so only sso_configured is written.
type AccessSignIn struct {
	SSOConfigured *bool `json:"sso_configured,omitempty"`
}

// AccessMembers counts the IAM users with a console password and the
// Identity Center users. Every such IAM user signs in without SSO, so the
// local values count them.
type AccessMembers struct {
	MembersPresent      *bool            `json:"members_present,omitempty"`
	MemberCount         *int             `json:"member_count,omitempty"`
	SSOMemberCount      *int             `json:"sso_member_count,omitempty"`
	SSOCoveragePct      Reading[float64] `json:"sso_coverage_pct,omitzero"`
	LocalMembersPresent *bool            `json:"local_members_present,omitempty"`
	LocalMemberCount    *int             `json:"local_member_count,omitempty"`
	LocalMFAMemberCount *int             `json:"local_mfa_member_count,omitempty"`
	LocalMFACoveragePct Reading[float64] `json:"local_mfa_coverage_pct,omitzero"`
	InactiveMemberCount *int             `json:"inactive_member_count,omitempty"`
	InactivePct         Reading[float64] `json:"inactive_pct,omitzero"`
}

// AccessAdmins counts the IAM users with a policy in adminPolicies. The
// admin count over every member is left out when Identity Center has users,
// since who of them administers an account is not read.
type AccessAdmins struct {
	AdminsPresent            *bool            `json:"admins_present,omitempty"`
	AdminCount               *int             `json:"admin_count,omitempty"`
	AdminSharePct            Reading[float64] `json:"admin_share_pct,omitzero"`
	LocalAdminsPresent       *bool            `json:"local_admins_present,omitempty"`
	LocalAdminCount          *int             `json:"local_admin_count,omitempty"`
	LocalMFAAdminCount       *int             `json:"local_mfa_admin_count,omitempty"`
	LocalAdminMFACoveragePct Reading[float64] `json:"local_admin_mfa_coverage_pct,omitzero"`
}

// AccessRoot describes each account's root user.
type AccessRoot struct {
	RootAccountsPresent   *bool            `json:"root_accounts_present,omitempty"`
	RootAccountCount      *int             `json:"root_account_count,omitempty"`
	RootMFAAccountCount   *int             `json:"root_mfa_account_count,omitempty"`
	RootMFACoveragePct    Reading[float64] `json:"root_mfa_coverage_pct,omitzero"`
	RootAccessKeysPresent *bool            `json:"root_access_keys_present,omitempty"`
}

// AccessCredentials counts the IAM users' active access keys.
type AccessCredentials struct {
	CredentialsPresent             *bool            `json:"credentials_present,omitempty"`
	CredentialCount                *int             `json:"credential_count,omitempty"`
	NeverExpiringCredentialCount   *int             `json:"never_expiring_credential_count,omitempty"`
	NeverExpiringPct               Reading[float64] `json:"never_expiring_pct,omitzero"`
	UnusedCredentialCount          *int             `json:"unused_credential_count,omitempty"`
	UnusedPct                      Reading[float64] `json:"unused_pct,omitzero"`
	RotationOverdueCredentialCount *int             `json:"rotation_overdue_credential_count,omitempty"`
	RotationOverduePct             Reading[float64] `json:"rotation_overdue_pct,omitzero"`
}

// AccessScope is one account's own sections, written from the audit level.
type AccessScope struct {
	ID          string            `json:"id"`
	Name        string            `json:"name,omitempty"`
	Kind        string            `json:"kind"`
	SignIn      AccessSignIn      `json:"sign_in,omitzero"`
	Members     AccessMembers     `json:"members,omitzero"`
	Admins      AccessAdmins      `json:"admins,omitzero"`
	Root        AccessRoot        `json:"root,omitzero"`
	Credentials AccessCredentials `json:"credentials,omitzero"`
}

// The reasons for the access-posture values AWS never reports, and for the
// ones it reports that this collector does not read.
var (
	ssoRequiredUnsupported        = unsupported("AWS has no account setting to require SSO for everyone who signs in.")
	mfaRequiredUnsupported        = unsupported("AWS has no account setting to require MFA for everyone who signs in.")
	scimUnsupported               = unsupported("Whether IAM Identity Center users are provisioned through SCIM is not available from the AWS API.")
	externalMembersUnsupported    = unsupported("IAM has no guest or outside users. People from other accounts get access through roles.")
	identityCenterAdminsNotRead   = notRead("Which Identity Center users can administer an account depends on the policies of the permission sets ListAccountAssignments assigns them, which this collector does not evaluate.")
	identityCenterInactiveNotRead = notRead("When Identity Center users last signed in is in CloudTrail's sign-in events, which this collector does not read.")
	scopeSSOMembersNotRead        = notRead("Who is assigned to each account is listed with ListAccountAssignments from the account that holds the organization's Identity Center instance, and no account collected read them.")
	unrestrictedKeysNotRead       = notRead("An access key's IP and scope limits are in its user's policy documents, from GetUserPolicy and GetPolicyVersion, which this collector does not read.")
	writeAccessKeysNotRead        = notRead("What an access key can change is in its user's policy documents, from GetUserPolicy and GetPolicyVersion, which this collector does not read.")
	connectedAppsNotRead          = notRead("Third-party access goes through IAM roles that trust other accounts, from ListRoles, and Identity Center applications, from ListApplications. This collector does not count them as connected apps.")
	unreadDirectoryNotRead        = notRead("The organization's Identity Center users are listed with ListUsers from the account that holds the instance or a delegated administrator, and no account collected is one.")
	accessPostureLeftOut          = []struct {
		why      *reason
		audit    bool
		pointers []string
	}{
		{ssoRequiredUnsupported, false, []string{"sign_in/sso_required"}},
		{mfaRequiredUnsupported, false, []string{"sign_in/mfa_required"}},
		{scimUnsupported, false, []string{"sign_in/scim_enabled"}},
		{externalMembersUnsupported, false, []string{"members/external_members_present"}},
		{externalMembersUnsupported, true, []string{"members/external_member_count"}},
		{unrestrictedKeysNotRead, false, []string{"credentials/unrestricted_pct"}},
		{unrestrictedKeysNotRead, true, []string{"credentials/unrestricted_credential_count"}},
		{writeAccessKeysNotRead, false, []string{"credentials/write_access_pct"}},
		{writeAccessKeysNotRead, true, []string{"credentials/write_access_credential_count"}},
	}
)

// signal is what one account's evidence shows of a fact: that it holds, that
// it does not, or neither, because a read failed.
type signal int

const (
	signalNo signal = iota
	signalYes
	signalUnknown
)

// identityCenterInstanceSignal says whether an account's instance listing
// found an active organization instance. An account instance or an instance
// in another status does not count. It is unknown, with the detailed value
// whose gap says why, when the instance's type could not be read or the
// listing failed in a region an instance could be in. It is unknown as well
// when a gap covers enabled, such as when the config lists the regions and
// none of them has an instance.
func identityCenterInstanceSignal(acct AccountPosture, at at, gaps *gapLog) (signal, string) {
	idc := acct.IdentityCenter
	active := idc.Enabled && idc.InstanceStatus == identityCenterActive
	enabled := at.p("identity_center", "enabled")
	switch {
	case active && idc.InstanceType == identityCenterOrganizationInstance:
		return signalYes, ""
	case active && idc.InstanceType == "":
		return signalUnknown, at.p("identity_center", "instance_type")
	case len(acct.Regions) == 0 || len(idc.RegionsChecked) < len(acct.Regions) || gaps.covered(enabled):
		return signalUnknown, enabled
	}
	return signalNo, ""
}

// accountAccess is one account's access evidence, folded from its detailed
// values and the admin check. members are the IAM users with a console
// password, who sign in without SSO, and localAdmins the admins among them.
// people are every member, Identity Center users included, and admins every
// admin. addPeople sets people and admins, and inactive over people.
type accountAccess struct {
	ssoConfigured truth

	members, localMFA, inactive count
	membersPresent              truth
	people                      count
	peoplePresent               truth

	admins, localAdmins, adminMFA     count
	adminsPresent, localAdminsPresent truth

	rootAccounts, rootMFA count
	rootPresent, rootKeys truth

	keys, unusedKeys, overdueKeys count
	keysPresent                   truth
}

// failedAccess is a failed account's evidence, every value unknown because
// of err.
func failedAccess(err error) accountAccess {
	why := &reason{err: err}
	c, t := count{why: why}, truth{why: why}
	return accountAccess{
		ssoConfigured: t, members: c, localMFA: c, inactive: c, membersPresent: t,
		localAdmins: c, adminMFA: c, localAdminsPresent: t,
		rootAccounts: c, rootMFA: c, rootPresent: t, rootKeys: t,
		keys: c, unusedKeys: c, overdueKeys: c, keysPresent: t,
	}
}

// accessOf folds account i's evidence. A value whose detailed source a gap
// covers is unknown, with that gap.
func accessOf(acct AccountPosture, i int, gaps *gapLog) accountAccess {
	at := accountAt(i)
	iam := acct.IAM
	users := at.p("iam", "iam_user_count")
	keys := at.p("iam", "access_key_user_count")
	a := accountAccess{
		ssoConfigured: ssoConfiguredOf(acct, at, gaps),
		members:       countAt(gaps, users, iam.usage.consoleUsers),
		localMFA:      countAt(gaps, at.p("iam", "mfa_enabled_user_count"), iam.usage.consoleMFAUsers),
		inactive:      countAt(gaps, users, iam.usage.consoleInactiveUsers),
		rootAccounts:  count{n: 1},
		rootMFA:       rootMFAOf(iam, at, gaps),
		rootKeys:      truthAt(gaps, at.p("iam", "root_access_keys_exist"), iam.RootAccessKeysExist),
		keys:          countAt(gaps, keys, iam.usage.activeKeys),
		unusedKeys:    countAt(gaps, keys, iam.usage.unusedKeys),
		overdueKeys:   countAt(gaps, keys, iam.usage.rotationOverdueKeys),
	}
	a.localAdmins, a.adminMFA, a.localAdminsPresent = adminsOf(acct.admins, a.members)
	a.membersPresent = presentIn(a.members)
	a.rootPresent = presentIn(a.rootAccounts)
	a.keysPresent = presentIn(a.keys)
	return a
}

// adminsOf folds the admin check. Without the credential report there were
// no users to check, so the admins are unknown for the members' reason. A
// user whose policies could not be read leaves the counts out with a
// partial gap, and admins_present is still true when another user is an
// admin.
func adminsOf(admins iamAdmins, members count) (count, count, truth) {
	switch {
	case members.why != nil:
		return members, members, truth{why: members.why}
	case !admins.read:
		why := &reason{err: fmt.Errorf("the IAM users' policies were not read")}
		return count{why: why}, count{why: why}, truth{why: why}
	case admins.unmeasured > 0:
		why := &reason{err: admins.err, unmeasured: admins.unmeasured}
		present := truth{why: why}
		if admins.admins > 0 {
			present = truth{v: true}
		}
		return count{why: why}, count{why: why}, present
	}
	return count{n: admins.admins}, count{n: admins.mfaAdmins}, truth{v: admins.admins > 0}
}

// rootMFAOf is 1 when the account's root user has MFA, or has no password,
// access key, or signing certificate to sign in with, and 0 otherwise.
func rootMFAOf(iam IAMMetrics, at at, gaps *gapLog) count {
	mfa := truthAt(gaps, at.p("iam", "root_mfa_enabled"), iam.RootMFAEnabled)
	switch {
	case mfa.why != nil:
		return count{why: mfa.why}
	case mfa.v:
		return count{n: 1}
	}
	credentials := truthAt(gaps, at.p("iam", "root_credentials_present"), iam.RootCredentialsPresent)
	switch {
	case credentials.why != nil:
		return count{why: credentials.why}
	case credentials.v:
		return count{n: 0}
	}
	return count{n: 1}
}

// ssoConfiguredOf is true when the account has an active organization
// instance of IAM Identity Center, an Identity Center role, or a SAML
// provider. It is false when every listing answered and found none.
func ssoConfiguredOf(acct AccountPosture, at at, gaps *gapLog) truth {
	signals := []truth{}
	switch instance, why := identityCenterInstanceSignal(acct, at, gaps); instance {
	case signalYes:
		return truth{v: true}
	case signalUnknown:
		signals = append(signals, truth{why: &reason{pointer: why}})
	}
	for _, c := range []struct {
		field string
		n     *int
	}{
		{"identity_center_role_count", acct.IAM.IdentityCenterRoleCount},
		{"identity_center_saml_provider_count", acct.IAM.IdentityCenterSAMLProviderCount},
		{"saml_provider_count", acct.IAM.SAMLProviderCount},
	} {
		if c.n == nil {
			signals = append(signals, truth{why: &reason{pointer: at.p("iam", c.field)}})
			continue
		}
		signals = append(signals, truth{v: *c.n > 0})
	}
	return anyOf(signals...)
}

// ssoMembersOf counts the users in the directories of the organization
// instances of IAM Identity Center that the accounts can read, each
// directory once. It is 0 when no account shows Identity Center in use.
// When Identity Center is in use, a directory that could not be read leaves
// the count unknown with its gap, and so does a failed instance listing
// when no account could read a directory. It also returns the identity
// stores of the directories it counted.
func ssoMembersOf(o *Output, gaps *gapLog) (count, []string) {
	type directory struct {
		users  int
		read   bool
		unread string
	}
	var (
		inUse                         bool
		instanceUnknown, rolesUnknown *reason
		stores                        []string
		directories                   = map[string]*directory{}
	)
	for i, acct := range o.Accounts {
		at := accountAt(i)
		idc := acct.IdentityCenter
		switch instance, why := identityCenterInstanceSignal(acct, at, gaps); instance {
		case signalYes:
			inUse = true
			d := directories[idc.identityStoreID]
			if d == nil {
				d = &directory{}
				directories[idc.identityStoreID] = d
				stores = append(stores, idc.identityStoreID)
			}
			switch {
			case d.read:
			case idc.MFAEvidence != "":
				d.read, d.users = true, idc.UserCount
			case d.unread == "":
				d.unread = at.p("identity_center", "user_count")
			}
		case signalUnknown:
			if instanceUnknown == nil {
				instanceUnknown = &reason{pointer: why}
			}
		}
		switch roles := acct.IAM.IdentityCenterRoleCount; {
		case roles == nil:
			if rolesUnknown == nil {
				rolesUnknown = &reason{pointer: at.p("iam", "identity_center_role_count")}
			}
		case *roles > 0:
			inUse = true
		}
		if providers := acct.IAM.IdentityCenterSAMLProviderCount; providers != nil && *providers > 0 {
			inUse = true
		}
	}
	for _, failed := range o.FailedAccounts {
		if instanceUnknown == nil {
			instanceUnknown = &reason{err: failed.err}
		}
	}
	if !inUse {
		switch {
		case instanceUnknown != nil:
			return count{why: instanceUnknown}, nil
		case rolesUnknown != nil:
			return count{why: rolesUnknown}, nil
		}
		return count{n: 0}, nil
	}
	users := 0
	for _, store := range stores {
		d := directories[store]
		if !d.read {
			return count{why: &reason{pointer: d.unread}}, nil
		}
		users += d.users
	}
	switch {
	case len(stores) > 0:
		return count{n: users}, stores
	case instanceUnknown != nil:
		return count{why: instanceUnknown}, nil
	}
	return count{why: unreadDirectoryNotRead}, nil
}

// assignedSSOMembers returns, for an account ID, the Identity Center users
// its account assignments give it, directly or through a group, from the
// directories in stores, which sso counted. A directory's assignments are
// read from the account that holds its organization instance, so one no
// account read them from leaves every account unknown. With no Identity
// Center users, no account has any, and when they are unknown, so is each
// account's.
func assignedSSOMembers(o *Output, gaps *gapLog, sso count, stores []string) func(accountID string) count {
	switch {
	case sso.why != nil:
		return func(string) count { return sso }
	case sso.n == 0:
		return func(string) count { return count{} }
	}
	users := map[string]map[string]bool{}
	unknown := map[string]*reason{}
	for _, store := range stores {
		i, why := assignmentsHolder(o, gaps, store)
		if why != nil {
			return func(string) count { return count{why: why} }
		}
		idc := o.Accounts[i].IdentityCenter
		idcAt := accountAt(i).sub("identity_center")
		groups := make(map[string]int, len(idc.Groups))
		for j, g := range idc.Groups {
			groups[g.GroupID] = j
		}
		for _, a := range idc.AccountAssignments {
			members := users[a.AccountID]
			if members == nil {
				members = map[string]bool{}
				users[a.AccountID] = members
			}
			if a.PrincipalType != "GROUP" {
				members[a.PrincipalID] = true
				continue
			}
			j, listed := groups[a.PrincipalID]
			switch {
			case gaps.covered(idcAt.p("groups")):
				unknown[a.AccountID] = &reason{pointer: idcAt.p("groups")}
			case !listed:
				unknown[a.AccountID] = &reason{err: componentsdk.CodeError(componentsdk.CodeInvalidResponse,
					errors.New("an account assignment names a group that ListGroups does not list"))}
			case gaps.covered(idcAt.p("groups", j, "member_user_ids")):
				unknown[a.AccountID] = &reason{pointer: idcAt.p("groups", j, "member_user_ids")}
			default:
				for _, u := range idc.Groups[j].MemberUserIDs {
					members[u] = true
				}
			}
		}
	}
	return func(accountID string) count {
		if why := unknown[accountID]; why != nil {
			return count{why: why}
		}
		return count{n: len(users[accountID])}
	}
}

// assignmentsHolder returns the index of an account that read every account
// assignment of the directory store, or why none did.
func assignmentsHolder(o *Output, gaps *gapLog, store string) (int, *reason) {
	var why *reason
	for i, acct := range o.Accounts {
		idc := acct.IdentityCenter
		if idc.identityStoreID != store {
			continue
		}
		switch at := accountAt(i).p("identity_center", "account_assignments"); {
		case idc.AssignmentsEvaluated && !idc.AssignmentsTruncated:
			return i, nil
		case idc.AssignmentsTruncated:
			why = &reason{err: componentsdk.CodeError(componentsdk.CodeTooLarge,
				fmt.Errorf("the account assignments run past the %d the collector keeps", IdentityCenterAssignmentsCap))}
		case why == nil && gaps.covered(at):
			why = &reason{pointer: at}
		}
	}
	if why == nil {
		why = scopeSSOMembersNotRead
	}
	return -1, why
}

// addPeople sets a's members to people, the IAM users with a console
// password and any Identity Center users, idc. When idc is unknown, or has
// users, the admins and the inactive members are unknown, for idc's reason
// or else inactiveWhy and adminsWhy: Identity Center users' sign-ins and the
// policies of their permission sets are not read. A value the IAM users already
// leave unknown keeps its own reason, and the IAM admins still make
// admins_present true.
func addPeople(a accountAccess, people, idc count, inactiveWhy, adminsWhy *reason) accountAccess {
	a.people = people
	a.peoplePresent = anyOf(a.membersPresent, presentIn(people))
	a.admins, a.adminsPresent = a.localAdmins, a.localAdminsPresent
	switch {
	case idc.why != nil:
		inactiveWhy, adminsWhy = idc.why, idc.why
	case idc.n == 0:
		return a
	}
	if a.inactive.why == nil {
		a.inactive = count{why: inactiveWhy}
	}
	if a.localAdmins.why == nil {
		a.admins = count{why: adminsWhy}
	}
	if a.localAdminsPresent.why == nil && !a.localAdminsPresent.v {
		a.adminsPresent = truth{why: adminsWhy}
	}
	return a
}

// accessPosture builds the access-posture artifact for output.
func (c *Collector) accessPosture(o *Output) *AccessPosture {
	return toAccessPosture(o, c.gaps)
}

func toAccessPosture(o *Output, gaps *gapLog) *AccessPosture {
	audit := componentsdk.Level(o.CollectedAtLevel).AtLeast(componentsdk.LevelAudit)
	w := writer{gaps: gaps, path: accessPosturePath, audit: audit}
	posture := &AccessPosture{
		SchemaVersion: "1.0.0",
		CollectedAt:   o.CollectedAt,
		Provider:      "aws",
		SystemType:    "cloud",
	}
	sso, stores := ssoMembersOf(o, gaps)
	assigned := assignedSSOMembers(o, gaps, sso, stores)
	accounts := make([]accountAccess, 0, len(o.Accounts)+len(o.FailedAccounts))
	for i, acct := range o.Accounts {
		a := accessOf(acct, i, gaps)
		accounts = append(accounts, a)
		if !audit {
			continue
		}
		ssoHere := assigned(acct.AccountID)
		a = addPeople(a, sumOf(a.members, ssoHere), ssoHere, identityCenterInactiveNotRead, identityCenterAdminsNotRead)
		scope := AccessScope{ID: acct.AccountID, Kind: "account"}
		base := fmt.Sprintf("/scopes/%d/", len(posture.Scopes))
		if alias := accountAt(i).p("account_alias"); gaps.covered(alias) {
			(&reason{pointer: alias}).record(gaps, accessPosturePath, base+"name")
		} else if acct.AccountAlias != nil {
			scope.Name = *acct.AccountAlias
		}
		writeAccess(w, base, a, &scope.SignIn, &scope.Members, &scope.Admins, &scope.Root, &scope.Credentials)
		scope.Members.SSOMemberCount = w.count(ssoHere, base+"members/sso_member_count")
		scope.Members.SSOCoveragePct = w.pct(ssoHere, a.people, componentsdk.RoundDown, base+"members/sso_coverage_pct")
		leaveOutUnreportedAccess(w, base)
		posture.Scopes = append(posture.Scopes, scope)
	}
	for _, failed := range o.FailedAccounts {
		accounts = append(accounts, failedAccess(failed.err))
	}

	total := foldAccess(accounts)
	total = addPeople(total, sumOf(total.members, sso), sso, identityCenterInactiveNotRead, identityCenterAdminsNotRead)
	writeAccess(w, "/", total, &posture.SignIn, &posture.Members, &posture.Admins, &posture.Root, &posture.Credentials)
	posture.Members.SSOMemberCount = w.count(sso, "/members/sso_member_count")
	posture.Members.SSOCoveragePct = w.pct(sso, total.people, componentsdk.RoundDown, "/members/sso_coverage_pct")
	leaveOutUnreportedAccess(w, "/")
	w.leaveOut(connectedAppsNotRead, false, "/connected_apps")
	return posture
}

// foldAccess totals the accounts' evidence. Counts add up, a present flag or
// root_access_keys_present is true when any account's is, and
// sso_configured is true only when every account's is.
func foldAccess(accounts []accountAccess) accountAccess {
	field := func(get func(accountAccess) count) count {
		counts := make([]count, len(accounts))
		for i, a := range accounts {
			counts[i] = get(a)
		}
		return sumOf(counts...)
	}
	flags := func(get func(accountAccess) truth) []truth {
		out := make([]truth, len(accounts))
		for i, a := range accounts {
			out[i] = get(a)
		}
		return out
	}
	return accountAccess{
		ssoConfigured:      allOf(flags(func(a accountAccess) truth { return a.ssoConfigured })...),
		members:            field(func(a accountAccess) count { return a.members }),
		localMFA:           field(func(a accountAccess) count { return a.localMFA }),
		inactive:           field(func(a accountAccess) count { return a.inactive }),
		membersPresent:     anyOf(flags(func(a accountAccess) truth { return a.membersPresent })...),
		localAdmins:        field(func(a accountAccess) count { return a.localAdmins }),
		adminMFA:           field(func(a accountAccess) count { return a.adminMFA }),
		localAdminsPresent: anyOf(flags(func(a accountAccess) truth { return a.localAdminsPresent })...),
		rootAccounts:       field(func(a accountAccess) count { return a.rootAccounts }),
		rootMFA:            field(func(a accountAccess) count { return a.rootMFA }),
		rootPresent:        anyOf(flags(func(a accountAccess) truth { return a.rootPresent })...),
		rootKeys:           anyOf(flags(func(a accountAccess) truth { return a.rootKeys })...),
		keys:               field(func(a accountAccess) count { return a.keys }),
		unusedKeys:         field(func(a accountAccess) count { return a.unusedKeys }),
		overdueKeys:        field(func(a accountAccess) count { return a.overdueKeys }),
		keysPresent:        anyOf(flags(func(a accountAccess) truth { return a.keysPresent })...),
	}
}

// writeAccess writes a's values into the sections under base, which is "/"
// or a scope's pointer with a trailing slash.
func writeAccess(w writer, base string, a accountAccess, signIn *AccessSignIn, members *AccessMembers, admins *AccessAdmins, root *AccessRoot, creds *AccessCredentials) {
	w.gaps.rec.Helper()
	at := func(field string) string { return base + field }

	signIn.SSOConfigured = w.truth(a.ssoConfigured, at("sign_in/sso_configured"))

	members.MembersPresent = w.truth(a.peoplePresent, at("members/members_present"))
	members.MemberCount = w.count(a.people, at("members/member_count"))
	members.LocalMembersPresent = w.truth(a.membersPresent, at("members/local_members_present"))
	members.LocalMemberCount = w.count(a.members, at("members/local_member_count"))
	members.LocalMFAMemberCount = w.count(a.localMFA, at("members/local_mfa_member_count"))
	members.LocalMFACoveragePct = w.pct(a.localMFA, a.members, componentsdk.RoundDown, at("members/local_mfa_coverage_pct"))
	members.InactiveMemberCount = w.count(a.inactive, at("members/inactive_member_count"))
	members.InactivePct = w.pct(a.inactive, a.people, componentsdk.RoundUp, at("members/inactive_pct"))

	admins.AdminsPresent = w.truth(a.adminsPresent, at("admins/admins_present"))
	admins.AdminCount = w.count(a.admins, at("admins/admin_count"))
	admins.AdminSharePct = w.pct(a.admins, a.people, componentsdk.RoundUp, at("admins/admin_share_pct"))
	admins.LocalAdminsPresent = w.truth(a.localAdminsPresent, at("admins/local_admins_present"))
	admins.LocalAdminCount = w.count(a.localAdmins, at("admins/local_admin_count"))
	admins.LocalMFAAdminCount = w.count(a.adminMFA, at("admins/local_mfa_admin_count"))
	admins.LocalAdminMFACoveragePct = w.pct(a.adminMFA, a.localAdmins, componentsdk.RoundDown, at("admins/local_admin_mfa_coverage_pct"))

	root.RootAccountsPresent = w.truth(a.rootPresent, at("root/root_accounts_present"))
	root.RootAccountCount = w.count(a.rootAccounts, at("root/root_account_count"))
	root.RootMFAAccountCount = w.count(a.rootMFA, at("root/root_mfa_account_count"))
	root.RootMFACoveragePct = w.pct(a.rootMFA, a.rootAccounts, componentsdk.RoundDown, at("root/root_mfa_coverage_pct"))
	root.RootAccessKeysPresent = w.truth(a.rootKeys, at("root/root_access_keys_present"))

	creds.CredentialsPresent = w.truth(a.keysPresent, at("credentials/credentials_present"))
	creds.CredentialCount = w.count(a.keys, at("credentials/credential_count"))
	creds.NeverExpiringCredentialCount = w.count(a.keys, at("credentials/never_expiring_credential_count"))
	creds.NeverExpiringPct = w.pct(a.keys, a.keys, componentsdk.RoundUp, at("credentials/never_expiring_pct"))
	creds.UnusedCredentialCount = w.count(a.unusedKeys, at("credentials/unused_credential_count"))
	creds.UnusedPct = w.pct(a.unusedKeys, a.keys, componentsdk.RoundUp, at("credentials/unused_pct"))
	creds.RotationOverdueCredentialCount = w.count(a.overdueKeys, at("credentials/rotation_overdue_credential_count"))
	creds.RotationOverduePct = w.pct(a.overdueKeys, a.keys, componentsdk.RoundUp, at("credentials/rotation_overdue_pct"))
}

// leaveOutUnreportedAccess records the gaps on the values AWS never reports
// and the ones this collector does not read, in the sections under base.
func leaveOutUnreportedAccess(w writer, base string) {
	w.gaps.rec.Helper()
	for _, u := range accessPostureLeftOut {
		for _, p := range u.pointers {
			w.leaveOut(u.why, u.audit, base+p)
		}
	}
}
