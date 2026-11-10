package collector

import (
	"fmt"

	"github.com/locktivity/epack/componentsdk"
)

// AccessPosture is the evidencepack/access-posture@v1 artifact for every
// account collected. The sections hold totals across the accounts, and from
// the audit level scopes holds each account alone. Members are the IAM users
// in each account's credential report, and admins are the ones with the AWS
// managed AdministratorAccess policy. Credentials are their active access
// keys. A value left out has a gap, and the counts and scopes are written
// from the audit level only.
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

// AccessMembers counts the IAM users. Every IAM user signs in without SSO,
// so the local values count the same users.
type AccessMembers struct {
	MembersPresent      *bool            `json:"members_present,omitempty"`
	MemberCount         *int             `json:"member_count,omitempty"`
	SSOMemberCount      *int             `json:"sso_member_count,omitempty"`
	LocalMembersPresent *bool            `json:"local_members_present,omitempty"`
	LocalMemberCount    *int             `json:"local_member_count,omitempty"`
	LocalMFAMemberCount *int             `json:"local_mfa_member_count,omitempty"`
	LocalMFACoveragePct Reading[float64] `json:"local_mfa_coverage_pct,omitzero"`
	InactiveMemberCount *int             `json:"inactive_member_count,omitempty"`
	InactivePct         Reading[float64] `json:"inactive_pct,omitzero"`
}

// AccessAdmins counts the IAM users with the AdministratorAccess policy.
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
	ssoRequiredUnsupported     = unsupported("AWS has no account setting to require SSO for everyone who signs in.")
	mfaRequiredUnsupported     = unsupported("AWS has no account setting to require MFA for everyone who signs in.")
	scimUnsupported            = unsupported("Whether IAM Identity Center users are provisioned through SCIM is not available from the AWS API.")
	externalMembersUnsupported = unsupported("IAM has no guest or outside users. People from other accounts get access through roles.")
	ssoCoverageUnsupported     = unsupported("IAM users cannot be linked to SSO, and Identity Center users are counted apart from them in sso_member_count.")
	scopeSSOMembersNotRead     = notRead("Who is assigned to each account is in ListAccountAssignments from the account that holds the Identity Center instance, which this collector does not count per account.")
	unrestrictedKeysNotRead    = notRead("An access key's IP and scope limits are in its user's policy documents, from GetUserPolicy and GetPolicyVersion, which this collector does not read.")
	writeAccessKeysNotRead     = notRead("What an access key can change is in its user's policy documents, from GetUserPolicy and GetPolicyVersion, which this collector does not read.")
	connectedAppsNotRead       = notRead("Third-party access goes through IAM roles that trust other accounts, from ListRoles, and Identity Center applications, from ListApplications. This collector does not count them as connected apps.")
	unreadDirectoryNotRead     = notRead("The organization's Identity Center users are listed with ListUsers from the account that holds the instance or a delegated administrator, and no account collected is one.")
	accessPostureLeftOut       = []struct {
		why      *reason
		audit    bool
		pointers []string
	}{
		{ssoRequiredUnsupported, false, []string{"sign_in/sso_required"}},
		{mfaRequiredUnsupported, false, []string{"sign_in/mfa_required"}},
		{scimUnsupported, false, []string{"sign_in/scim_enabled"}},
		{externalMembersUnsupported, false, []string{"members/external_members_present"}},
		{externalMembersUnsupported, true, []string{"members/external_member_count"}},
		{ssoCoverageUnsupported, false, []string{"members/sso_coverage_pct"}},
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
// values and the admin check.
type accountAccess struct {
	ssoConfigured truth

	members, localMFA, inactive count
	membersPresent              truth

	admins, adminMFA count
	adminsPresent    truth

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
		admins: c, adminMFA: c, adminsPresent: t,
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
		members:       countAt(gaps, users, iam.IAMUserCount),
		localMFA:      countAt(gaps, at.p("iam", "mfa_enabled_user_count"), iam.MFAEnabledUserCount),
		inactive:      countAt(gaps, users, iam.usage.inactiveUsers),
		rootAccounts:  count{n: 1},
		rootMFA:       rootMFAOf(iam, at, gaps),
		rootKeys:      truthAt(gaps, at.p("iam", "root_access_keys_exist"), iam.RootAccessKeysExist),
		keys:          countAt(gaps, keys, iam.usage.activeKeys),
		unusedKeys:    countAt(gaps, keys, iam.usage.unusedKeys),
		overdueKeys:   countAt(gaps, keys, iam.usage.rotationOverdueKeys),
	}
	a.admins, a.adminMFA, a.adminsPresent = adminsOf(acct.admins, a.members)
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
// when no account could read a directory.
func ssoMembersOf(o *Output, gaps *gapLog) count {
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
			return count{why: instanceUnknown}
		case rolesUnknown != nil:
			return count{why: rolesUnknown}
		}
		return count{n: 0}
	}
	users := 0
	for _, store := range stores {
		d := directories[store]
		if !d.read {
			return count{why: &reason{pointer: d.unread}}
		}
		users += d.users
	}
	switch {
	case len(stores) > 0:
		return count{n: users}
	case instanceUnknown != nil:
		return count{why: instanceUnknown}
	}
	return count{why: unreadDirectoryNotRead}
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
	accounts := make([]accountAccess, 0, len(o.Accounts)+len(o.FailedAccounts))
	for i, acct := range o.Accounts {
		a := accessOf(acct, i, gaps)
		accounts = append(accounts, a)
		if !audit {
			continue
		}
		scope := AccessScope{ID: acct.AccountID, Kind: "account"}
		base := fmt.Sprintf("/scopes/%d/", len(posture.Scopes))
		if alias := accountAt(i).p("account_alias"); gaps.covered(alias) {
			(&reason{pointer: alias}).record(gaps, accessPosturePath, base+"name")
		} else if acct.AccountAlias != nil {
			scope.Name = *acct.AccountAlias
		}
		writeAccess(w, base, a, &scope.SignIn, &scope.Members, &scope.Admins, &scope.Root, &scope.Credentials)
		w.leaveOut(scopeSSOMembersNotRead, true, base+"members/sso_member_count")
		leaveOutUnreportedAccess(w, base)
		posture.Scopes = append(posture.Scopes, scope)
	}
	for _, failed := range o.FailedAccounts {
		accounts = append(accounts, failedAccess(failed.err))
	}

	total := foldAccess(accounts)
	writeAccess(w, "/", total, &posture.SignIn, &posture.Members, &posture.Admins, &posture.Root, &posture.Credentials)
	posture.Members.SSOMemberCount = w.count(ssoMembersOf(o, gaps), "/members/sso_member_count")
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
		ssoConfigured:  allOf(flags(func(a accountAccess) truth { return a.ssoConfigured })...),
		members:        field(func(a accountAccess) count { return a.members }),
		localMFA:       field(func(a accountAccess) count { return a.localMFA }),
		inactive:       field(func(a accountAccess) count { return a.inactive }),
		membersPresent: anyOf(flags(func(a accountAccess) truth { return a.membersPresent })...),
		admins:         field(func(a accountAccess) count { return a.admins }),
		adminMFA:       field(func(a accountAccess) count { return a.adminMFA }),
		adminsPresent:  anyOf(flags(func(a accountAccess) truth { return a.adminsPresent })...),
		rootAccounts:   field(func(a accountAccess) count { return a.rootAccounts }),
		rootMFA:        field(func(a accountAccess) count { return a.rootMFA }),
		rootPresent:    anyOf(flags(func(a accountAccess) truth { return a.rootPresent })...),
		rootKeys:       anyOf(flags(func(a accountAccess) truth { return a.rootKeys })...),
		keys:           field(func(a accountAccess) count { return a.keys }),
		unusedKeys:     field(func(a accountAccess) count { return a.unusedKeys }),
		overdueKeys:    field(func(a accountAccess) count { return a.overdueKeys }),
		keysPresent:    anyOf(flags(func(a accountAccess) truth { return a.keysPresent })...),
	}
}

// writeAccess writes a's values into the sections under base, which is "/"
// or a scope's pointer with a trailing slash.
func writeAccess(w writer, base string, a accountAccess, signIn *AccessSignIn, members *AccessMembers, admins *AccessAdmins, root *AccessRoot, creds *AccessCredentials) {
	w.gaps.rec.Helper()
	at := func(field string) string { return base + field }

	signIn.SSOConfigured = w.truth(a.ssoConfigured, at("sign_in/sso_configured"))

	members.MembersPresent = w.truth(a.membersPresent, at("members/members_present"))
	members.MemberCount = w.count(a.members, at("members/member_count"))
	members.LocalMembersPresent = w.truth(a.membersPresent, at("members/local_members_present"))
	members.LocalMemberCount = w.count(a.members, at("members/local_member_count"))
	members.LocalMFAMemberCount = w.count(a.localMFA, at("members/local_mfa_member_count"))
	members.LocalMFACoveragePct = w.pct(a.localMFA, a.members, componentsdk.RoundDown, at("members/local_mfa_coverage_pct"))
	members.InactiveMemberCount = w.count(a.inactive, at("members/inactive_member_count"))
	members.InactivePct = w.pct(a.inactive, a.members, componentsdk.RoundUp, at("members/inactive_pct"))

	admins.AdminsPresent = w.truth(a.adminsPresent, at("admins/admins_present"))
	admins.AdminCount = w.count(a.admins, at("admins/admin_count"))
	admins.AdminSharePct = w.pct(a.admins, a.members, componentsdk.RoundUp, at("admins/admin_share_pct"))
	admins.LocalAdminsPresent = w.truth(a.adminsPresent, at("admins/local_admins_present"))
	admins.LocalAdminCount = w.count(a.admins, at("admins/local_admin_count"))
	admins.LocalMFAAdminCount = w.count(a.adminMFA, at("admins/local_mfa_admin_count"))
	admins.LocalAdminMFACoveragePct = w.pct(a.adminMFA, a.admins, componentsdk.RoundDown, at("admins/local_admin_mfa_coverage_pct"))

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
