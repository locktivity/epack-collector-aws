package collector

import (
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// The simulated matrix varies the sandbox along the axes below. Each
// one-at-a-time row changes one setting, so a difference it shows belongs
// to that setting and is listed in simMatrixAlone. The pairwise rows put
// every two settings together at least once, and a difference none of a
// row's settings shows alone must be listed in simMatrixTogether.

const (
	simConsoleUser = "epack-sandbox-5-console"
	simKey         = "epack-sandbox-1-mfa-new-key/access-key"
	simDatabase    = "epack-sandbox-db"
	simAdminGroup  = "epack-sandbox-admins"
	simVendor      = "epack-sandbox-vendor"
)

// simMatrixBase is the sandbox with an IAM user who signs in with a
// console password, and so is a member, and an encrypted Multi-AZ
// database that keeps a week of backups, so the axes reach the member and
// database values the sandbox has none of. Its terms name every vendor
// term an axis uses, since a change must not write to the terms the base
// shares with its variants.
func simMatrixBase(t testing.TB) *roster.Roster {
	t.Helper()
	r := simBase(t)
	terms := &r.Terms
	terms.AccountKinds["iam_user_console_password"] = roster.KindMember
	terms.LoginMethods = map[string]string{"console_password": roster.LoginLocal}
	terms.MFAMethods["u2f_security_key"] = roster.MFAPhishingResistant
	terms.CloudRoles = map[string]string{"AdministratorAccess": roster.RoleAdmin, "PowerUserAccess": roster.RoleAdmin, "ReadOnlyAccess": roster.RoleNone}
	terms.Protocols["-1"] = roster.ProtocolAny
	terms.KeySources["aws/rds"] = roster.ProviderKey
	terms.KeySources["aws:kms"] = roster.CustomerKey
	terms.KeySources["none"] = roster.NoKey
	terms.CloudNetworkAccess["private"] = roster.NetworkOff
	terms.CloudIdentityProviders = map[string]string{"saml": roster.IdPSAML}
	terms.AppPublishers = map[string]string{"vendor": roster.PublisherThirdParty}
	r.Accounts = append(r.Accounts, roster.Account{
		Key: simConsoleUser, Kind: "iam_user_console_password", Enabled: true, CloudAccount: "sandbox",
		Methods: []string{"virtual_mfa_device"}, Logins: []string{"console_password"}, SignedInDaysAgo: new(3),
	})
	r.Cloud.Databases = append(r.Cloud.Databases, roster.Database{
		Key: simDatabase, KeySource: "aws/rds", NetworkAccess: "private", Zones: 2, BackupRetentionDays: new(7),
	})
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	return r
}

func onKey(key string, change func(*roster.MachineCredential)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		for i := range r.Cloud.Credentials {
			if r.Cloud.Credentials[i].Key == key {
				change(&r.Cloud.Credentials[i])
			}
		}
	}
}

func onRule(group string, change func(*roster.NetworkRule)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		for i := range r.SecurityGroups {
			if r.SecurityGroups[i].Key == group {
				change(&r.SecurityGroups[i].Rules[0])
			}
		}
	}
}

func onBucket(suffix string, change func(*roster.Storage)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		for i := range r.Storage {
			if r.Storage[i].Key == "epack-"+suffix {
				change(&r.Storage[i])
			}
		}
	}
}

func onDatabase(change func(*roster.Database)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		for i := range r.Cloud.Databases {
			if r.Cloud.Databases[i].Key == simDatabase {
				change(&r.Cloud.Databases[i])
			}
		}
	}
}

func onTrails(change func(map[string]*roster.AuditLog, *roster.CloudAccount)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		a := &r.Cloud.Accounts[0]
		byName := map[string]*roster.AuditLog{}
		for i := range a.AuditLogs {
			byName[a.AuditLogs[i].Key] = &a.AuditLogs[i]
		}
		change(byName, a)
	}
}

func onConsoleUser(change func(*roster.Account)) func(*roster.Roster) {
	return simulate.OnAccount(simConsoleUser, change)
}

func simMatrixAxes() []roster.Axis {
	return []roster.Axis{
		{Name: "console_mfa", Values: []roster.Value{
			{Name: "virtual"},
			{Name: "none", Change: onConsoleUser(func(a *roster.Account) { a.Methods = nil })},
			{Name: "security_key", Change: onConsoleUser(func(a *roster.Account) { a.Methods = []string{"u2f_security_key"} })},
		}},
		{Name: "console_sign_in", Values: []roster.Value{
			{Name: "3_days_ago"},
			{Name: "never", Change: onConsoleUser(func(a *roster.Account) { a.SignedInDaysAgo = nil })},
			{Name: "90_days_ago", Change: onConsoleUser(func(a *roster.Account) { a.SignedInDaysAgo = new(90) })},
			{Name: "91_days_ago", Change: onConsoleUser(func(a *roster.Account) { a.SignedInDaysAgo = new(91) })},
		}},
		{Name: "console_admin", Values: []roster.Value{
			{Name: "none"},
			{Name: "attached", Change: onConsoleUser(func(a *roster.Account) { a.CloudRoles = []string{"AdministratorAccess"} })},
			{Name: "power_user", Change: onConsoleUser(func(a *roster.Account) { a.CloudRoles = []string{"PowerUserAccess"} })},
			{Name: "read_only", Change: onConsoleUser(func(a *roster.Account) { a.CloudRoles = []string{"ReadOnlyAccess"} })},
			{Name: "through_group", Change: func(r *roster.Roster) {
				r.Groups = append(r.Groups, roster.Group{Key: simAdminGroup, Members: []string{simConsoleUser}, CloudRoles: []string{"AdministratorAccess"}})
			}},
			{Name: "inline_policy", Change: onConsoleUser(func(a *roster.Account) {
				simulate.SetExtra(&a.Extra, "inline_policies", []string{"s3-full-access"})
			})},
		}},
		{Name: "console_key", Values: []roster.Value{
			{Name: "none"},
			{Name: "used_yesterday", Change: func(r *roster.Roster) {
				r.Cloud.Credentials = append(r.Cloud.Credentials, roster.MachineCredential{
					Key: simConsoleUser + "/access-key", Owner: simConsoleUser, Active: true, CreatedDaysAgo: new(10), LastUsedDaysAgo: new(1), Permissions: "deny-all",
				})
			}},
		}},
		{Name: "key_age", Values: []roster.Value{
			{Name: "15_days"},
			{Name: "90_days", Change: onKey(simKey, func(m *roster.MachineCredential) { m.CreatedDaysAgo = new(90) })},
			{Name: "91_days", Change: onKey(simKey, func(m *roster.MachineCredential) { m.CreatedDaysAgo = new(91) })},
		}},
		{Name: "key_use", Values: []roster.Value{
			{Name: "never"},
			{Name: "yesterday", Change: onKey(simKey, func(m *roster.MachineCredential) { m.LastUsedDaysAgo = new(1) })},
			{Name: "90_days_ago", Change: onKey(simKey, func(m *roster.MachineCredential) { m.LastUsedDaysAgo = new(90) })},
			{Name: "91_days_ago", Change: onKey(simKey, func(m *roster.MachineCredential) { m.LastUsedDaysAgo = new(91) })},
			{Name: "deactivated", Change: onKey(simKey, func(m *roster.MachineCredential) { m.Active = false })},
		}},
		{Name: "ssh_group", Values: []roster.Value{
			{Name: "restricted"},
			{Name: "open_ipv4", Change: onRule("us-east-1/epack-sandbox-ssh-restricted", func(n *roster.NetworkRule) { n.Sources = []string{"0.0.0.0/0"} })},
			{Name: "open_ipv6", Change: onRule("us-east-1/epack-sandbox-ssh-restricted", func(n *roster.NetworkRule) { n.Sources = []string{"::/0"} })},
			{Name: "all_traffic", Change: onRule("us-east-1/epack-sandbox-ssh-restricted", func(n *roster.NetworkRule) {
				n.Protocol, n.Ports, n.Sources = "-1", []string{"*"}, []string{"0.0.0.0/0"}
			})},
		}},
		{Name: "rdp_group", Values: []roster.Value{
			{Name: "open_ipv6"},
			{Name: "restricted", Change: onRule("us-west-2/epack-sandbox-rdp-open-ipv6", func(n *roster.NetworkRule) { n.Sources = []string{"10.0.0.0/8"} })},
			{Name: "range_from_anywhere", Change: onRule("us-west-2/epack-sandbox-rdp-open-ipv6", func(n *roster.NetworkRule) {
				n.Ports, n.Sources = []string{"3380-3390"}, []string{"0.0.0.0/0"}
			})},
		}},
		{Name: "bucket_block", Values: []roster.Value{
			{Name: "acls_and_account"},
			{Name: "all", Change: onBucket("sandbox-123456789012-pab-combined", func(st *roster.Storage) {
				simulate.SetExtra(&st.Extra, "public_access_block", "all")
			})},
			{Name: "off", Change: onBucket("sandbox-123456789012-pab-combined", func(st *roster.Storage) {
				st.AnonymousAccess = true
				simulate.SetExtra(&st.Extra, "public_access_block", "off")
			})},
			{Name: "absent", Change: onBucket("sandbox-123456789012-pab-combined", func(st *roster.Storage) {
				st.AnonymousAccess = true
				simulate.SetExtra(&st.Extra, "public_access_block", "absent")
			})},
		}},
		{Name: "bucket_region", Values: []roster.Value{
			{Name: "us_east_1"},
			{Name: "us_west_2", Change: onBucket("sandbox-123456789012-access-logs", func(st *roster.Storage) {
				simulate.SetExtra(&st.Extra, "region", "us-west-2")
			})},
		}},
		{Name: "bucket_encryption", Values: []roster.Value{
			{Name: "sse_s3"},
			{Name: "sse_kms", Change: onBucket("collector-sandboxes-state-123456789012", func(st *roster.Storage) { st.KeySource = "aws:kms" })},
			{Name: "none", Change: onBucket("collector-sandboxes-state-123456789012", func(st *roster.Storage) { st.KeySource = "none" })},
		}},
		{Name: "cloudtrail", Values: []roster.Value{
			{Name: "multi_region_logging"},
			{Name: "multi_region_stopped", Change: onTrails(func(trails map[string]*roster.AuditLog, _ *roster.CloudAccount) {
				trails["epack-sandbox-trail-1-multi-region"].Enabled = false
			})},
			{Name: "all_stopped", Change: onTrails(func(trails map[string]*roster.AuditLog, _ *roster.CloudAccount) {
				for _, l := range trails {
					l.Enabled = false
				}
			})},
			{Name: "multi_region_no_global_events", Change: onTrails(func(trails map[string]*roster.AuditLog, _ *roster.CloudAccount) {
				simulate.SetExtra(&trails["epack-sandbox-trail-1-multi-region"].Extra, "global_service_events", false)
			})},
			{Name: "regional_pair", Change: onTrails(func(trails map[string]*roster.AuditLog, a *roster.CloudAccount) {
				trails["epack-sandbox-trail-1-multi-region"].Enabled = false
				a.AuditLogs = append(a.AuditLogs, roster.AuditLog{Key: "epack-sandbox-trail-4-us-west-2", Enabled: true, Regions: []string{"us-west-2"}})
			})},
		}},
		{Name: "database", Values: []roster.Value{
			{Name: "private_backed_up"},
			{Name: "no_backups", Change: onDatabase(func(d *roster.Database) { d.BackupRetentionDays = nil })},
			{Name: "public_unencrypted", Change: onDatabase(func(d *roster.Database) {
				d.NetworkAccess, d.KeySource, d.Zones = "public_endpoint", "none", 1
			})},
			{Name: "customer_key", Change: onDatabase(func(d *roster.Database) { d.KeySource = "aws:kms" })},
			{Name: "none", Change: func(r *roster.Roster) { r.Cloud.Databases = nil }},
		}},
		{Name: "root", Values: []roster.Value{
			{Name: "mfa"},
			{Name: "password_no_mfa", Change: simulate.OnAccount("root", func(a *roster.Account) {
				a.Methods, a.Logins = nil, []string{"console_password"}
			})},
			{Name: "no_credentials", Change: simulate.OnAccount("root", func(a *roster.Account) { a.Methods = nil })},
			{Name: "access_key", Change: func(r *roster.Roster) {
				r.Cloud.Credentials = append(r.Cloud.Credentials, roster.MachineCredential{
					Key: "root/access-key", Owner: "root", Active: true, CreatedDaysAgo: new(30), Permissions: "deny-all",
				})
			}},
		}},
		{Name: "saml_provider", Values: []roster.Value{
			{Name: "none"},
			{Name: "okta", Change: func(r *roster.Roster) {
				r.Cloud.Accounts[0].IdentityProviders = append(r.Cloud.Accounts[0].IdentityProviders, roster.IdentityProvider{Key: "okta", Kind: "saml"})
			}},
		}},
		{Name: "connected_app", Values: []roster.Value{
			{Name: "none"},
			{Name: "one_role", Change: func(r *roster.Roster) {
				r.Apps = append(r.Apps, roster.App{Key: simVendor, Enabled: true, Publisher: "vendor", CloudRoles: []string{"ReadOnlyAccess"}})
			}},
			{Name: "two_roles", Change: func(r *roster.Roster) {
				r.Apps = append(r.Apps, roster.App{Key: simVendor, Enabled: true, Publisher: "vendor", CloudRoles: []string{"ReadOnlyAccess", "PowerUserAccess"}})
			}},
			{Name: "two_apps", Change: func(r *roster.Roster) {
				r.Apps = append(r.Apps,
					roster.App{Key: simVendor, Enabled: true, Publisher: "vendor", CloudRoles: []string{"ReadOnlyAccess"}},
					roster.App{Key: simVendor + "-2", Enabled: true, Publisher: "vendor", CloudRoles: []string{"AdministratorAccess"}})
			}},
		}},
	}
}

// simAdminValues are the admin values, in the totals and the scope.
var simAdminValues = simAccessBoth("/admins/admins_present", "/admins/admin_count", "/admins/admin_share_pct",
	"/admins/local_admins_present", "/admins/local_admin_count", "/admins/local_mfa_admin_count", "/admins/local_admin_mfa_coverage_pct")

// simRootKeyNote says why the root user's access key is counted apart.
const simRootKeyNote = "credentialUsage in iam_access.go counts the IAM users' access keys, as docs/overview.md says, and leaves the root user's out, which root_access_keys_present reports instead. Derive counts every active access key, the root user's too, since the schema's credential_count names access keys. Whether the root user's keys are machine credentials is a definition question."

// simMatrixAlone lists, by axis=value, the differences a setting shows on
// its own.
var simMatrixAlone = map[string]simulate.Differences{
	"console_admin=inline_policy": simulate.Same(simulate.Gap,
		"adminsOf and checkPolicies in iam_access.go: an inline policy may grant administrator access, and the collector doesn't read policy documents, so the user is unmeasured and the admin values are left out with a partial not_read gap, as docs/overview.md says.",
		simAdminValues...),
	"bucket_encryption=none": simulate.Same(simulate.Unmodeled,
		"s3DefaultEncryptionEvaluation in internal/aws/client.go: S3 has encrypted every bucket with SSE-S3 since January 2023, so no S3 bucket is unencrypted. The simulator answers as a bucket from before then with no default encryption configured, which the collector counts as encrypted, so the derived value is the one in doubt.",
		"/accounts/0/storage/encryption_pct", "/accounts/0/storage/encrypted_storage_resource_count"),
	"cloudtrail=multi_region_stopped": simulate.Same(simulate.Gap,
		"trailCoverageUnknown in account.go: with trail-1 stopped, trail-2 decides, and whether its event selectors record management writes is unknown, since the sandbox's role has no cloudtrail:GetEventSelectors (bootstrap/aws/collector_policy.tf) and the recording holds the denial. The values are left out with a partial permission_denied gap.",
		"/accounts/0/logging/audit_log_enabled", "/accounts/0/logging/cloudtrail_enabled"),
	"cloudtrail=multi_region_no_global_events": simulate.Same(simulate.Unmodeled,
		"summarizeCloudTrailStatus in account.go doesn't count a multi-region trail that leaves out global service events, the IAM, STS and CloudFront events, as covering every region. The roster has no term for global service events, so Derive counts the trail.",
		"/accounts/0/logging/audit_log_all_regions", "/accounts/0/logging/cloudtrail_multiregion"),
	"cloudtrail=regional_pair": simulate.Same(simulate.Definition,
		"summarizeCloudTrailStatus in account.go counts an audit log as covering every region only when one multi-region trail logs, and Derive counts single-region trails that between them cover every region the account uses. Whether they cover every region, including ones the run doesn't scan, is a definition question.",
		"/accounts/0/logging/audit_log_all_regions", "/accounts/0/logging/cloudtrail_multiregion"),
	"database=no_backups": simulate.Same(simulate.Definition,
		"countDatabase in rds.go counts a database with automated backups off as 0 days, which TestToCloudPosture_ZeroRetention pins as evidence, and the schema's retention_days_min counts only backup-enabled resources and is null when none has backups. Which one holds is a definition question.",
		"/accounts/0/backup/retention_days_min"),
	"database=none": simNoDatabase,
	"root=no_credentials": simulate.Same(simulate.Known,
		"rootMFAOf in access_posture.go and normalizedIAM in deprecated.go count a root user with no password, access key or signing certificate as having MFA, as docs/overview.md and the v0.7.0 changelog say. The schema's root_mfa_account_count counts the root accounts that have MFA turned on.",
		"access-posture:/root/root_mfa_account_count", "access-posture:/root/root_mfa_coverage_pct",
		"access-posture:/scopes/0/root/root_mfa_account_count", "access-posture:/scopes/0/root/root_mfa_coverage_pct",
		"/accounts/0/iam/root_mfa_enabled"),
	"root=access_key": simulate.Same(simulate.Definition, simRootKeyNote,
		append(simAccessBoth("/credentials/credential_count", "/credentials/never_expiring_credential_count",
			"/credentials/unused_credential_count", "/credentials/rotation_overdue_pct"),
			"/accounts/0/iam/access_key_user_count", "/accounts/0/iam/access_key_rotation_compliant_pct")...),
}

// simMatrixTogether lists the differences that show only when settings
// meet.
var simMatrixTogether = []simulate.Together{
	{
		// A member who never signs in, or not for 91 days, but whose key
		// was used yesterday.
		Match: func(choices []string) bool {
			return simulate.Any(choices, "console_key=used_yesterday") && simulate.Any(choices, "console_sign_in=never", "console_sign_in=91_days_ago")
		},
		Differences: simulate.Same(simulate.Unmodeled,
			"credentialUsage in iam_access.go counts the use of a member's access key as activity, as the schema's inactive_member_count, members with no sign-in or other recorded activity, does. The roster gives a member's sign-ins alone, so Derive counts the member inactive.",
			simAccessBoth("/members/inactive_member_count", "/members/inactive_pct")...),
	},
	{
		// The unused share over the root user's key as well, once another
		// key was used.
		Match:       func(choices []string) bool { return simulate.Any(choices, "root=access_key") },
		Differences: simulate.Same(simulate.Definition, simRootKeyNote, simAccessBoth("/credentials/unused_pct")...),
	},
}

func TestSimulatedMatrix(t *testing.T) {
	simHarness(t, simStanding).Matrix(t, simMatrixBase(t), simMatrixAxes(), simMatrixAlone, simMatrixTogether)
}
