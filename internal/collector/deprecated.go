package collector

import (
	"fmt"

	"github.com/locktivity/epack/componentsdk"
)

// The blocks in this file are the ones epack v0.10.0 moved out of
// cloud-posture, into access-posture and vuln-scanning. The schema keeps
// them as deprecated, and the collector writes them as v0.6 did, so profiles
// written before v0.10.0 grade the same. A later minor removes them.

// CloudPostureIAM holds an account's IAM values. Each is left out when its
// detailed source was not read.
type CloudPostureIAM struct {
	MFACoveragePct                *float64 `json:"mfa_coverage_pct,omitempty"`
	RootMFAEnabled                *bool    `json:"root_mfa_enabled,omitempty"`
	RootAccessProtected           *bool    `json:"root_access_protected,omitempty"`
	AccessKeyRotationCompliantPct *float64 `json:"access_key_rotation_compliant_pct,omitempty"`
	UserCount                     *int     `json:"user_count,omitempty"`
	AccessKeyUserCount            *int     `json:"access_key_user_count,omitempty"`
	SAMLProviderCount             *int     `json:"saml_provider_count,omitempty"`
}

// CloudPostureVulnScanning holds an account's Inspector status.
type CloudPostureVulnScanning struct {
	Enabled      *bool    `json:"enabled,omitempty"`
	UnpatchedPct *float64 `json:"unpatched_pct,omitempty"`
}

// CloudPostureWorkforceSignIn describes AWS IAM Identity Center, the
// workforce sign-in service, across the accounts: whether it is in use, how
// many users its directory has, and where their MFA is set. A value the
// accounts' evidence cannot decide is left out.
type CloudPostureWorkforceSignIn struct {
	InUse     *bool  `json:"in_use,omitempty"`
	UserCount *int   `json:"user_count,omitempty"`
	MFASource string `json:"mfa_source,omitempty"`
}

// mfaSourceSignInService is mfa_source when Identity Center sets its users'
// MFA itself, which the detailed mfa_evidence reports as manual_required.
const mfaSourceSignInService = "sign_in_service"

// mfaSource maps a detailed mfa_evidence value to mfa_source.
func mfaSource(evidence string) string {
	if evidence == mfaEvidenceManualRequired {
		return mfaSourceSignInService
	}
	return evidence
}

// normalizedIAM copies the IAM values whose detailed source was read.
func normalizedIAM(iam IAMMetrics) CloudPostureIAM {
	out := CloudPostureIAM{}
	if iam.CredentialReportEvaluated {
		out.MFACoveragePct = pctFloat(iam.MFAEnabled)
		out.AccessKeyRotationCompliantPct = pctFloat(iam.AccessKeysRotated)
		out.UserCount = intPtr(iam.IAMUserCount)
		out.AccessKeyUserCount = intPtr(iam.AccessKeyUserCount)
	}
	if iam.SAMLProviderCount != nil {
		out.SAMLProviderCount = intPtr(*iam.SAMLProviderCount)
	}
	if iam.RootCredentialStateEvaluated {
		// An account whose root credentials were removed through centralized
		// root access has no root login to protect, so the MFA answer is yes.
		// The detailed field stays literal.
		out.RootMFAEnabled = boolPtr(iam.RootMFAEnabled || !iam.RootCredentialsPresent)
		out.RootAccessProtected = boolPtr(iam.RootAccessProtected)
	}
	return out
}

// normalizedVulnScanning copies whether Inspector is on, and the unpatched
// share when Inspector's findings in Security Hub were read. A gap on either
// detailed value leaves its copy out.
func normalizedVulnScanning(ins InspectorStatus) CloudPostureVulnScanning {
	out := CloudPostureVulnScanning{Enabled: boolPtr(ins.Enabled)}
	if ins.StatusEvaluated {
		out.UnpatchedPct = pctFloat(ins.UnpatchedServerPercent)
	}
	return out
}

// pctFloat carries a whole percentage into the normalized artifact, where a
// percentage over an empty population is left out.
func pctFloat(pct *int) *float64 {
	if pct == nil {
		return nil
	}
	return float64Ptr(float64(*pct))
}

// normalizedWorkforceSignIn folds the accounts' IAM Identity Center evidence
// into workforce_sign_in. Identity Center is in use when any account shows
// an active organization instance, the roles Identity Center provisions, or
// the SAML provider it creates. It is not in use when the instance and role
// listings answered for every account and found neither. Otherwise in_use is
// left out with the gap of a read that failed.
//
// The user count and where the users' MFA is set come from the directories
// of the organization instances the accounts could see. A member account
// cannot see its organization's instance, so when no account could see one,
// the user count is left out and mfa_source is unknown. Both are left out
// with a gap when a read that failed could have found the instance.
func normalizedWorkforceSignIn(o *Output, gaps *gapLog) CloudPostureWorkforceSignIn {
	type directory struct {
		users, withExternalID int
		read                  bool
		unread                string
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
				d.read, d.users, d.withExternalID = true, idc.UserCount, idc.ExternalIDUserCount
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

	var out CloudPostureWorkforceSignIn
	if !inUse {
		why := instanceUnknown
		if why == nil {
			why = rolesUnknown
		}
		if why == nil {
			out.InUse = boolPtr(false)
			return out
		}
		why.record(gaps, cloudPosturePath, "/workforce_sign_in/in_use", "/workforce_sign_in/user_count", "/workforce_sign_in/mfa_source")
		return out
	}

	out.InUse = boolPtr(true)
	users, withExternalID := 0, 0
	for _, store := range stores {
		d := directories[store]
		if !d.read {
			(&reason{pointer: d.unread}).record(gaps, cloudPosturePath, "/workforce_sign_in/user_count", "/workforce_sign_in/mfa_source")
			return out
		}
		users += d.users
		withExternalID += d.withExternalID
	}
	switch {
	case len(stores) > 0:
		out.UserCount = intPtr(users)
		out.MFASource = mfaSource(identityCenterMFAEvidence(users, withExternalID))
	case instanceUnknown != nil:
		instanceUnknown.record(gaps, cloudPosturePath, "/workforce_sign_in/user_count", "/workforce_sign_in/mfa_source")
	default:
		out.MFASource = mfaSource(mfaEvidenceUnknown)
	}
	return out
}

// movedDeprecated records account i's deprecated blocks as moved to the
// artifacts that now hold their values. A collect list that leaves out one
// of them then leaves out the block, with a not_shared gap.
func (l *gapLog) movedDeprecated(i int) {
	l.rec.Moved(componentsdk.Location{Path: cloudPosturePath, Pointer: fmt.Sprintf("/accounts/%d/iam", i)}, accessPostureArtifact)
	l.rec.Moved(componentsdk.Location{Path: cloudPosturePath, Pointer: fmt.Sprintf("/accounts/%d/vuln_scanning", i)}, vulnScanningArtifact)
}

// The artifacts the deprecated blocks moved to.
var (
	accessPostureArtifact = componentsdk.Location{Schema: accessPostureSchema, Path: accessPosturePath}
	vulnScanningArtifact  = componentsdk.Location{Schema: vulnScanningSchema, Path: vulnScanningPath}
)
