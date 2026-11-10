package collector

import (
	"net/http"
	"slices"
	"testing"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

// declared is a run's target declarations: the accounts, the regions it
// scanned, and the primary region, declared for the security services read
// there alone. run is the run that declared them.
type declared struct {
	accounts, regions, primary componentsdk.ResultTarget
	run                        componentsdk.InProcessResult
}

// targetsRun runs the collector and returns its target declarations. It
// fails t when the run fails, when a declaration is missing or made twice,
// or when the artifacts don't bear a declaration out.
func targetsRun(t *testing.T, config map[string]any, secrets map[string]string, responses []collectortest.Response) declared {
	t.Helper()
	res := runKit(t, config, secrets, responses)
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	for _, f := range res.Result.Checks {
		if f.Check == componentsdk.CheckTargets {
			t.Errorf("targets finding %+v", f)
		}
	}
	out := declared{run: res}
	for _, d := range res.Result.Targets {
		var slot *componentsdk.ResultTarget
		switch {
		case d.Kind == componentsdk.TargetAccount:
			slot = &out.accounts
		case d.Kind == componentsdk.TargetRegion && len(d.For) == 0:
			slot = &out.regions
		case d.Kind == componentsdk.TargetRegion:
			slot = &out.primary
		default:
			t.Fatalf("%s targets are declared, want only accounts and regions", d.Kind)
		}
		if slot.Kind != "" {
			t.Errorf("%s targets at %+v are declared twice", d.Kind, d.At)
		}
		*slot = d
	}
	if len(res.Result.Targets) != 3 {
		t.Fatalf("targets = %+v, want accounts, regions, and the primary region", res.Result.Targets)
	}
	return out
}

// accountsAt is where the account targets sit: the normalized artifact's
// accounts, which keep an entry for an account that failed.
var accountsAt = componentsdk.Location{Schema: cloudPostureSchema, Path: cloudPosturePath, Pointer: "/accounts"}

// regionsAt is where the region targets sit: each account's regions in the
// detailed artifact.
var regionsAt = componentsdk.Location{Path: awsPath, Pointer: "/accounts/*/regions"}

// primaryAt is where the primary region sits: each account's primary_region
// in the detailed artifact.
var primaryAt = componentsdk.Location{Path: awsPath, Pointer: "/accounts/*/primary_region"}

// primaryFor are the values read in the primary region alone: each account's
// AWS Config, Security Hub, and Inspector status in the detailed artifact.
var primaryFor = []componentsdk.Location{
	{Path: awsPath, Pointer: "/accounts/*/account_security/config"},
	{Path: awsPath, Pointer: "/accounts/*/account_security/security_hub"},
	{Path: awsPath, Pointer: "/accounts/*/account_security/inspector"},
}

func countIs(n *int, want int) bool { return n != nil && *n == want }

func completeIs(b *bool, want bool) bool { return b != nil && *b == want }

// An audit run over the single role_arn account declares that account, its
// region, and its primary region for the security services read there, each
// counted and complete.
func TestTargetsAtAudit(t *testing.T) {
	isolateAWSEnvironment(t)
	config := kitConfig()
	config["level"] = "audit"
	got := targetsRun(t, config, kitSecrets(), kitResponses())

	accounts := got.accounts
	if accounts.ChosenBy != componentsdk.ChosenByConfig || accounts.ConfigKey != "role_arn" {
		t.Errorf("accounts chosen by %q with %q, want %q with role_arn", accounts.ChosenBy, accounts.ConfigKey, componentsdk.ChosenByConfig)
	}
	if accounts.At == nil || *accounts.At != accountsAt {
		t.Errorf("accounts at %+v, want %+v", accounts.At, accountsAt)
	}
	if !slices.Equal(accounts.Name, []string{"/account_id"}) || accounts.Label != "/account_label" || accounts.Reached != "" {
		t.Errorf("accounts name %q, label %q, reached %q; want /account_id and /account_label", accounts.Name, accounts.Label, accounts.Reached)
	}
	if accounts.Found != nil || accounts.Assessed != nil || accounts.Coverage != nil {
		t.Errorf("accounts found %+v, assessed %+v, coverage %+v; want none", accounts.Found, accounts.Assessed, accounts.Coverage)
	}
	if !countIs(accounts.Count, 1) || !completeIs(accounts.Complete, true) {
		t.Errorf("accounts count %v, complete %v; want 1 and true", accounts.Count, accounts.Complete)
	}

	regions := got.regions
	if regions.ChosenBy != componentsdk.ChosenByDiscovery || regions.ConfigKey != "" {
		t.Errorf("regions chosen by %q with %q, want %q", regions.ChosenBy, regions.ConfigKey, componentsdk.ChosenByDiscovery)
	}
	if regions.At == nil || *regions.At != regionsAt || regions.Name != nil || regions.Label != "" {
		t.Errorf("regions = %+v, want them at %+v with no name or label", regions, regionsAt)
	}
	if !countIs(regions.Count, 1) || !completeIs(regions.Complete, true) {
		t.Errorf("regions count %v, complete %v; want 1 and true", regions.Count, regions.Complete)
	}

	primary := got.primary
	if primary.ChosenBy != componentsdk.ChosenByCollector || primary.ConfigKey != "" {
		t.Errorf("primary region chosen by %q with %q, want %q", primary.ChosenBy, primary.ConfigKey, componentsdk.ChosenByCollector)
	}
	if primary.At == nil || *primary.At != primaryAt || primary.Name != nil || primary.Label != "" {
		t.Errorf("primary region = %+v, want it at %+v with no name or label", primary, primaryAt)
	}
	if !slices.Equal(primary.For, primaryFor) {
		t.Errorf("primary region for %+v, want %+v", primary.For, primaryFor)
	}
	if !countIs(primary.Count, 1) || !completeIs(primary.Complete, true) {
		t.Errorf("primary region count %v, complete %v; want 1 and true", primary.Count, primary.Complete)
	}
}

// A trust run keeps where the targets sit, the accounts' labels, and the
// values read in the primary region, and leaves out the counts, which the
// schema writes from the audit level.
func TestTargetsAtTrust(t *testing.T) {
	isolateAWSEnvironment(t)
	config := kitConfig()
	config["level"] = "trust"
	got := targetsRun(t, config, kitSecrets(), kitResponses())

	accounts := got.accounts
	if accounts.At == nil || *accounts.At != accountsAt || accounts.Label != "/account_label" {
		t.Errorf("accounts at %+v with label %q, want %+v with /account_label", accounts.At, accounts.Label, accountsAt)
	}
	if accounts.Count != nil {
		t.Errorf("accounts count %d at trust, want none", *accounts.Count)
	}
	if !completeIs(accounts.Complete, true) {
		t.Errorf("accounts complete %v at trust, want true", accounts.Complete)
	}

	regions := got.regions
	if regions.At == nil || *regions.At != regionsAt || regions.Count != nil || !completeIs(regions.Complete, true) {
		t.Errorf("regions = %+v at trust, want them at %+v, uncounted and complete", regions, regionsAt)
	}

	primary := got.primary
	if primary.At == nil || *primary.At != primaryAt || primary.Count != nil || !completeIs(primary.Complete, true) {
		t.Errorf("primary region = %+v at trust, want it at %+v, uncounted and complete", primary, primaryAt)
	}
	if !slices.Equal(primary.For, primaryFor) {
		t.Errorf("primary region for %+v at trust, want %+v", primary.For, primaryFor)
	}
}

// An accounts list whose second role AWS refuses declares both accounts,
// and the refused one leaves them incomplete at every level. The regions
// come from the accounts the run signed in to, so they stay complete.
func TestTargetsWithARefusedAccount(t *testing.T) {
	refused := withRequestBody(collectortest.Response{
		Operation: "aws.sts.AssumeRoleWithWebIdentity", Method: http.MethodPost, URL: kitSTSURL, Status: http.StatusForbidden, Header: xmlHeader(),
		Body: "<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>Not authorized to perform sts:AssumeRoleWithWebIdentity</Message></Error>" +
			"<RequestId>kit-request</RequestId></ErrorResponse>",
	}, formFields("aws.sts.AssumeRoleWithWebIdentity", map[string]string{"RoleArn": identifierRole}))
	responses := append([]collectortest.Response{refused}, kitResponses()...)

	for _, level := range []componentsdk.Level{componentsdk.LevelAudit, componentsdk.LevelTrust} {
		t.Run(string(level), func(t *testing.T) {
			isolateAWSEnvironment(t)
			config := map[string]any{
				"auth_mode": "oidc",
				"level":     string(level),
				"accounts": []any{
					map[string]any{"role_arn": kitRoleARN, "label": "production"},
					map[string]any{"role_arn": identifierRole, "label": "staging"},
				},
			}
			got := targetsRun(t, config, kitSecrets(), responses)

			accounts := got.accounts
			if accounts.ChosenBy != componentsdk.ChosenByConfig || accounts.ConfigKey != "accounts" {
				t.Errorf("accounts chosen by %q with %q, want %q with accounts", accounts.ChosenBy, accounts.ConfigKey, componentsdk.ChosenByConfig)
			}
			if !completeIs(accounts.Complete, false) {
				t.Errorf("accounts complete %v, want false with a refused account", accounts.Complete)
			}
			wantCount := 2
			if level == componentsdk.LevelTrust {
				if accounts.Count != nil {
					t.Errorf("accounts count %d at trust, want none", *accounts.Count)
				}
			} else if !countIs(accounts.Count, wantCount) {
				t.Errorf("accounts count %v, want %d", accounts.Count, wantCount)
			}

			if regions := got.regions; !completeIs(regions.Complete, true) {
				t.Errorf("regions complete %v, want true", regions.Complete)
			}
		})
	}
}

// A gap inside an account that is not about its regions leaves the regions
// complete. The accounts are read from the normalized artifact, so they are
// incomplete only when the gap reaches it: a refused bucket listing leaves
// out the account's storage values there, and a refused password policy
// leaves out a detailed value only.
func TestTargetsWithAnUnrelatedGapInAnAccount(t *testing.T) {
	cases := []struct {
		name             string
		refused          collectortest.Response
		accountsComplete bool
	}{
		{
			name: "bucket listing",
			refused: restResponse("aws.s3.ListBuckets", http.MethodGet, kitS3URL+"/?max-buckets=10000&x-id=ListBuckets",
				http.StatusForbidden, s3Error("AccessDenied")),
			accountsComplete: false,
		},
		{
			name: "password policy",
			refused: iamDenied("aws.iam.GetAccountPasswordPolicy", "iam:GetAccountPasswordPolicy",
				"because no identity-based policy allows the iam:GetAccountPasswordPolicy action"),
			accountsComplete: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateAWSEnvironment(t)
			config := kitConfig()
			config["level"] = "audit"
			got := targetsRun(t, config, kitSecrets(), replaceResponses(kitResponses(), tc.refused))
			if accounts := got.accounts; !completeIs(accounts.Complete, tc.accountsComplete) {
				t.Errorf("accounts complete %v, want %v", accounts.Complete, tc.accountsComplete)
			}
			if regions := got.regions; !countIs(regions.Count, 1) || !completeIs(regions.Complete, true) {
				t.Errorf("regions count %v, complete %v; want 1 and true", regions.Count, regions.Complete)
			}
		})
	}
}

// A regions list chooses the regions and the primary region by config, and
// with no account configured the run declares the default credentials'
// account as found.
func TestTargetsChosenBy(t *testing.T) {
	t.Run("regions listed", func(t *testing.T) {
		isolateAWSEnvironment(t)
		config := kitConfig()
		config["level"] = "audit"
		config["regions"] = []any{kitRegion}
		got := targetsRun(t, config, kitSecrets(), kitResponses())
		if regions := got.regions; regions.ChosenBy != componentsdk.ChosenByConfig || regions.ConfigKey != "regions" || !countIs(regions.Count, 1) {
			t.Errorf("regions = %+v, want one chosen by %q with regions", regions, componentsdk.ChosenByConfig)
		}
		if primary := got.primary; primary.ChosenBy != componentsdk.ChosenByConfig || primary.ConfigKey != "regions" || !countIs(primary.Count, 1) {
			t.Errorf("primary region = %+v, want one chosen by %q with regions", primary, componentsdk.ChosenByConfig)
		}
	})

	t.Run("default credentials", func(t *testing.T) {
		useAccessKeys(t)
		responses := replaceResponses(kitResponses(), queryResponse("aws.sts.GetCallerIdentity", kitSTSURL,
			"<Arn>arn:aws:iam::111122223333:user/epack-collector</Arn><UserId>AIDAKITEXAMPLE</UserId><Account>"+kitAccountID+"</Account>"))
		accounts := targetsRun(t, map[string]any{"level": "audit"}, nil, responses).accounts
		if accounts.ChosenBy != componentsdk.ChosenByDiscovery || accounts.ConfigKey != "" || !countIs(accounts.Count, 1) {
			t.Errorf("accounts = %+v, want one chosen by %q", accounts, componentsdk.ChosenByDiscovery)
		}
	})
}

// twoRegionResponses answer the kit account with us-west-2 enabled beside
// its own region, where nothing is deployed.
func twoRegionResponses() []collectortest.Response {
	var items string
	for _, region := range []string{kitRegion, "us-west-2"} {
		items += "<item><regionName>" + region + "</regionName><regionEndpoint>ec2." + region + ".amazonaws.com</regionEndpoint><optInStatus>opt-in-not-required</optInStatus></item>"
	}
	responses := replaceResponses(kitResponses(), ec2Response("aws.ec2.DescribeRegions", "<regionInfo>"+items+"</regionInfo>"))
	return append(responses, emptyRegionResponses("us-west-2")...)
}

// A run over two regions declares both as the regions it scanned, and the
// first alone as the primary region, for the security services read there.
// The collector picks it from the regions it found, or the config lists it
// first.
func TestTargetsPrimaryRegion(t *testing.T) {
	cases := []struct {
		name          string
		regions       []any
		regionsChoice componentsdk.TargetChoice
		primaryChoice componentsdk.TargetChoice
		configKey     string
	}{
		{"regions found", nil, componentsdk.ChosenByDiscovery, componentsdk.ChosenByCollector, ""},
		{"regions listed", []any{kitRegion, "us-west-2"}, componentsdk.ChosenByConfig, componentsdk.ChosenByConfig, "regions"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateAWSEnvironment(t)
			config := kitConfig()
			config["level"] = "audit"
			if tc.regions != nil {
				config["regions"] = tc.regions
			}
			got := targetsRun(t, config, kitSecrets(), twoRegionResponses())

			regions := got.regions
			if regions.ChosenBy != tc.regionsChoice || regions.ConfigKey != tc.configKey {
				t.Errorf("regions chosen by %q with %q, want %q with %q", regions.ChosenBy, regions.ConfigKey, tc.regionsChoice, tc.configKey)
			}
			if !countIs(regions.Count, 2) || !completeIs(regions.Complete, true) {
				t.Errorf("regions count %v, complete %v; want 2 and true", regions.Count, regions.Complete)
			}

			primary := got.primary
			if primary.ChosenBy != tc.primaryChoice || primary.ConfigKey != tc.configKey {
				t.Errorf("primary region chosen by %q with %q, want %q with %q", primary.ChosenBy, primary.ConfigKey, tc.primaryChoice, tc.configKey)
			}
			if primary.At == nil || *primary.At != primaryAt || !slices.Equal(primary.For, primaryFor) {
				t.Errorf("primary region at %+v for %+v, want %+v for %+v", primary.At, primary.For, primaryAt, primaryFor)
			}
			if !countIs(primary.Count, 1) || !completeIs(primary.Complete, true) {
				t.Errorf("primary region count %v, complete %v; want 1 and true", primary.Count, primary.Complete)
			}

			var doc any
			decodeArtifact(t, got.run, awsPath, &doc)
			expectValues(t, doc, map[string]any{
				"/accounts/0/regions":        []any{kitRegion, "us-west-2"},
				"/accounts/0/primary_region": kitRegion,
			})
		})
	}
}

// When the region list can't be read, the primary region is left out with
// the regions, so neither holds a target and both are incomplete, with no
// finding.
func TestTargetsWithoutTheRegionList(t *testing.T) {
	isolateAWSEnvironment(t)
	config := kitConfig()
	config["level"] = "audit"
	got := targetsRun(t, config, kitSecrets(), emptyRegionListResponses())
	if regions := got.regions; !countIs(regions.Count, 0) || !completeIs(regions.Complete, false) {
		t.Errorf("regions count %v, complete %v; want 0 and false", regions.Count, regions.Complete)
	}
	if primary := got.primary; !countIs(primary.Count, 0) || !completeIs(primary.Complete, false) || !slices.Equal(primary.For, primaryFor) {
		t.Errorf("primary region = %+v, want none counted and incomplete for %+v", primary, primaryFor)
	}
	if g := gapAt(got.run, awsPath, "/accounts/0/primary_region"); g == nil {
		t.Error("primary_region has no gap, want the region list's")
	}
}
