package aws

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

const testWebACLARN = "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/edge/a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"

// wafClient answers the regional web ACL listing with one web ACL whose
// GetWebACL answer holds webACLBody's fields, and GetRuleGroup with
// ruleGroup, or a 400 when it is "".
func wafClient(webACLBody, ruleGroup string) *AWSClient {
	return testClient(func(r *http.Request, _ string) (string, string) {
		switch target := r.Header.Get("X-Amz-Target"); {
		case strings.HasSuffix(target, ".ListWebACLs"):
			return jsonContentType, `{"WebACLs":[{"Name":"edge","Id":"a1b2c3d4-5678-90ab-cdef-EXAMPLE11111","ARN":"` + testWebACLARN + `","LockToken":"kit"}]}`
		case strings.HasSuffix(target, ".GetWebACL"):
			return jsonContentType, `{"LockToken":"kit","WebACL":{"Name":"edge","Id":"a1b2c3d4-5678-90ab-cdef-EXAMPLE11111","ARN":"` + testWebACLARN + `",` +
				`"DefaultAction":{"Allow":{}},"VisibilityConfig":{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"edge"},` + webACLBody + `}}`
		case strings.HasSuffix(target, ".GetRuleGroup"):
			return jsonContentType, ruleGroup
		case strings.HasSuffix(target, ".ListResourcesForWebACL"):
			return jsonContentType, `{"ResourceArns":[]}`
		case strings.HasSuffix(target, ".GetLoggingConfiguration"):
			return jsonContentType, `{"LoggingConfiguration":{"ResourceArn":"` + testWebACLARN + `","LogDestinationConfigs":["arn:aws:firehose:us-east-1:111122223333:deliverystream/aws-waf-logs-x"]}}`
		}
		return jsonContentType, `{}`
	})
}

func listOneWebACL(t *testing.T, client *AWSClient) WebACL {
	t.Helper()
	acls, err := client.ListWebACLs(context.Background(), WAFScopeRegional, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(acls) != 1 {
		t.Fatalf("web ACLs = %d, want 1", len(acls))
	}
	return acls[0]
}

// A Firewall Manager web ACL runs its policy's rule groups first and last,
// so they are among the web ACL's rules.
func TestListWebACLs_FirewallManagerRuleGroupsAreRules(t *testing.T) {
	group := `{"Name":"fms-baseline","Priority":10,"OverrideAction":{"None":{}},` +
		`"FirewallManagerStatement":{"ManagedRuleGroupStatement":{"VendorName":"AWS","Name":"AWSManagedRulesCommonRuleSet"}},` +
		`"VisibilityConfig":{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"fms"}}`
	for _, field := range []string{"PreProcessFirewallManagerRuleGroups", "PostProcessFirewallManagerRuleGroups"} {
		acl := listOneWebACL(t, wafClient(`"ManagedByFirewallManager":true,"Rules":[],"`+field+`":[`+group+`]`, ""))
		if len(acl.Rules) != 1 || acl.Rules[0].Name != "fms-baseline" || acl.Rules[0].ManagedRuleGroupName != "AWSManagedRulesCommonRuleSet" {
			t.Errorf("%s: rules = %+v, want the Firewall Manager rule group", field, acl.Rules)
		}
	}
}

// A rule group the web ACL references is read, and a rate-based rule in it
// that blocks counts unless the web ACL runs the group in count mode.
func TestListWebACLs_RuleGroupRateBasedBlock(t *testing.T) {
	const groupARN = "arn:aws:wafv2:us-east-1:111122223333:regional/rulegroup/throttle/c3d4e5f6-7890-12ab-cdef-EXAMPLE33333"
	reference := func(override string) string {
		return `"Rules":[{"Name":"throttle","Priority":0,"OverrideAction":{"` + override + `":{}},` +
			`"Statement":{"RuleGroupReferenceStatement":{"ARN":"` + groupARN + `"}},` +
			`"VisibilityConfig":{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"throttle"}}]`
	}
	group := `{"LockToken":"kit","RuleGroup":{"Name":"throttle","Id":"c3d4e5f6-7890-12ab-cdef-EXAMPLE33333","ARN":"` + groupARN + `","Capacity":20,` +
		`"VisibilityConfig":{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"throttle"},` +
		`"Rules":[{"Name":"per-ip","Priority":0,"Action":{"Block":{}},"Statement":{"RateBasedStatement":{"Limit":2000,"AggregateKeyType":"IP"}},` +
		`"VisibilityConfig":{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"per-ip"}}]}}`

	if rule := listOneWebACL(t, wafClient(reference("None"), group)).Rules[0]; !rule.GroupRateBasedBlock || rule.RuleGroupARN != groupARN {
		t.Errorf("rule = %+v, want the group's rate-based block found", rule)
	}
	if rule := listOneWebACL(t, wafClient(reference("Count"), group)).Rules[0]; rule.GroupRateBasedBlock {
		t.Errorf("rule = %+v, want no block for a group run in count mode", rule)
	}
	acl := listOneWebACL(t, wafClient(reference("None"), `{}`))
	if acl.Rules[0].GroupErr == nil || acl.RuleGroupsErr == nil {
		t.Errorf("rule = %+v, want the unreadable group's error recorded", acl.Rules[0])
	}
}

// The web ACL can set a group's rule to another action with
// RuleActionOverrides, or to Count with the older ExcludedRules. The
// group's rate-based rule blocks when the action it ends up with is Block.
func TestListWebACLs_RuleGroupActionOverrides(t *testing.T) {
	const groupARN = "arn:aws:wafv2:us-east-1:111122223333:regional/rulegroup/throttle/c3d4e5f6-7890-12ab-cdef-EXAMPLE33333"
	reference := func(extras string) string {
		return `"Rules":[{"Name":"throttle","Priority":0,"OverrideAction":{"None":{}},` +
			`"Statement":{"RuleGroupReferenceStatement":{"ARN":"` + groupARN + `"` + extras + `}},` +
			`"VisibilityConfig":{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"throttle"}}]`
	}
	group := func(action string) string {
		return `{"LockToken":"kit","RuleGroup":{"Name":"throttle","Id":"c3d4e5f6-7890-12ab-cdef-EXAMPLE33333","ARN":"` + groupARN + `","Capacity":20,` +
			`"VisibilityConfig":{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"throttle"},` +
			`"Rules":[{"Name":"per-ip","Priority":0,"Action":{"` + action + `":{}},"Statement":{"RateBasedStatement":{"Limit":2000,"AggregateKeyType":"IP"}},` +
			`"VisibilityConfig":{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"per-ip"}}]}}`
	}
	for _, tc := range []struct {
		name, extras, action string
		blocks               bool
	}{
		{"block rule excluded", `,"ExcludedRules":[{"Name":"per-ip"}]`, "Block", false},
		{"another rule excluded", `,"ExcludedRules":[{"Name":"some-other-rule"}]`, "Block", true},
		{"count rule overridden to block", `,"RuleActionOverrides":[{"Name":"per-ip","ActionToUse":{"Block":{}}}]`, "Count", true},
		{"count rule not overridden", ``, "Count", false},
		{"count rule overridden to count", `,"RuleActionOverrides":[{"Name":"per-ip","ActionToUse":{"Count":{}}}]`, "Count", false},
		{"block rule overridden to count", `,"RuleActionOverrides":[{"Name":"per-ip","ActionToUse":{"Count":{}}}]`, "Block", false},
	} {
		if rule := listOneWebACL(t, wafClient(reference(tc.extras), group(tc.action))).Rules[0]; rule.GroupRateBasedBlock != tc.blocks {
			t.Errorf("%s: GroupRateBasedBlock = %v, want %v", tc.name, rule.GroupRateBasedBlock, tc.blocks)
		}
	}
}
