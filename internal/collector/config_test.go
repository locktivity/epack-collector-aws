package collector

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// runDetailed runs the kit's account with responses and returns the detailed
// artifact decoded generically, so an absent value differs from a zero one.
func runDetailed(t *testing.T, responses []collectortest.Response) any {
	t.Helper()
	isolateAWSEnvironment(t)
	res := runKit(t, kitConfig(), kitSecrets(), responses)
	if res.ExitCode != 0 {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	var doc any
	decodeArtifact(t, res, awsPath, &doc)
	return doc
}

// valueAt returns the value at a JSON pointer in doc, and whether it is
// present.
func valueAt(doc any, pointer string) (any, bool) {
	cur := doc
	for _, part := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		switch v := cur.(type) {
		case map[string]any:
			next, ok := v[part]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(v) {
				return nil, false
			}
			cur = v[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

// expectValues fails t for each pointer whose value in doc is not the one
// wanted. A nil want means absent.
func expectValues(t *testing.T, doc any, want map[string]any) {
	t.Helper()
	for pointer, w := range want {
		got, ok := valueAt(doc, pointer)
		switch {
		case w == nil && ok:
			t.Errorf("%s = %v, want it absent", pointer, got)
		case w != nil && !ok:
			t.Errorf("%s is absent, want %v", pointer, w)
		case w != nil && fmt.Sprint(got) != fmt.Sprint(w):
			t.Errorf("%s = %v, want %v", pointer, got, w)
		}
	}
}

// include_global follows the recording strategy. includeGlobalResourceTypes
// adds the global IAM types to an all-supported recorder only, an exclusion
// strategy records them unless it excludes them, and an inclusion strategy
// records the ones it lists.
func TestConfig_IncludeGlobalFollowsTheRecordingStrategy(t *testing.T) {
	iam := []string{"AWS::IAM::User", "AWS::IAM::Group", "AWS::IAM::Role", "AWS::IAM::Policy"}
	for _, tc := range []struct {
		name  string
		group map[string]any
		want  bool
	}{
		{"all supported with global types", map[string]any{
			"allSupported": true, "includeGlobalResourceTypes": true,
			"recordingStrategy": map[string]any{"useOnly": "ALL_SUPPORTED_RESOURCE_TYPES"},
		}, true},
		{"exclusion strategy excluding one other type", map[string]any{
			"allSupported": false, "includeGlobalResourceTypes": false,
			"recordingStrategy":        map[string]any{"useOnly": "EXCLUSION_BY_RESOURCE_TYPES"},
			"exclusionByResourceTypes": map[string]any{"resourceTypes": []string{"AWS::Config::ResourceCompliance"}},
		}, true},
		{"exclusion strategy excluding the global IAM types", map[string]any{
			"allSupported": false, "includeGlobalResourceTypes": false,
			"recordingStrategy":        map[string]any{"useOnly": "EXCLUSION_BY_RESOURCE_TYPES"},
			"exclusionByResourceTypes": map[string]any{"resourceTypes": iam},
		}, false},
		{"inclusion strategy listing the IAM types", map[string]any{
			"allSupported": false, "includeGlobalResourceTypes": false,
			"recordingStrategy": map[string]any{"useOnly": "INCLUSION_BY_RESOURCE_TYPES"},
			"resourceTypes":     iam,
		}, true},
		{"inclusion strategy with no IAM type", map[string]any{
			"allSupported": false, "includeGlobalResourceTypes": false,
			"recordingStrategy": map[string]any{"useOnly": "INCLUSION_BY_RESOURCE_TYPES"},
			"resourceTypes":     []string{"AWS::S3::Bucket", "AWS::EC2::SecurityGroup"},
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := runDetailed(t, replaceResponses(kitResponses(),
				jsonResponse("aws.configservice.DescribeConfigurationRecorders", regional("config"), map[string]any{"ConfigurationRecorders": []any{map[string]any{
					"name": "default", "roleARN": "arn:aws:iam::111122223333:role/aws-config", "recordingGroup": tc.group,
				}}})))
			expectValues(t, doc, map[string]any{"/accounts/0/account_security/config/recorders/0/include_global": tc.want})
		})
	}
}

// last_evaluated is when the rule last evaluated successfully, so a rule
// whose evaluations have only failed has none.
func TestConfig_LastEvaluatedIsTheLastSuccess(t *testing.T) {
	const pointer = "/accounts/0/account_security/config/rules/0/last_evaluated"
	for _, tc := range []struct {
		name   string
		status map[string]any
		want   any
	}{
		{"successful evaluation", map[string]any{"LastSuccessfulEvaluationTime": 1767222000}, "2025-12-31T23:00:00Z"},
		{"success and a later failure", map[string]any{"LastSuccessfulEvaluationTime": 1767222000, "LastFailedEvaluationTime": 1767225000}, "2025-12-31T23:00:00Z"},
		{"failures only", map[string]any{"LastFailedEvaluationTime": 1767222000, "LastErrorCode": "AccessDenied", "FirstEvaluationStarted": true}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.status["ConfigRuleName"] = "s3-bucket-public-read-prohibited"
			doc := runDetailed(t, replaceResponses(kitResponses(),
				jsonResponse("aws.configservice.DescribeConfigRuleEvaluationStatus", regional("config"),
					map[string]any{"ConfigRulesEvaluationStatus": []any{tc.status}})))
			expectValues(t, doc, map[string]any{pointer: tc.want})
		})
	}
}

// The primary region does not depend on the order DescribeRegions lists the
// regions in, which AWS does not promise.
func TestConfig_PrimaryRegionDoesNotDependOnRegionOrder(t *testing.T) {
	notSubscribed := `{"__type":"InvalidAccessException","Code":"InvalidAccessException","Message":"Account 111122223333 is not subscribed to AWS Security Hub"}`
	for _, order := range [][]string{{"us-east-1", "us-west-2"}, {"us-west-2", "us-east-1"}} {
		t.Run(strings.Join(order, " then "), func(t *testing.T) {
			var items string
			for _, region := range order {
				items += "<item><regionName>" + region + "</regionName><regionEndpoint>ec2." + region + ".amazonaws.com</regionEndpoint><optInStatus>opt-in-not-required</optInStatus></item>"
			}
			responses := replaceResponses(kitResponses(), ec2Response("aws.ec2.DescribeRegions", "<regionInfo>"+items+"</regionInfo>"))
			responses = append(responses, emptyRegionResponses("us-west-2")...)
			responses = append(responses, inRegion("us-west-2",
				jsonResponse("aws.configservice.DescribeConfigurationRecorders", regional("config"), map[string]any{"ConfigurationRecorders": []any{}}),
				restResponse("aws.securityhub.DescribeHub", http.MethodGet, "https://securityhub.us-east-1.amazonaws.com/accounts", http.StatusUnauthorized, notSubscribed),
				restResponse("aws.securityhub.GetFindings", http.MethodPost, "https://securityhub.us-east-1.amazonaws.com/findings", http.StatusUnauthorized, notSubscribed),
			)...)
			doc := runDetailed(t, responses)
			expectValues(t, doc, map[string]any{
				"/accounts/0/primary_region":                  "us-east-1",
				"/accounts/0/account_security/config/enabled": true,
			})
		})
	}
}

// configDenied answers a Config call as AWS does when the caller's policy
// refuses it.
func configDenied(op string) collectortest.Response {
	return collectortest.Response{
		Operation: op, Method: http.MethodPost, URL: regional("config"), Status: http.StatusBadRequest,
		Header: jsonHeader("application/x-amz-json-1.1"),
		Body:   `{"__type":"AccessDeniedException","message":"User is not authorized to perform: ` + op + `"}`,
	}
}

// configSection runs the kit's account with config and responses and returns
// its config section decoded generically.
func configSection(t *testing.T, config map[string]any, responses []collectortest.Response) map[string]any {
	t.Helper()
	isolateAWSEnvironment(t)
	res := runKit(t, config, kitSecrets(), responses)
	if res.ExitCode != 0 {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	var doc any
	decodeArtifact(t, res, awsPath, &doc)
	v, _ := valueAt(doc, "/accounts/0/account_security/config")
	section, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("config section is %T, want an object", v)
	}
	return section
}

// leftOut reports whether section has key as null or leaves it out.
func leftOut(section map[string]any, key string) bool {
	v, ok := section[key]
	return !ok || v == nil
}

// When the rule list, or a compliance read joined to it, is refused, the
// rules and their truncation companions are left out.
func TestConfig_RuleCompanionsLeftOutWhenRulesCannotBeRead(t *testing.T) {
	for _, op := range []string{
		"aws.configservice.DescribeConfigRules",
		"aws.configservice.DescribeComplianceByConfigRule",
		"aws.configservice.DescribeConfigRuleEvaluationStatus",
		"aws.configservice.DescribeConfigurationRecorders",
	} {
		t.Run(actionOf(op), func(t *testing.T) {
			section := configSection(t, kitConfig(), replaceResponses(kitResponses(), configDenied(op)))
			for _, key := range []string{"rules", "rules_truncated", "rules_dropped_count"} {
				if !leftOut(section, key) {
					t.Errorf("%s = %v after %s was refused, want it left out", key, section[key], actionOf(op))
				}
			}
		})
	}
	section := configSection(t, kitConfig(), kitResponses())
	if section["rules_truncated"] != false || section["rules_dropped_count"] != float64(0) {
		t.Errorf("rules_truncated = %v, rules_dropped_count = %v, want false and 0", section["rules_truncated"], section["rules_dropped_count"])
	}
}

// Rules can exist without a customer managed recorder, for example the rules
// Security Hub creates beside its service-linked recorder.
func TestConfig_RulesListedWithoutACustomerRecorder(t *testing.T) {
	const rule = "securityhub-s3-bucket-public-read-prohibited-1a2b3c"
	responses := replaceResponses(kitResponses(),
		jsonResponse("aws.configservice.DescribeConfigurationRecorders", regional("config"), map[string]any{"ConfigurationRecorders": []any{}}),
		jsonResponse("aws.configservice.DescribeConfigRules", regional("config"), map[string]any{"ConfigRules": []any{map[string]any{
			"ConfigRuleName": rule, "ConfigRuleArn": "arn:aws:config:us-east-1:111122223333:config-rule/config-rule-sh",
			"ConfigRuleState": "ACTIVE", "CreatedBy": "securityhub.amazonaws.com",
			"Source": map[string]any{"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"},
		}}}),
		jsonResponse("aws.configservice.DescribeComplianceByConfigRule", regional("config"), map[string]any{"ComplianceByConfigRules": []any{map[string]any{
			"ConfigRuleName": rule, "Compliance": map[string]any{"ComplianceType": "NON_COMPLIANT"},
		}}}),
		jsonResponse("aws.configservice.DescribeConfigRuleEvaluationStatus", regional("config"), map[string]any{"ConfigRulesEvaluationStatus": []any{map[string]any{
			"ConfigRuleName": rule, "LastSuccessfulEvaluationTime": 1767222000,
		}}}),
	)
	section := configSection(t, kitConfig(), responses)
	if section["enabled"] != false {
		t.Errorf("enabled = %v, want false with no recorder", section["enabled"])
	}
	rules, _ := section["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("rules = %v, want the account's one rule", section["rules"])
	}
	if row, _ := rules[0].(map[string]any); row["compliance_state"] != "NON_COMPLIANT" {
		t.Errorf("compliance_state = %v, want NON_COMPLIANT", row["compliance_state"])
	}
}

// The regions AWS Config reached after February 2022 cannot record the global
// IAM types, so a recorder there does not include them whatever its
// recording group says. This includes ap-east-2 and ap-southeast-6, which the
// AWS Config list of those regions leaves out.
func TestConfig_IncludeGlobalIsFalseWhereIAMCannotBeRecorded(t *testing.T) {
	group := map[string]any{
		"allSupported": true, "includeGlobalResourceTypes": true,
		"recordingStrategy": map[string]any{"useOnly": "ALL_SUPPORTED_RESOURCE_TYPES"},
	}
	recorder := jsonResponse("aws.configservice.DescribeConfigurationRecorders", regional("config"), map[string]any{"ConfigurationRecorders": []any{map[string]any{
		"name": "default", "roleARN": "arn:aws:iam::111122223333:role/aws-config", "recordingGroup": group,
	}}})
	shub := `{"__type":"InvalidAccessException","Code":"InvalidAccessException","Message":"Account 111122223333 is not subscribed to AWS Security Hub"}`
	for region, want := range map[string]bool{
		kitRegion: true, "ap-southeast-3": true,
		"eu-central-2": false, "me-central-1": false, "il-central-1": false, "ap-east-2": false, "ap-southeast-6": false,
	} {
		t.Run(region, func(t *testing.T) {
			responses := replaceResponses(kitResponses(), recorder)
			if region != kitRegion {
				responses = append(responses, emptyRegionResponses(region)...)
				responses = append(responses, inRegion(region, recorder,
					jsonResponse("aws.configservice.DescribeConfigurationRecorderStatus", regional("config"), map[string]any{"ConfigurationRecordersStatus": []any{map[string]any{
						"name": "default", "recording": true, "lastStatus": "SUCCESS",
					}}}),
					restResponse("aws.securityhub.DescribeHub", http.MethodGet, "https://securityhub.us-east-1.amazonaws.com/accounts", http.StatusUnauthorized, shub),
					restResponse("aws.securityhub.GetFindings", http.MethodPost, "https://securityhub.us-east-1.amazonaws.com/findings", http.StatusUnauthorized, shub),
				)...)
			}
			cfg := kitConfig()
			cfg["regions"] = []any{region}
			recorders, _ := configSection(t, cfg, responses)["recorders"].([]any)
			if len(recorders) != 1 {
				t.Fatalf("recorders = %v, want one", recorders)
			}
			if row, _ := recorders[0].(map[string]any); row["region"] != region || row["include_global"] != want {
				t.Errorf("recorder in %v: include_global = %v, want %v", row["region"], row["include_global"], want)
			}
		})
	}
}
