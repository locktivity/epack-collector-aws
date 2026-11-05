package aws

import (
	"context"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	guarddutytypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

func TestMatchesGuardDutyFindings(t *testing.T) {
	tests := []struct {
		name                string
		pattern             string
		wantMatch           bool
		wantFiltersSeverity bool
	}{
		{
			name:      "source alone selects findings",
			pattern:   `{"source":["aws.guardduty"]}`,
			wantMatch: true,
		},
		{
			name:      "detail-type alone selects findings",
			pattern:   `{"detail-type":["GuardDuty Finding"]}`,
			wantMatch: true,
		},
		{
			name:      "the console-generated pattern has both",
			pattern:   `{"source":["aws.guardduty"],"detail-type":["GuardDuty Finding"]}`,
			wantMatch: true,
		},
		{
			name:                "severity constraint is reported",
			pattern:             `{"source":["aws.guardduty"],"detail":{"severity":[{"numeric":[">=",7]}]}}`,
			wantMatch:           true,
			wantFiltersSeverity: true,
		},
		{
			name:      "detail constraint on another field is not a severity filter",
			pattern:   `{"source":["aws.guardduty"],"detail":{"type":["UnauthorizedAccess:EC2/SSHBruteForce"]}}`,
			wantMatch: true,
		},
		{
			name:      "guardduty among several sources still matches",
			pattern:   `{"source":["aws.securityhub","aws.guardduty"]}`,
			wantMatch: true,
		},
		{
			name:    "another service's rule",
			pattern: `{"source":["aws.ec2"]}`,
		},
		{
			name:    "prefix matcher objects are deliberately not recognised",
			pattern: `{"source":[{"prefix":"aws.guard"}]}`,
		},
		{
			// EventBridge ANDs the fields, so each of these selects GuardDuty
			// events that are not findings.
			name:    "S3 malware scan results",
			pattern: `{"source":["aws.guardduty"],"detail-type":["GuardDuty Malware Protection Object Scan Result"]}`,
		},
		{
			name:    "malware protection plan status",
			pattern: `{"source":["aws.guardduty"],"detail-type":["GuardDuty Malware Protection Resource Status Error","GuardDuty Malware Protection Resource Status Warning"]}`,
		},
		{
			name:    "runtime protection health",
			pattern: `{"source":["aws.guardduty"],"detail-type":["GuardDuty Runtime Protection Unhealthy"]}`,
		},
		{
			name:    "GuardDuty API calls delivered through CloudTrail",
			pattern: `{"source":["aws.guardduty"],"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventSource":["guardduty.amazonaws.com"]}}`,
		},
		{
			name:    "finding detail-type from another source",
			pattern: `{"source":["aws.securityhub"],"detail-type":["GuardDuty Finding"]}`,
		},
		{
			name:      "finding listed among other GuardDuty events",
			pattern:   `{"source":["aws.guardduty"],"detail-type":["GuardDuty Malware Protection Object Scan Result","GuardDuty Finding"]}`,
			wantMatch: true,
		},
		{
			name:    "schedule rules have no pattern",
			pattern: "",
		},
		{
			name:    "unparseable pattern",
			pattern: `{"source":`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, filtersSeverity := matchesGuardDutyFindings(tt.pattern)
			if match != tt.wantMatch {
				t.Errorf("matches = %v, want %v", match, tt.wantMatch)
			}
			if filtersSeverity != tt.wantFiltersSeverity {
				t.Errorf("filtersSeverity = %v, want %v", filtersSeverity, tt.wantFiltersSeverity)
			}
		})
	}
}

func TestEventTargetKind(t *testing.T) {
	tests := []struct {
		arn  string
		want string
	}{
		{"arn:aws:sns:us-east-1:123456789012:security-alerts", "sns"},
		{"arn:aws:lambda:us-east-1:123456789012:function:notify-slack", "lambda"},
		{"arn:aws:events:us-east-1:999999999999:event-bus/central-security", "event_bus"},
		{"arn:aws:events:us-east-1:123456789012:api-destination/pagerduty/abc-123", "api_destination"},
		{"arn:aws:sqs:us-east-1:123456789012:findings-queue", "sqs"},
		{"arn:aws:ssm:us-east-1:123456789012:document/run-remediation", "other"},
		{"arn:aws-us-gov:sns:us-gov-west-1:123456789012:security-alerts", "sns"},
		{"arn:aws-cn:sns:cn-north-1:123456789012:security-alerts", "sns"},
	}

	for _, tt := range tests {
		t.Run(tt.arn, func(t *testing.T) {
			if got := eventTargetKind(tt.arn); got != tt.want {
				t.Errorf("eventTargetKind(%q) = %q, want %q", tt.arn, got, tt.want)
			}
		})
	}
}

// A GovCloud rule that publishes to an SNS topic names the topic, so its
// subscribers are looked up.
func TestListGuardDutyNotificationRules_SNSTargetInAnyPartition(t *testing.T) {
	for _, topic := range []string{
		"arn:aws:sns:us-east-1:123456789012:security-alerts",
		"arn:aws-us-gov:sns:us-gov-west-1:123456789012:security-alerts",
	} {
		client := testClient(func(r *http.Request, _ string) (string, string) {
			switch r.Header.Get("X-Amz-Target") {
			case "AWSEvents.ListRules":
				return jsonContentType, `{"Rules":[{"Name":"guardduty-findings","State":"ENABLED","EventPattern":"{\"source\":[\"aws.guardduty\"],\"detail-type\":[\"GuardDuty Finding\"]}"}]}`
			case "AWSEvents.ListTargetsByRule":
				return jsonContentType, `{"Targets":[{"Id":"1","Arn":"` + topic + `"}]}`
			}
			return jsonContentType, `{}`
		})
		rules, err := client.ListGuardDutyNotificationRules(context.Background(), "us-east-1")
		if err != nil {
			t.Fatal(err)
		}
		if len(rules) != 1 || rules[0].TargetsByKind["sns"] != 1 || len(rules[0].TopicARNs) != 1 || rules[0].TopicARNs[0] != topic {
			t.Errorf("%s: rules = %+v, want one sns target naming the topic", topic, rules)
		}
	}
}

func guardDutyFindingOn(resource *guarddutytypes.Resource) guarddutytypes.Finding {
	return guarddutytypes.Finding{
		Id: aws.String("f-1"), Severity: aws.Float64(8), Type: aws.String("Exfiltration:S3/MaliciousIPCaller"), Title: aws.String("title"),
		Resource: resource,
	}
}

// A finding can carry several resources' details, and its resource type
// names the affected one, whose ID the row takes.
func TestProjectGuardDutyFinding_ResourceIDNamesTheAffectedResource(t *testing.T) {
	key := &guarddutytypes.AccessKeyDetails{AccessKeyId: aws.String("AKIAIOSFODNN7EXAMPLE"), UserName: aws.String("carol")}
	tests := []struct {
		name     string
		resource *guarddutytypes.Resource
		want     string
	}{
		{"instance", &guarddutytypes.Resource{ResourceType: aws.String("Instance"), InstanceDetails: &guarddutytypes.InstanceDetails{InstanceId: aws.String("i-0abc")}}, "i-0abc"},
		{"bucket with the caller's access key", &guarddutytypes.Resource{ResourceType: aws.String("S3Bucket"), AccessKeyDetails: key,
			S3BucketDetails: []guarddutytypes.S3BucketDetail{{Name: aws.String("payroll-exports")}}}, "payroll-exports"},
		{"access key", &guarddutytypes.Resource{ResourceType: aws.String("AccessKey"), AccessKeyDetails: key}, "AKIAIOSFODNN7EXAMPLE"},
		{"Lambda function", &guarddutytypes.Resource{ResourceType: aws.String("Lambda"), LambdaDetails: &guarddutytypes.LambdaDetails{
			FunctionName: aws.String("payments-processor"), FunctionArn: aws.String("arn:aws:lambda:us-east-1:111122223333:function:payments-processor")}}, "payments-processor"},
		{"ECS cluster", &guarddutytypes.Resource{ResourceType: aws.String("ECSCluster"), EcsClusterDetails: &guarddutytypes.EcsClusterDetails{
			Name: aws.String("checkout-cluster"), Arn: aws.String("arn:aws:ecs:us-east-1:111122223333:cluster/checkout-cluster")}}, "checkout-cluster"},
		{"container", &guarddutytypes.Resource{ResourceType: aws.String("Container"), ContainerDetails: &guarddutytypes.Container{
			Id: aws.String("3f2a9c1b"), Name: aws.String("web")}}, "3f2a9c1b"},
		{"RDS database instance", &guarddutytypes.Resource{ResourceType: aws.String("RDSDBInstance"), RdsDbInstanceDetails: &guarddutytypes.RdsDbInstanceDetails{
			DbInstanceIdentifier: aws.String("orders-db-1"), DbInstanceArn: aws.String("arn:aws:rds:us-east-1:111122223333:db:orders-db-1")}}, "orders-db-1"},
		{"RDS limitless database", &guarddutytypes.Resource{ResourceType: aws.String("RDSLimitlessDB"), RdsLimitlessDbDetails: &guarddutytypes.RdsLimitlessDbDetails{
			DbShardGroupIdentifier: aws.String("orders-shards"), DbClusterIdentifier: aws.String("orders")}}, "orders-shards"},
	}
	for _, tt := range tests {
		if got := projectGuardDutyFinding(guardDutyFindingOn(tt.resource), "det-1"); got.ResourceID != tt.want {
			t.Errorf("%s: ResourceID = %q, want %q", tt.name, got.ResourceID, tt.want)
		}
	}
}
