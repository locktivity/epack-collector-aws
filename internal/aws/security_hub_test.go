package aws

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// GetEnabledStandards and ListEnabledProductsForImport answer a NextToken
// while more results remain, and every page is read.
func TestGetSecurityHubConfig_ReadsEveryPage(t *testing.T) {
	const (
		fsbp             = "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"
		cis              = "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0"
		guardDutyProduct = "arn:aws:securityhub:us-east-1:111122223333:product-subscription/aws/guardduty"
		inspectorProduct = "arn:aws:securityhub:us-east-1:111122223333:product-subscription/aws/inspector"
	)
	standard := func(arn string) string {
		return `{"StandardsArn":"` + arn + `","StandardsSubscriptionArn":"` + arn + `-sub","StandardsStatus":"READY","StandardsInput":{}}`
	}
	client := testClient(func(r *http.Request, body string) (string, string) {
		switch r.URL.Path {
		case "/accounts":
			return "application/json", `{"HubArn":"arn:aws:securityhub:us-east-1:111122223333:hub/default"}`
		case "/standards/get":
			if strings.Contains(body, `"NextToken":"page-2"`) {
				return "application/json", `{"StandardsSubscriptions":[` + standard(cis) + `]}`
			}
			return "application/json", `{"StandardsSubscriptions":[` + standard(fsbp) + `],"NextToken":"page-2"}`
		case "/productSubscriptions":
			if r.URL.Query().Get("NextToken") == "page-2" {
				return "application/json", `{"ProductSubscriptions":["` + inspectorProduct + `"]}`
			}
			return "application/json", `{"ProductSubscriptions":["` + guardDutyProduct + `"],"NextToken":"page-2"}`
		}
		return "application/json", `{}`
	})

	cfg, err := client.GetSecurityHubConfig(context.Background(), "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{fsbp, cis}; !reflect.DeepEqual(cfg.StandardsARNs, want) {
		t.Errorf("standards = %v, want %v", cfg.StandardsARNs, want)
	}
	if want := []string{guardDutyProduct, inspectorProduct}; !reflect.DeepEqual(cfg.ProductSubscriptions, want) || cfg.IntegrationCount != 2 {
		t.Errorf("product subscriptions = %v (count %d), want %v", cfg.ProductSubscriptions, cfg.IntegrationCount, want)
	}
}
