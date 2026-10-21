package aws

import (
	"net/http"
	"testing"

	smithycbor "github.com/aws/smithy-go/encoding/cbor"
	"github.com/locktivity/epack/componentsdk"
)

func TestOperationName(t *testing.T) {
	cases := map[[2]string]string{
		{"Elastic Load Balancing v2", "DescribeListeners"}: "aws.elasticloadbalancingv2.DescribeListeners",
		{"CloudWatch Logs", "DescribeLogGroups"}:           "aws.cloudwatchlogs.DescribeLogGroups",
		{"SSO Admin", "ListInstances"}:                     "aws.ssoadmin.ListInstances",
		{"S3 Control", "GetPublicAccessBlock"}:             "aws.s3control.GetPublicAccessBlock",
		{"STS", "AssumeRoleWithWebIdentity"}:               "aws.sts.AssumeRoleWithWebIdentity",
	}
	for in, want := range cases {
		if got := OperationName(in[0], in[1]); got != want {
			t.Errorf("OperationName(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

func TestResponseErrorCode(t *testing.T) {
	cbor := smithycbor.Encode(smithycbor.Map{"__type": smithycbor.String("com.amazonaws.cloudwatch#ThrottlingException")})
	cases := []struct {
		name   string
		header http.Header
		body   string
		want   string
	}{
		{"REST JSON header", http.Header{"X-Amzn-Errortype": {"ThrottlingException:http://internal.amazon.com/coral/com.amazon.coral.service/"}}, "{}", "ThrottlingException"},
		{"Query compatible header", http.Header{"X-Amzn-Query-Error": {"Throttling;Sender"}}, "{}", "Throttling"},
		{"JSON __type with a namespace", nil, `{"__type":"com.amazon.coral.service#ExpiredTokenException","message":"expired"}`, "ExpiredTokenException"},
		{"JSON code", nil, `{"code":"AccessDeniedException","message":"denied"}`, "AccessDeniedException"},
		{"Query XML", nil, "<ErrorResponse><Error><Type>Sender</Type><Code>Throttling</Code><Message>Rate exceeded</Message></Error></ErrorResponse>", "Throttling"},
		{"EC2 XML", nil, "<Response><Errors><Error><Code>RequestLimitExceeded</Code></Error></Errors><RequestID>r</RequestID></Response>", "RequestLimitExceeded"},
		{"S3 XML", nil, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>SlowDown</Code><Message>Reduce your request rate.</Message></Error>", "SlowDown"},
		{"RPC v2 CBOR", nil, string(cbor), "ThrottlingException"},
		{"an XML body with no error", nil, "<Code>NotAnError</Code>", ""},
		{"an empty body", nil, "", ""},
		{"a body that is not JSON", nil, "{not json", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := responseErrorCode(tc.header, []byte(tc.body)); got != tc.want {
				t.Errorf("responseErrorCode() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClassifyResponse(t *testing.T) {
	cases := []struct {
		body string
		want componentsdk.Code
	}{
		{`{"__type":"ThrottlingException"}`, componentsdk.CodeRateLimited},
		{`{"__type":"TooManyRequestsException"}`, componentsdk.CodeRateLimited},
		{"<Error><Code>SlowDown</Code></Error>", componentsdk.CodeRateLimited},
		{`{"__type":"RequestTimeoutException"}`, componentsdk.CodeTimeout},
		{`{"__type":"ExpiredTokenException"}`, componentsdk.CodeAuthFailed},
		{"<ErrorResponse><Error><Code>InvalidIdentityToken</Code></Error></ErrorResponse>", componentsdk.CodeAuthFailed},
		{`{"__type":"AccessDeniedException"}`, componentsdk.CodePermissionDenied},
		{"<Response><Errors><Error><Code>UnauthorizedOperation</Code></Error></Errors></Response>", componentsdk.CodePermissionDenied},
		{`{"__type":"InternalServerException"}`, componentsdk.CodeVendorError},
	}
	for _, tc := range cases {
		resp := &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{}}
		code, ok := ClassifyResponse(resp, []byte(tc.body))
		if !ok || code != tc.want {
			t.Errorf("ClassifyResponse(%s) = %q, %v, want %q", tc.body, code, ok, tc.want)
		}
	}

	resp := &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}}
	if code, ok := ClassifyResponse(resp, []byte("<Error><Code>NoSuchPublicAccessBlockConfiguration</Code></Error>")); ok {
		t.Errorf("ClassifyResponse() = %q for an error code that is an answer, want no classification so the status decides", code)
	}
}

func TestHasXMLElement(t *testing.T) {
	if !hasXMLElement([]byte(`<?xml version="1.0"?><ListBucketsResult/>`)) {
		t.Error("an XML document should have an element")
	}
	for _, body := range []string{"", "{}", "not xml", `<?xml version="1.0"?>`} {
		if hasXMLElement([]byte(body)) {
			t.Errorf("hasXMLElement(%q) = true, want false", body)
		}
	}
}
