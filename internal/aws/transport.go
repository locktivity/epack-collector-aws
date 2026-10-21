package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/smithy-go"
	smithycbor "github.com/aws/smithy-go/encoding/cbor"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/locktivity/epack/componentsdk"
)

// CredentialHosts are the hosts AWS credentials may be sent to: every
// commercial and GovCloud endpoint, the China partition, and the dual-stack
// endpoints.
var CredentialHosts = []string{"*.amazonaws.com", "*.amazonaws.com.cn", "*.api.aws"}

// HTTPOptions configures the client every AWS call goes through. extraHosts
// adds hosts outside AWS that receive credentials, such as the CI provider's
// identity token endpoint.
func HTTPOptions(extraHosts ...string) componentsdk.HTTPOptions {
	return componentsdk.HTTPOptions{
		CredentialHosts:   append(append([]string{}, CredentialHosts...), extraHosts...),
		CredentialHeaders: []string{"X-Amz-Security-Token"},
		NameOperation:     NameOperation,
		ClassifyResponse:  ClassifyResponse,
	}
}

// NameOperation names an AWS SDK request "aws.<service>.<Operation>" from the
// service ID and operation name the SDK's middleware puts on the request's
// context. The collector only reads, so every operation is safe to retry.
func NameOperation(req *http.Request) (componentsdk.Operation, bool) {
	service := awsmiddleware.GetServiceID(req.Context())
	operation := awsmiddleware.GetOperationName(req.Context())
	if service == "" || operation == "" {
		return componentsdk.Operation{}, false
	}
	return componentsdk.Operation{Name: OperationName(service, operation), Safe: true}, true
}

// OperationName builds an operation name from an SDK service ID such as
// "Elastic Load Balancing v2" and an operation such as "DescribeListeners".
func OperationName(serviceID, operation string) string {
	service := strings.ToLower(strings.NewReplacer(" ", "", "-", "").Replace(serviceID))
	return "aws." + service + "." + operation
}

// ClassifyResponse gives a failed AWS response the code its error code calls
// for. AWS sends throttling, expired credentials, and denied access as 400
// in its JSON protocols, so the status alone misleads.
func ClassifyResponse(resp *http.Response, body []byte) (componentsdk.Code, bool) {
	return codeForErrorCode(responseErrorCode(resp.Header, body))
}

var (
	authFailedCodes = setOf(
		"AuthFailure", "ExpiredToken", "ExpiredTokenException", "IDPRejectedClaim",
		"IncompleteSignature", "InvalidAccessKeyId", "InvalidClientTokenId",
		"InvalidIdentityToken", "InvalidSignatureException", "MissingAuthenticationToken",
		"MissingAuthenticationTokenException", "RequestExpired", "SignatureDoesNotMatch",
		"TokenRefreshRequired", "UnrecognizedClientException",
	)
	permissionDeniedCodes = setOf(
		"AccessDenied", "AccessDeniedException", "AccessDeniedForDependencyException",
		"AllAccessDisabled", "AuthorizationError", "AuthorizationErrorException",
		"Forbidden", "ForbiddenException", "UnauthorizedAccess", "UnauthorizedException",
		"UnauthorizedOperation",
	)
	vendorErrorCodes = setOf(
		"InternalError", "InternalFailure", "InternalServerError", "InternalServerException",
		"ServiceException", "ServiceUnavailable", "ServiceUnavailableException", "Unavailable",
	)
)

func setOf(codes ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(codes))
	for _, c := range codes {
		out[c] = struct{}{}
	}
	return out
}

func codeForErrorCode(code string) (componentsdk.Code, bool) {
	if code == "" {
		return "", false
	}
	if _, ok := retry.DefaultThrottleErrorCodes[code]; ok {
		return componentsdk.CodeRateLimited, true
	}
	if _, ok := retry.DefaultRetryableErrorCodes[code]; ok {
		return componentsdk.CodeTimeout, true
	}
	if _, ok := authFailedCodes[code]; ok {
		return componentsdk.CodeAuthFailed, true
	}
	if _, ok := permissionDeniedCodes[code]; ok {
		return componentsdk.CodePermissionDenied, true
	}
	if _, ok := vendorErrorCodes[code]; ok {
		return componentsdk.CodeVendorError, true
	}
	return "", false
}

// responseErrorCode reads the error code from an AWS error response in any of
// the protocols the collector's services use: the X-Amzn-ErrorType header
// (REST JSON), a JSON body's __type or code (JSON 1.0 and 1.1), an XML body's
// Error/Code (Query, REST XML, and EC2's Response/Errors/Error/Code), or a
// CBOR body's __type (RPC v2, CloudWatch).
func responseErrorCode(header http.Header, body []byte) string {
	if v := header.Get("X-Amzn-ErrorType"); v != "" {
		return sanitizeErrorCode(v)
	}
	if v := header.Get("X-Amzn-Query-Error"); v != "" {
		code, _, _ := strings.Cut(v, ";")
		return sanitizeErrorCode(code)
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return ""
	}
	switch trimmed[0] {
	case '{':
		var e struct {
			Type      string `json:"__type"`
			Code      string `json:"code"`
			CodeUpper string `json:"Code"`
		}
		if json.Unmarshal(trimmed, &e) != nil {
			return ""
		}
		for _, v := range []string{e.Type, e.Code, e.CodeUpper} {
			if v != "" {
				return sanitizeErrorCode(v)
			}
		}
		return ""
	case '<':
		return xmlErrorCode(trimmed)
	default:
		v, err := smithycbor.Decode(trimmed)
		if err != nil {
			return ""
		}
		m, ok := v.(smithycbor.Map)
		if !ok {
			return ""
		}
		if s, ok := m["__type"].(smithycbor.String); ok {
			return sanitizeErrorCode(string(s))
		}
		return ""
	}
}

// xmlErrorCode returns the text of the first Code element inside an Error
// element.
func xmlErrorCode(body []byte) string {
	dec := xml.NewDecoder(bytes.NewReader(body))
	var stack []string
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "Code" && len(stack) > 0 && stack[len(stack)-1] == "Error" {
				var code string
				if dec.DecodeElement(&code, &t) != nil {
					return ""
				}
				return strings.TrimSpace(code)
			}
			stack = append(stack, t.Name.Local)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
}

// sanitizeErrorCode drops the namespace AWS prefixes to some codes
// ("com.amazon.coral#ThrottlingException") and the URI it appends to others
// ("ThrottlingException:http://internal.amazon.com/...").
func sanitizeErrorCode(code string) string {
	code, _, _ = strings.Cut(code, ":")
	if i := strings.LastIndex(code, "#"); i >= 0 {
		code = code[i+1:]
	}
	return strings.TrimSpace(code)
}

// apiError carries an AWS call's failure to componentsdk.Classify and the
// run's records: the code its response calls for, its status and headers,
// and AWS's own error code.
type apiError struct {
	code   componentsdk.Code
	status int
	header http.Header
	vendor string
	err    error
}

func (e *apiError) Error() string                     { return e.err.Error() }
func (e *apiError) Unwrap() error                     { return e.err }
func (e *apiError) CollectionCode() componentsdk.Code { return e.code }
func (e *apiError) HTTPStatus() int                   { return e.status }
func (e *apiError) HTTPHeader() http.Header           { return e.header }
func (e *apiError) VendorCode() string                { return e.vendor }

// codedError gives an SDK operation's error the code its response calls for:
// the ClassifyResponse hook's answer or the status for a failed response,
// and invalid_response for a successful one whose body the SDK could not
// read. Transport failures pass through for Classify, which reads them.
func codedError(err error) error {
	var respErr *smithyhttp.ResponseError
	if !errors.As(err, &respErr) || respErr.Response == nil || respErr.Response.Response == nil {
		return err
	}
	resp := respErr.Response.Response
	out := &apiError{err: err, vendor: apiErrorCode(err)}
	if out.vendor == "NonAPIError" {
		out.vendor = ""
	}
	var deserialization *smithy.DeserializationError
	switch {
	case resp.StatusCode >= 400:
		out.code = componentsdk.ClassifyResponse(resp)
		out.status = resp.StatusCode
		out.header = resp.Header
	case resp.StatusCode >= 200 && resp.StatusCode < 300 && errors.As(err, &deserialization):
		out.code = componentsdk.CodeInvalidResponse
	case resp.StatusCode == 0:
		return err
	}
	if out.code == "" && out.vendor == "" {
		return err
	}
	return out
}

// callError returns err as an error about the response it was built from, so
// a gap recorded from it names the call that response answered. The SDK
// builds its own errors from responses, and smithy's ResponseError keeps the
// response.
func callError(err error) error {
	var respErr *smithyhttp.ResponseError
	if !errors.As(err, &respErr) || respErr.Response == nil {
		return err
	}
	return componentsdk.ResponseError(respErr.Response.Response, err)
}

// codedErrors is the middleware that applies codedError and callError to
// every operation's error before the SDK wraps it in an OperationError.
type codedErrors struct{}

func (codedErrors) ID() string { return "EpackCodedErrors" }

func (codedErrors) HandleDeserialize(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (middleware.DeserializeOutput, middleware.Metadata, error) {
	out, metadata, err := next.HandleDeserialize(ctx, in)
	if err != nil {
		err = callError(codedError(err))
	}
	return out, metadata, err
}

func addCodedErrors(stack *middleware.Stack) error {
	return stack.Deserialize.Add(codedErrors{}, middleware.Before)
}

// inResponse returns err, an error the collector built from an answer the
// SDK read, as an error about that answer's response, so a gap recorded from
// it names the call. meta is the output's ResultMetadata, where the SDK keeps
// the response.
func inResponse(meta middleware.Metadata, err error) error {
	raw, ok := awsmiddleware.GetRawResponse(meta).(*smithyhttp.Response)
	if !ok {
		return err
	}
	return componentsdk.ResponseError(raw.Response, err)
}

// errMissing reports a response without a member the collector reads, such
// as a describe call without the object it describes. A missing list is not
// one: the SDK reads an empty list as nil, and AWS's JSON protocols leave
// empty lists out. meta is the output's ResultMetadata.
func errMissing(meta middleware.Metadata, call, member string) error {
	return inResponse(meta, componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("%s: the response has no %s", call, member)))
}

// errIncomplete reports a response that leaves out items the request named,
// such as a read by ID that answers for fewer IDs than it was given. meta is
// the output's ResultMetadata.
func errIncomplete(meta middleware.Metadata, call, items string, got, want int) error {
	return inResponse(meta, componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("%s: the response has %d of the %d %s asked for", call, got, want, items)))
}

// xmlServices are the services whose responses are XML documents. The SDK
// reads a successful response with no XML element as an empty result, so a
// body that is not XML would otherwise pass for an empty list.
var xmlServices = setOf("Auto Scaling", "CloudFront", "EC2", "Elastic Load Balancing v2", "IAM", "RDS", "S3", "S3 Control", "SNS", "STS")

// rawPayloadOperations answer with a document of their own as the body, not
// an XML result.
var rawPayloadOperations = setOf("aws.s3.GetBucketPolicy")

// requireXMLDocument fails a successful response from an XML service whose
// body has no XML element.
type requireXMLDocument struct{}

func (requireXMLDocument) ID() string { return "EpackRequireXMLDocument" }

func (requireXMLDocument) HandleDeserialize(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (middleware.DeserializeOutput, middleware.Metadata, error) {
	out, metadata, err := next.HandleDeserialize(ctx, in)
	if err != nil {
		return out, metadata, err
	}
	service := awsmiddleware.GetServiceID(ctx)
	if _, ok := xmlServices[service]; !ok {
		return out, metadata, nil
	}
	if _, ok := rawPayloadOperations[OperationName(service, awsmiddleware.GetOperationName(ctx))]; ok {
		return out, metadata, nil
	}
	resp, ok := out.RawResponse.(*smithyhttp.Response)
	if !ok || resp.StatusCode < 200 || resp.StatusCode >= 300 || resp.Body == nil {
		return out, metadata, nil
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return out, metadata, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if !hasXMLElement(body) {
		return out, metadata, &smithy.DeserializationError{Err: errors.New("the response body is not an XML document")}
	}
	return out, metadata, nil
}

func hasXMLElement(body []byte) bool {
	dec := xml.NewDecoder(bytes.NewReader(body))
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		if _, ok := tok.(xml.StartElement); ok {
			return true
		}
	}
}

func addRequireXMLDocument(stack *middleware.Stack) error {
	if _, ok := stack.Deserialize.Get("OperationDeserializer"); !ok {
		return nil
	}
	return stack.Deserialize.Insert(requireXMLDocument{}, "OperationDeserializer", middleware.After)
}

// useTransport sends cfg's calls through client and turns off the SDK's own
// retries, which client's transport already makes. Credential providers the
// SDK's default chain built before this keep their own client.
func useTransport(cfg *aws.Config, client *http.Client) {
	if client == nil {
		return
	}
	cfg.HTTPClient = client
	cfg.Retryer = func() aws.Retryer { return aws.NopRetryer{} }
	cfg.RetryMaxAttempts = 0
	cfg.APIOptions = append(cfg.APIOptions, addCodedErrors, addRequireXMLDocument)
}
