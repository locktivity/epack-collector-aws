package collector

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	smithycbor "github.com/aws/smithy-go/encoding/cbor"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

// The kit tenant is one account in one region, signed in through GitHub
// Actions OIDC. Calls in AWS's Query and JSON protocols all go to one URL per
// service and name their operation in the body, so the replay tells them
// apart by operation. A call that names an item, such as one trail's status
// or one user's MFA devices, gets its item's answer by RequestBody, which
// matches a JSON body or the fields of a Query or EC2 form body. The replay
// answers a call with the first response whose RequestBody its body holds, so
// the response to a narrower query comes before a broader one's. REST calls
// are matched by URL.
const (
	kitAccountID   = "111122223333"
	kitRegion      = "us-east-1"
	kitRoleARN     = "arn:aws:iam::111122223333:role/epack-collector"
	kitTokenURL    = "https://token.actions.githubusercontent.test/idtoken?api-version=2.0"
	kitTokenQuery  = kitTokenURL + "&audience=sts.amazonaws.com"
	kitRequestTok  = "kit-github-request-token-0123456789"
	kitSessionTok  = "kit-session-token-FwoGZXIvYXdzEBYaDKit0123456789"
	kitSecretKey   = "kit-secret-access-key-0123456789abcdef"
	kitIdentityJWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvOm5vcnRod2luZC9jb21wbGlhbmNlIn0.kit"

	kitIAMURL     = "https://iam.amazonaws.com/"
	kitSTSURL     = "https://sts.us-east-1.amazonaws.com/"
	kitEC2URL     = "https://ec2.us-east-1.amazonaws.com/"
	kitS3URL      = "https://s3.us-east-1.amazonaws.com"
	kitLogsBucket = "northwind-logs"
	kitAppBucket  = "northwind-app"

	kitTopicARN     = "arn:aws:sns:us-east-1:111122223333:northwind-alerts"
	kitALBARN       = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/northwind-web/50dc6c495c0c9188"
	kitDetectorID   = "12abc34d567e8fa901bc2d34e56789f0"
	kitInstanceARN  = "arn:aws:sso:::instance/ssoins-1111222233334444"
	kitStoreID      = "d-9067111111"
	kitPermSetARN   = "arn:aws:sso:::permissionSet/ssoins-1111222233334444/ps-1111222233334444"
	kitKMSKeyID     = "1234abcd-12ab-34cd-56ef-1234567890ab"
	kitImportedKey  = "abcd1234-ab12-cd34-ef56-abcdef123456"
	kitWebACLARN    = "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/northwind-edge/a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"
	kitCDNWebACLARN = "arn:aws:wafv2:us-east-1:111122223333:global/webacl/northwind-cdn/b2c3d4e5-6789-01ab-cdef-EXAMPLE22222"
	kitClusterARN   = "arn:aws:ecs:us-east-1:111122223333:cluster/northwind"
	kitServiceARN   = "arn:aws:ecs:us-east-1:111122223333:service/northwind/api"
	kitFunctionName = "northwind-api"
)

var kitClock = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func kitConfig() map[string]any {
	return map[string]any{
		"role_arn":  kitRoleARN,
		"auth_mode": "oidc",
		"level":     "internal",
	}
}

func kitSecrets() map[string]string {
	return map[string]string{
		"ACTIONS_ID_TOKEN_REQUEST_URL":   kitTokenURL,
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": kitRequestTok,
	}
}

// kitCanaries are values the collector holds that no output may carry: the
// identity token and the role session's credentials.
func kitCanaries() map[string]string {
	canaries := kitSecrets()
	canaries["KIT_IDENTITY_TOKEN"] = kitIdentityJWT
	canaries["KIT_SESSION_TOKEN"] = kitSessionTok
	canaries["KIT_SECRET_ACCESS_KEY"] = kitSecretKey
	return canaries
}

func xmlHeader() http.Header { return http.Header{"Content-Type": []string{"text/xml"}} }

func jsonHeader(contentType string) http.Header {
	return http.Header{"Content-Type": []string{contentType}}
}

func actionOf(op string) string { return op[strings.LastIndex(op, ".")+1:] }

// queryResponse answers an AWS Query protocol call (IAM, STS, RDS, ELB,
// Auto Scaling, SNS).
func queryResponse(op, endpoint, result string) collectortest.Response {
	action := actionOf(op)
	return collectortest.Response{
		Operation: op,
		Method:    http.MethodPost,
		URL:       endpoint,
		Header:    xmlHeader(),
		Body: "<" + action + "Response xmlns=\"https://kit.amazonaws.com/doc/\"><" + action + "Result>" + result +
			"</" + action + "Result><ResponseMetadata><RequestId>kit-request</RequestId></ResponseMetadata></" + action + "Response>",
	}
}

// queryItemResponse answers the Query protocol calls of op whose form body
// holds fields, such as the read of one item.
func queryItemResponse(op, endpoint string, fields map[string]string, result string) collectortest.Response {
	return withRequestBody(queryResponse(op, endpoint, result), formFields(op, fields))
}

// ec2Response answers an EC2 Query protocol call.
func ec2Response(op, inner string) collectortest.Response {
	action := actionOf(op)
	return collectortest.Response{
		Operation: op,
		Method:    http.MethodPost,
		URL:       kitEC2URL,
		Header:    xmlHeader(),
		Body: "<" + action + "Response xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\"><requestId>kit-request</requestId>" +
			inner + "</" + action + "Response>",
	}
}

// ec2ItemResponse answers the EC2 calls of op whose form body holds fields.
func ec2ItemResponse(op string, fields map[string]string, inner string) collectortest.Response {
	return withRequestBody(ec2Response(op, inner), formFields(op, fields))
}

// formFields is what the form body of a Query or EC2 call of op holds: its
// action and fields, each a string.
func formFields(op string, fields map[string]string) map[string]any {
	out := map[string]any{"Action": actionOf(op)}
	for k, v := range fields {
		out[k] = v
	}
	return out
}

// jsonResponse answers an AWS JSON 1.1 protocol call.
func jsonResponse(op, endpoint string, body any) collectortest.Response {
	return collectortest.Response{
		Operation: op,
		Method:    http.MethodPost,
		URL:       endpoint,
		Header:    jsonHeader("application/x-amz-json-1.1"),
		Body:      kitJSON(body),
	}
}

// jsonItemResponse answers the AWS JSON 1.1 calls of op whose body holds
// request, such as the read of one item.
func jsonItemResponse(op, endpoint string, request map[string]any, body any) collectortest.Response {
	return withRequestBody(jsonResponse(op, endpoint, body), request)
}

// restResponse answers a REST JSON or REST XML call by its URL.
func restResponse(op, method, target string, status int, body string) collectortest.Response {
	header := jsonHeader("application/json")
	if strings.HasPrefix(strings.TrimSpace(body), "<") {
		header = xmlHeader()
	}
	return collectortest.Response{Operation: op, Method: method, URL: target, Status: status, Header: header, Body: body}
}

// withRequestBody limits r to the calls whose body holds request.
func withRequestBody(r collectortest.Response, request map[string]any) collectortest.Response {
	r.RequestBody = kitJSON(request)
	return r
}

// cborResponse answers a Smithy RPC v2 CBOR call (CloudWatch).
func cborResponse(op, target string, body smithycbor.Map) collectortest.Response {
	return collectortest.Response{
		Operation: op,
		Method:    http.MethodPost,
		URL:       target,
		Header:    http.Header{"Content-Type": []string{"application/cbor"}, "Smithy-Protocol": []string{"rpc-v2-cbor"}},
		Body:      string(smithycbor.Encode(body)),
	}
}

func kitJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// s3Error is an S3 error body, such as the 404 that says a bucket has no
// policy.
func s3Error(code string) string {
	return "<Error><Code>" + code + "</Code><Message>kit</Message><RequestId>kit-request</RequestId></Error>"
}

func bucketURL(bucket, query string) string {
	return "https://" + bucket + ".s3.us-east-1.amazonaws.com/?" + query
}

// kitResponses answer every call a clean internal-level run makes.
func kitResponses() []collectortest.Response {
	return kitResponsesWithReport(kitCredentialReport)
}

// kitResponsesWithReport answers as kitResponses does, with report as the
// IAM credential report.
func kitResponsesWithReport(report string) []collectortest.Response {
	var out []collectortest.Response
	for _, part := range [][]collectortest.Response{
		kitSignInResponses(),
		kitIAMResponses(report),
		kitS3Responses(),
		kitCloudFrontResponses(),
		kitRegionalResponses(),
		kitSecurityResponses(),
		kitIdentityCenterResponses(),
	} {
		out = append(out, part...)
	}
	return out
}

// kitSignInResponses answer the sign-in: GitHub's identity token, the role
// session it buys, the caller identity, and the region list.
func kitSignInResponses() []collectortest.Response {
	return []collectortest.Response{
		{Operation: "github.id_token.get", URL: kitTokenQuery, Body: kitJSON(map[string]any{"value": kitIdentityJWT})},
		queryResponse("aws.sts.AssumeRoleWithWebIdentity", kitSTSURL,
			"<Credentials><AccessKeyId>ASIAKITEXAMPLE0001</AccessKeyId><SecretAccessKey>"+kitSecretKey+"</SecretAccessKey>"+
				"<SessionToken>"+kitSessionTok+"</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials>"+
				"<SubjectFromWebIdentityToken>repo:northwind/compliance:ref:refs/heads/main</SubjectFromWebIdentityToken>"+
				"<AssumedRoleUser><Arn>arn:aws:sts::111122223333:assumed-role/epack-collector/kit</Arn><AssumedRoleId>AROAKITEXAMPLE:kit</AssumedRoleId></AssumedRoleUser>"),
		queryResponse("aws.sts.GetCallerIdentity", kitSTSURL,
			"<Arn>arn:aws:sts::111122223333:assumed-role/epack-collector/kit</Arn><UserId>AROAKITEXAMPLE:kit</UserId><Account>"+kitAccountID+"</Account>"),
		ec2Response("aws.ec2.DescribeRegions",
			"<regionInfo><item><regionName>us-east-1</regionName><regionEndpoint>ec2.us-east-1.amazonaws.com</regionEndpoint><optInStatus>opt-in-not-required</optInStatus></item></regionInfo>"),
	}
}

// kitCredentialReport has the root user, two console users with MFA, and a
// programmatic user without it. alice's key was rotated within 90 days of
// the kit clock and carol's was not.
var kitCredentialReport = strings.Join([]string{
	"user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated",
	"<root_account>,arn:aws:iam::111122223333:root,2020-01-01T00:00:00+00:00,not_supported,2025-12-01T00:00:00+00:00,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
	"alice,arn:aws:iam::111122223333:user/alice,2023-01-01T00:00:00+00:00,true,2025-12-20T00:00:00+00:00,2025-11-01T00:00:00+00:00,N/A,true,true,2025-12-01T00:00:00+00:00,2025-12-30T00:00:00+00:00,us-east-1,s3,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
	"bob,arn:aws:iam::111122223333:user/bob,2023-06-01T00:00:00+00:00,true,2025-12-28T00:00:00+00:00,2025-10-15T00:00:00+00:00,N/A,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
	"carol,arn:aws:iam::111122223333:user/carol,2024-02-01T00:00:00+00:00,false,N/A,N/A,N/A,false,true,2025-01-01T00:00:00+00:00,2025-12-31T00:00:00+00:00,us-east-1,sts,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
}, "\n") + "\n"

// kitRootOnlyReport lists no IAM users: the account's people sign in through
// Identity Center.
var kitRootOnlyReport = strings.Join(strings.Split(kitCredentialReport, "\n")[:2], "\n") + "\n"

// reportPendingResponses answer as an account whose credential report never
// finishes generating, so polling runs out of time.
func reportPendingResponses() []collectortest.Response {
	return replaceResponses(kitResponses(),
		queryResponse("aws.iam.GenerateCredentialReport", kitIAMURL, "<State>STARTED</State><Description>No report exists. Starting a new report generation task</Description>"),
		collectortest.Response{
			Operation: "aws.iam.GetCredentialReport", Method: http.MethodPost, URL: kitIAMURL, Status: http.StatusNotFound, Header: xmlHeader(),
			Body: "<ErrorResponse><Error><Type>Sender</Type><Code>ReportInProgress</Code><Message>Report is not ready</Message></Error><RequestId>kit-request</RequestId></ErrorResponse>",
		},
	)
}

// accountBlockCoversResponses answer as an account whose account-level block
// sets every flag while neither bucket's own block can be read.
func accountBlockCoversResponses() []collectortest.Response {
	denied := func(bucket string) collectortest.Response {
		return restResponse("aws.s3.GetPublicAccessBlock", http.MethodGet, bucketURL(bucket, "publicAccessBlock"), http.StatusForbidden, s3Error("AccessDenied"))
	}
	return replaceResponses(kitResponses(), accountBlockResponse(kitFullBlock), denied(kitAppBucket), denied(kitLogsBucket))
}

// splitBlockResponses answer as an account whose account-level block sets the
// ACL flags while the log bucket's own block sets the policy flags.
func splitBlockResponses() []collectortest.Response {
	return replaceResponses(kitResponses(),
		restResponse("aws.s3.GetPublicAccessBlock", http.MethodGet, bucketURL(kitLogsBucket, "publicAccessBlock"), 0, kitPolicyBlock))
}

// emptyRegionListResponses answer the region listing with no regions.
func emptyRegionListResponses() []collectortest.Response {
	return replaceResponses(kitResponses(), ec2Response("aws.ec2.DescribeRegions", "<regionInfo/>"))
}

// emptyGroupReadResponses answer the read of the database's security group
// by ID with no groups. The replay answers with the first response a call
// matches, so this one comes before the kit's own.
func emptyGroupReadResponses() []collectortest.Response {
	empty := ec2ItemResponse("aws.ec2.DescribeSecurityGroups", map[string]string{"GroupId.1": "sg-0db"}, "<securityGroupInfo/>")
	return append([]collectortest.Response{empty}, kitResponses()...)
}

// zeroCountResponses answer as an account whose Security Hub has no
// integrations, whose ECS service runs on EC2 with bridge networking and so
// names no subnets of its own, whose distribution's only origin is a custom
// origin fetched over HTTP, and which has no EventBridge rules. The rule
// listing leaves the empty list out, as AWS's JSON protocols do.
func zeroCountResponses() []collectortest.Response {
	service := kitECSService()
	service["launchType"] = "EC2"
	delete(service, "networkConfiguration")
	return replaceResponses(kitResponses(),
		jsonResponse("aws.eventbridge.ListRules", regional("events"), map[string]any{}),
		restResponse("aws.securityhub.ListEnabledProductsForImport", http.MethodGet, "https://securityhub.us-east-1.amazonaws.com/productSubscriptions", 0,
			kitJSON(map[string]any{"ProductSubscriptions": []string{}})),
		ecsDescribeServicesResponse(service),
		restResponse("aws.cloudfront.ListDistributions", http.MethodGet, "https://cloudfront.amazonaws.com/2020-05-31/distribution", 0,
			"<DistributionList><Marker></Marker><MaxItems>100</MaxItems><IsTruncated>false</IsTruncated><Quantity>1</Quantity><Items><DistributionSummary>"+
				"<Id>E2KITEXAMPLE01</Id><ARN>arn:aws:cloudfront::111122223333:distribution/E2KITEXAMPLE01</ARN><Status>Deployed</Status>"+
				"<DomainName>d111111abcdef8.cloudfront.net</DomainName><Aliases><Quantity>1</Quantity><Items><CNAME>www.northwind.example</CNAME></Items></Aliases>"+
				"<Origins><Quantity>1</Quantity><Items>"+
				"<Origin><Id>legacy</Id><DomainName>legacy.northwind.example</DomainName><CustomOriginConfig><HTTPPort>80</HTTPPort><HTTPSPort>443</HTTPSPort><OriginProtocolPolicy>http-only</OriginProtocolPolicy></CustomOriginConfig></Origin>"+
				"</Items></Origins>"+
				"<DefaultCacheBehavior><TargetOriginId>legacy</TargetOriginId><ViewerProtocolPolicy>redirect-to-https</ViewerProtocolPolicy></DefaultCacheBehavior>"+
				"<ViewerCertificate><MinimumProtocolVersion>TLSv1.2_2021</MinimumProtocolVersion><SSLSupportMethod>sni-only</SSLSupportMethod></ViewerCertificate>"+
				"<Enabled>true</Enabled><WebACLId>"+kitCDNWebACLARN+"</WebACLId>"+
				"</DistributionSummary></Items></DistributionList>"),
	)
}

// unrotatableKeyResponses answer as an account with two customer managed
// keys: the kit's key with rotation off, and a symmetric key with imported
// key material, which KMS cannot rotate, so its rotation status is never
// read.
func unrotatableKeyResponses() []collectortest.Response {
	keyARN := "arn:aws:kms:us-east-1:111122223333:key/" + kitKMSKeyID
	importedARN := "arn:aws:kms:us-east-1:111122223333:key/" + kitImportedKey
	responses := replaceResponses(kitResponses(),
		jsonResponse("aws.kms.ListKeys", regional("kms"), map[string]any{"Keys": []any{
			map[string]any{"KeyId": kitKMSKeyID, "KeyArn": keyARN},
			map[string]any{"KeyId": kitImportedKey, "KeyArn": importedARN},
		}, "Truncated": false}),
		jsonItemResponse("aws.kms.GetKeyRotationStatus", regional("kms"), map[string]any{"KeyId": kitKMSKeyID}, map[string]any{"KeyId": keyARN, "KeyRotationEnabled": false}),
	)
	return append(responses, jsonItemResponse("aws.kms.DescribeKey", regional("kms"), map[string]any{"KeyId": kitImportedKey}, map[string]any{"KeyMetadata": map[string]any{
		"KeyId": kitImportedKey, "Arn": importedARN, "AWSAccountId": kitAccountID,
		"KeyManager": "CUSTOMER", "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT", "KeyState": "Enabled", "Origin": "EXTERNAL",
		"Enabled": true, "MultiRegion": false, "CreationDate": 1735689600, "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE",
	}}))
}

func kitTrustPolicy(principal string) string {
	return url.QueryEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":` + principal + `,"Action":"sts:AssumeRole"}]}`)
}

func kitIAMResponses(report string) []collectortest.Response {
	roles := []struct{ name, principal string }{
		{"epack-collector", `{"Federated":"arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"}`},
		{"vendor-audit", `{"AWS":"arn:aws:iam::999988887777:root"}`},
		{"deploy", `{"AWS":"444455556666"}`},
	}
	var roleXML strings.Builder
	for i, r := range roles {
		fmt.Fprintf(&roleXML, "<member><Path>/</Path><RoleName>%s</RoleName><RoleId>AROAKITROLE%04d</RoleId><Arn>arn:aws:iam::111122223333:role/%s</Arn>"+
			"<CreateDate>2024-01-01T00:00:00Z</CreateDate><AssumeRolePolicyDocument>%s</AssumeRolePolicyDocument></member>", r.name, i, r.name, kitTrustPolicy(r.principal))
	}
	return []collectortest.Response{
		queryResponse("aws.iam.ListAccountAliases", kitIAMURL, "<AccountAliases><member>northwind-prod</member></AccountAliases><IsTruncated>false</IsTruncated>"),
		queryResponse("aws.iam.GenerateCredentialReport", kitIAMURL, "<State>COMPLETE</State><Description>Report generated</Description>"),
		queryResponse("aws.iam.GetCredentialReport", kitIAMURL,
			"<Content>"+base64.StdEncoding.EncodeToString([]byte(report))+"</Content><ReportFormat>text/csv</ReportFormat><GeneratedTime>2025-12-31T23:00:00Z</GeneratedTime>"),
		queryResponse("aws.iam.GetAccountSummary", kitIAMURL, "<SummaryMap>"+
			"<entry><key>AccountMFAEnabled</key><value>1</value></entry>"+
			"<entry><key>AccountPasswordPresent</key><value>0</value></entry>"+
			"<entry><key>AccountAccessKeysPresent</key><value>0</value></entry>"+
			"<entry><key>AccountSigningCertificatesPresent</key><value>0</value></entry>"+
			"<entry><key>Users</key><value>3</value></entry></SummaryMap>"),
		queryResponse("aws.iam.GetAccountPasswordPolicy", kitIAMURL, "<PasswordPolicy>"+
			"<MinimumPasswordLength>14</MinimumPasswordLength><RequireSymbols>true</RequireSymbols><RequireNumbers>true</RequireNumbers>"+
			"<RequireUppercaseCharacters>true</RequireUppercaseCharacters><RequireLowercaseCharacters>true</RequireLowercaseCharacters>"+
			"<AllowUsersToChangePassword>true</AllowUsersToChangePassword><ExpirePasswords>true</ExpirePasswords><MaxPasswordAge>90</MaxPasswordAge>"+
			"<PasswordReusePrevention>24</PasswordReusePrevention><HardExpiry>false</HardExpiry></PasswordPolicy>"),
		queryResponse("aws.iam.ListOrganizationsFeatures", kitIAMURL,
			"<OrganizationId>o-kit12345678</OrganizationId><EnabledFeatures><member>RootCredentialsManagement</member><member>RootSessions</member></EnabledFeatures>"),
		// alice's MFA device is a security key and bob's a virtual device.
		queryItemResponse("aws.iam.ListMFADevices", kitIAMURL, map[string]string{"UserName": "alice"},
			"<MFADevices><member><UserName>alice</UserName><SerialNumber>arn:aws:iam::111122223333:u2f/user/alice/yubikey-EXAMPLE</SerialNumber>"+
				"<EnableDate>2024-03-01T00:00:00Z</EnableDate></member></MFADevices><IsTruncated>false</IsTruncated>"),
		queryItemResponse("aws.iam.ListMFADevices", kitIAMURL, map[string]string{"UserName": "bob"},
			"<MFADevices><member><UserName>bob</UserName><SerialNumber>arn:aws:iam::111122223333:mfa/bob</SerialNumber>"+
				"<EnableDate>2024-06-01T00:00:00Z</EnableDate></member></MFADevices><IsTruncated>false</IsTruncated>"),
		queryResponse("aws.iam.ListRoles", kitIAMURL, "<Roles>"+roleXML.String()+"</Roles><IsTruncated>false</IsTruncated>"),
		samlProvidersResponse(),
		jsonResponse("aws.organizations.ListAccounts", "https://organizations.us-east-1.amazonaws.com/", map[string]any{
			"Accounts": []any{
				map[string]any{"Id": kitAccountID, "Arn": "arn:aws:organizations::111122223333:account/o-kit12345678/111122223333", "Name": "Northwind Prod", "Email": "aws-prod@northwind.example", "Status": "ACTIVE"},
				map[string]any{"Id": "444455556666", "Arn": "arn:aws:organizations::111122223333:account/o-kit12345678/444455556666", "Name": "Northwind Deploy", "Email": "aws-deploy@northwind.example", "Status": "ACTIVE"},
			},
		}),
	}
}

// Public access block bodies: kitFullBlock sets all four flags, kitACLBlock
// only the two ACL flags, and kitPolicyBlock only the two policy flags.
var (
	kitFullBlock   = publicAccessBlock(true, true)
	kitACLBlock    = publicAccessBlock(true, false)
	kitPolicyBlock = publicAccessBlock(false, true)
)

func publicAccessBlock(acls, policies bool) string {
	return fmt.Sprintf("<PublicAccessBlockConfiguration><BlockPublicAcls>%t</BlockPublicAcls><IgnorePublicAcls>%t</IgnorePublicAcls>"+
		"<BlockPublicPolicy>%t</BlockPublicPolicy><RestrictPublicBuckets>%t</RestrictPublicBuckets></PublicAccessBlockConfiguration>", acls, acls, policies, policies)
}

// accountBlockResponse answers the read of the account-level public access
// block.
func accountBlockResponse(body string) collectortest.Response {
	return restResponse("aws.s3control.GetPublicAccessBlock", http.MethodGet, "https://111122223333.s3-control.us-east-1.amazonaws.com/v20180820/configuration/publicAccessBlock", 0, body)
}

// kitS3Responses answer the account's two buckets under an account-level
// block that covers ACLs only, so each bucket's own block decides whether it
// is blocked: a locked-down log bucket whose own block sets every flag and
// that enforces TLS, and an app bucket with no block of its own that logs to
// it and leaves most settings at their defaults.
func kitS3Responses() []collectortest.Response {
	logsPolicy := `{"Version":"2012-10-17","Statement":[{"Sid":"DenyInsecureTransport","Effect":"Deny","Principal":"*","Action":"s3:*",` +
		`"Resource":["arn:aws:s3:::northwind-logs","arn:aws:s3:::northwind-logs/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`
	acl := func(owner string) string {
		return "<AccessControlPolicy><Owner><ID>" + owner + "</ID></Owner><AccessControlList><Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">" +
			"<ID>" + owner + "</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>"
	}
	const owner = "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"
	return []collectortest.Response{
		restResponse("aws.s3.ListBuckets", http.MethodGet, kitS3URL+"/?x-id=ListBuckets", 0,
			"<ListAllMyBucketsResult><Owner><ID>"+owner+"</ID></Owner><Buckets>"+
				"<Bucket><Name>"+kitAppBucket+"</Name><CreationDate>2024-01-01T00:00:00.000Z</CreationDate></Bucket>"+
				"<Bucket><Name>"+kitLogsBucket+"</Name><CreationDate>2023-01-01T00:00:00.000Z</CreationDate></Bucket>"+
				"</Buckets></ListAllMyBucketsResult>"),
		accountBlockResponse(kitACLBlock),

		restResponse("aws.s3.GetBucketLocation", http.MethodGet, bucketURL(kitLogsBucket, "location"), 0, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>`),
		restResponse("aws.s3.GetPublicAccessBlock", http.MethodGet, bucketURL(kitLogsBucket, "publicAccessBlock"), 0, kitFullBlock),
		restResponse("aws.s3.GetBucketEncryption", http.MethodGet, bucketURL(kitLogsBucket, "encryption"), 0,
			"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm>"+
				"<KMSMasterKeyID>arn:aws:kms:us-east-1:111122223333:key/"+kitKMSKeyID+"</KMSMasterKeyID></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>"),
		restResponse("aws.s3.GetBucketVersioning", http.MethodGet, bucketURL(kitLogsBucket, "versioning"), 0,
			"<VersioningConfiguration><Status>Enabled</Status><MfaDelete>Enabled</MfaDelete></VersioningConfiguration>"),
		restResponse("aws.s3.GetBucketLogging", http.MethodGet, bucketURL(kitLogsBucket, "logging"), 0, "<BucketLoggingStatus/>"),
		restResponse("aws.s3.GetBucketPolicy", http.MethodGet, bucketURL(kitLogsBucket, "policy"), 0, logsPolicy),
		restResponse("aws.s3.GetBucketAcl", http.MethodGet, bucketURL(kitLogsBucket, "acl"), 0, acl(owner)),
		restResponse("aws.s3.GetBucketLifecycleConfiguration", http.MethodGet, bucketURL(kitLogsBucket, "lifecycle"), 0,
			"<LifecycleConfiguration><Rule><ID>expire-trail-logs</ID><Filter><Prefix>AWSLogs/</Prefix></Filter><Status>Enabled</Status>"+
				"<Transition><Days>30</Days><StorageClass>STANDARD_IA</StorageClass></Transition><Expiration><Days>365</Days></Expiration></Rule></LifecycleConfiguration>"),
		restResponse("aws.s3.GetObjectLockConfiguration", http.MethodGet, bucketURL(kitLogsBucket, "object-lock"), 0,
			"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>90</Days></DefaultRetention></Rule></ObjectLockConfiguration>"),

		restResponse("aws.s3.GetBucketLocation", http.MethodGet, bucketURL(kitAppBucket, "location"), 0, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>`),
		restResponse("aws.s3.GetPublicAccessBlock", http.MethodGet, bucketURL(kitAppBucket, "publicAccessBlock"), http.StatusNotFound, s3Error("NoSuchPublicAccessBlockConfiguration")),
		restResponse("aws.s3.GetBucketEncryption", http.MethodGet, bucketURL(kitAppBucket, "encryption"), http.StatusNotFound, s3Error("ServerSideEncryptionConfigurationNotFoundError")),
		restResponse("aws.s3.GetBucketVersioning", http.MethodGet, bucketURL(kitAppBucket, "versioning"), 0, "<VersioningConfiguration/>"),
		restResponse("aws.s3.GetBucketLogging", http.MethodGet, bucketURL(kitAppBucket, "logging"), 0,
			"<BucketLoggingStatus><LoggingEnabled><TargetBucket>"+kitLogsBucket+"</TargetBucket><TargetPrefix>s3/northwind-app/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>"),
		restResponse("aws.s3.GetBucketPolicy", http.MethodGet, bucketURL(kitAppBucket, "policy"), http.StatusNotFound, s3Error("NoSuchBucketPolicy")),
		restResponse("aws.s3.GetBucketAcl", http.MethodGet, bucketURL(kitAppBucket, "acl"), 0, acl(owner)),
		restResponse("aws.s3.GetBucketLifecycleConfiguration", http.MethodGet, bucketURL(kitAppBucket, "lifecycle"), http.StatusNotFound, s3Error("NoSuchLifecycleConfiguration")),
	}
}

func kitCloudFrontResponses() []collectortest.Response {
	return []collectortest.Response{
		restResponse("aws.cloudfront.ListDistributions", http.MethodGet, "https://cloudfront.amazonaws.com/2020-05-31/distribution", 0,
			"<DistributionList><Marker></Marker><MaxItems>100</MaxItems><IsTruncated>false</IsTruncated><Quantity>1</Quantity><Items><DistributionSummary>"+
				"<Id>E2KITEXAMPLE01</Id><ARN>arn:aws:cloudfront::111122223333:distribution/E2KITEXAMPLE01</ARN><Status>Deployed</Status>"+
				"<DomainName>d111111abcdef8.cloudfront.net</DomainName><Aliases><Quantity>1</Quantity><Items><CNAME>www.northwind.example</CNAME></Items></Aliases>"+
				"<Origins><Quantity>2</Quantity><Items>"+
				"<Origin><Id>assets</Id><DomainName>northwind-app.s3.amazonaws.com</DomainName><S3OriginConfig><OriginAccessIdentity></OriginAccessIdentity></S3OriginConfig></Origin>"+
				"<Origin><Id>api</Id><DomainName>api.northwind.example</DomainName><CustomOriginConfig><HTTPPort>80</HTTPPort><HTTPSPort>443</HTTPSPort><OriginProtocolPolicy>https-only</OriginProtocolPolicy></CustomOriginConfig></Origin>"+
				"</Items></Origins>"+
				"<DefaultCacheBehavior><TargetOriginId>assets</TargetOriginId><ViewerProtocolPolicy>redirect-to-https</ViewerProtocolPolicy></DefaultCacheBehavior>"+
				"<CacheBehaviors><Quantity>1</Quantity><Items><CacheBehavior><PathPattern>/api/*</PathPattern><TargetOriginId>api</TargetOriginId><ViewerProtocolPolicy>https-only</ViewerProtocolPolicy></CacheBehavior></Items></CacheBehaviors>"+
				"<ViewerCertificate><MinimumProtocolVersion>TLSv1.2_2021</MinimumProtocolVersion><SSLSupportMethod>sni-only</SSLSupportMethod></ViewerCertificate>"+
				"<Enabled>true</Enabled><WebACLId>"+kitCDNWebACLARN+"</WebACLId>"+
				"</DistributionSummary></Items></DistributionList>"),
	}
}

// replaceResponses swaps in each replacement for the responses with the same
// operation and URL.
func replaceResponses(responses []collectortest.Response, replacements ...collectortest.Response) []collectortest.Response {
	out := append([]collectortest.Response(nil), responses...)
	for _, r := range replacements {
		replaced := false
		for i := range out {
			if out[i].Operation == r.Operation && out[i].URL == r.URL {
				out[i] = r
				replaced = true
			}
		}
		if !replaced {
			panic("no response to replace for " + r.Operation + " " + r.URL)
		}
	}
	return out
}

func regional(service string) string { return "https://" + service + ".us-east-1.amazonaws.com/" }

// kitRegionalResponses answer the per-region surfaces in us-east-1.
func kitRegionalResponses() []collectortest.Response {
	sgWeb := "<item><groupId>sg-0web</groupId><groupName>web</groupName><groupDescription>web</groupDescription><vpcId>vpc-0kit</vpcId><ipPermissions>" +
		"<item><ipProtocol>tcp</ipProtocol><fromPort>22</fromPort><toPort>22</toPort><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item>" +
		"<item><ipProtocol>tcp</ipProtocol><fromPort>443</fromPort><toPort>443</toPort><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item>" +
		"</ipPermissions></item>"
	sgDB := "<item><groupId>sg-0db</groupId><groupName>database</groupName><groupDescription>database</groupDescription><vpcId>vpc-0kit</vpcId><ipPermissions>" +
		"<item><ipProtocol>tcp</ipProtocol><fromPort>5432</fromPort><toPort>5432</toPort><groups><item><groupId>sg-0web</groupId></item></groups></item>" +
		"</ipPermissions></item>"
	sgDefault := "<item><groupId>sg-0default</groupId><groupName>default</groupName><groupDescription>default</groupDescription><vpcId>vpc-0kit</vpcId><ipPermissions/></item>"
	sgAllTraffic := "<item><groupId>sg-0all</groupId><groupName>allow-all</groupName><groupDescription>allow-all</groupDescription><vpcId>vpc-0kit</vpcId><ipPermissions>" +
		"<item><ipProtocol>-1</ipProtocol><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item>" +
		"</ipPermissions></item>"
	return []collectortest.Response{
		// RDS: one PostgreSQL instance with pgaudit and one Aurora cluster,
		// with an event subscription that alerts on backup failures.
		queryResponse("aws.rds.DescribeDBInstances", regional("rds"), "<DBInstances><DBInstance>"+
			"<DBInstanceIdentifier>northwind-db</DBInstanceIdentifier><Engine>postgres</Engine><EngineVersion>16.4</EngineVersion>"+
			"<PubliclyAccessible>false</PubliclyAccessible><StorageEncrypted>true</StorageEncrypted><DeletionProtection>true</DeletionProtection>"+
			"<BackupRetentionPeriod>7</BackupRetentionPeriod><MultiAZ>true</MultiAZ><AutoMinorVersionUpgrade>true</AutoMinorVersionUpgrade>"+
			"<PreferredBackupWindow>03:00-04:00</PreferredBackupWindow><LatestRestorableTime>2025-12-31T23:55:00Z</LatestRestorableTime>"+
			"<Endpoint><Address>northwind-db.kit.us-east-1.rds.amazonaws.com</Address><Port>5432</Port></Endpoint>"+
			"<DBParameterGroups><DBParameterGroup><DBParameterGroupName>northwind-pg16</DBParameterGroupName><ParameterApplyStatus>in-sync</ParameterApplyStatus></DBParameterGroup></DBParameterGroups>"+
			"<VpcSecurityGroups><VpcSecurityGroupMembership><VpcSecurityGroupId>sg-0db</VpcSecurityGroupId><Status>active</Status></VpcSecurityGroupMembership></VpcSecurityGroups>"+
			"<EnabledCloudwatchLogsExports><member>postgresql</member></EnabledCloudwatchLogsExports>"+
			"</DBInstance></DBInstances>"),
		queryResponse("aws.rds.DescribeDBClusters", regional("rds"), "<DBClusters><DBCluster>"+
			"<DBClusterIdentifier>northwind-aurora</DBClusterIdentifier><Engine>aurora-postgresql</Engine><EngineVersion>16.4</EngineVersion>"+
			"<StorageEncrypted>true</StorageEncrypted><DeletionProtection>false</DeletionProtection><BackupRetentionPeriod>14</BackupRetentionPeriod>"+
			"<MultiAZ>true</MultiAZ><LatestRestorableTime>2025-12-31T23:50:00Z</LatestRestorableTime></DBCluster></DBClusters>"),
		queryItemResponse("aws.rds.DescribeDBParameters", regional("rds"), map[string]string{"DBParameterGroupName": "northwind-pg16"}, "<Parameters>"+
			"<Parameter><ParameterName>shared_preload_libraries</ParameterName><ParameterValue>pg_stat_statements,pgaudit</ParameterValue></Parameter>"+
			"<Parameter><ParameterName>pgaudit.log</ParameterName><ParameterValue>write,ddl</ParameterValue></Parameter>"+
			"<Parameter><ParameterName>log_statement</ParameterName><ParameterValue>ddl</ParameterValue></Parameter>"+
			"</Parameters>"),
		queryResponse("aws.rds.DescribeEventSubscriptions", regional("rds"), "<EventSubscriptionsList><EventSubscription>"+
			"<CustSubscriptionId>northwind-backups</CustSubscriptionId><Enabled>true</Enabled><SourceType>db-instance</SourceType>"+
			"<EventCategoriesList><EventCategory>backup</EventCategory><EventCategory>failure</EventCategory></EventCategoriesList>"+
			"<SnsTopicArn>"+kitTopicARN+"</SnsTopicArn><Status>active</Status></EventSubscription></EventSubscriptionsList>"),
		queryItemResponse("aws.sns.ListSubscriptionsByTopic", regional("sns"), map[string]string{"TopicArn": kitTopicARN}, "<Subscriptions><member>"+
			"<SubscriptionArn>"+kitTopicARN+":6f1c2a3b-0000-4000-8000-000000000001</SubscriptionArn><Owner>111122223333</Owner><Protocol>email</Protocol>"+
			"<Endpoint>security@northwind.example</Endpoint><TopicArn>"+kitTopicARN+"</TopicArn></member></Subscriptions>"),

		// Network: one VPC with flow logs, a web group open to the world on
		// SSH and HTTPS, a database group reachable from the web group, the
		// default group, and a group open to the world on all traffic. The
		// database group is also read alone, for the RDS instance it is
		// attached to.
		ec2Response("aws.ec2.DescribeVpcs", "<vpcSet><item><vpcId>vpc-0kit</vpcId><state>available</state><cidrBlock>10.0.0.0/16</cidrBlock><isDefault>false</isDefault></item></vpcSet>"),
		ec2Response("aws.ec2.DescribeFlowLogs", "<flowLogSet><item><flowLogId>fl-0kit</flowLogId><resourceId>vpc-0kit</resourceId><flowLogStatus>ACTIVE</flowLogStatus>"+
			"<trafficType>ALL</trafficType><logDestinationType>cloud-watch-logs</logDestinationType></item></flowLogSet>"),
		ec2ItemResponse("aws.ec2.DescribeSecurityGroups", map[string]string{"GroupId.1": "sg-0db"}, "<securityGroupInfo>"+sgDB+"</securityGroupInfo>"),
		ec2Response("aws.ec2.DescribeSecurityGroups", "<securityGroupInfo>"+sgWeb+sgDB+sgDefault+sgAllTraffic+"</securityGroupInfo>"),

		// Lambda: one function with a resource policy and an IAM-authorized
		// function URL.
		restResponse("aws.lambda.ListFunctions", http.MethodGet, "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions", 0, kitJSON(map[string]any{
			"Functions": []any{map[string]any{
				"FunctionName": kitFunctionName, "FunctionArn": "arn:aws:lambda:us-east-1:111122223333:function:" + kitFunctionName,
				"Runtime": "nodejs20.x", "Role": "arn:aws:iam::111122223333:role/northwind-api", "MemorySize": 512, "Timeout": 30,
				"CodeSize": 123456, "PackageType": "Zip", "Architectures": []string{"arm64"}, "LastModified": "2025-11-15T10:00:00.000+0000",
				"KMSKeyArn":   "arn:aws:kms:us-east-1:111122223333:key/" + kitKMSKeyID,
				"VpcConfig":   map[string]any{"SubnetIds": []string{"subnet-0kit"}, "SecurityGroupIds": []string{"sg-0web"}, "VpcId": "vpc-0kit"},
				"Environment": map[string]any{"Variables": map[string]string{"TABLE_NAME": "orders", "STAGE": "prod"}},
				"Layers":      []any{map[string]any{"Arn": "arn:aws:lambda:us-east-1:111122223333:layer:otel:3", "CodeSize": 1000}},
			}},
		})),
		restResponse("aws.lambda.GetPolicy", http.MethodGet, "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/"+kitFunctionName+"/policy", 0,
			kitJSON(map[string]any{"Policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"apigateway.amazonaws.com"},"Action":"lambda:InvokeFunction"}]}`, "RevisionId": "kit-revision"})),
		restResponse("aws.lambda.ListFunctionUrlConfigs", http.MethodGet, "https://lambda.us-east-1.amazonaws.com/2021-10-31/functions/"+kitFunctionName+"/urls", 0,
			kitJSON(map[string]any{"FunctionUrlConfigs": []any{map[string]any{"FunctionUrl": "https://kit.lambda-url.us-east-1.on.aws/", "FunctionArn": "arn:aws:lambda:us-east-1:111122223333:function:" + kitFunctionName, "AuthType": "AWS_IAM", "CreationTime": "2025-01-01T00:00:00Z", "LastModifiedTime": "2025-01-01T00:00:00Z"}}})),

		// EC2: one IMDSv2 instance with an encrypted root volume.
		ec2Response("aws.ec2.DescribeInstances", "<reservationSet><item><reservationId>r-0kit</reservationId><ownerId>111122223333</ownerId><instancesSet><item>"+
			"<instanceId>i-0kit00000000000001</instanceId><imageId>ami-0kit</imageId><instanceState><code>16</code><name>running</name></instanceState>"+
			"<instanceType>t3.micro</instanceType><launchTime>2025-12-01T00:00:00Z</launchTime><subnetId>subnet-0kit</subnetId><vpcId>vpc-0kit</vpcId>"+
			"<keyName>northwind-ops</keyName><iamInstanceProfile><arn>arn:aws:iam::111122223333:instance-profile/web</arn><id>AIPAKIT</id></iamInstanceProfile>"+
			"<groupSet><item><groupId>sg-0web</groupId><groupName>web</groupName></item></groupSet>"+
			"<rootDeviceName>/dev/xvda</rootDeviceName><blockDeviceMapping><item><deviceName>/dev/xvda</deviceName><ebs><volumeId>vol-0kit</volumeId><status>attached</status></ebs></item></blockDeviceMapping>"+
			"<metadataOptions><httpTokens>required</httpTokens><httpPutResponseHopLimit>1</httpPutResponseHopLimit><httpEndpoint>enabled</httpEndpoint></metadataOptions>"+
			"<tagSet><item><key>Name</key><value>web-1</value></item></tagSet>"+
			"</item></instancesSet></item></reservationSet>"),
		ec2Response("aws.ec2.DescribeVolumes", "<volumeSet><item><volumeId>vol-0kit</volumeId><size>8</size><encrypted>true</encrypted><status>in-use</status>"+
			"<attachmentSet><item><volumeId>vol-0kit</volumeId><instanceId>i-0kit00000000000001</instanceId><device>/dev/xvda</device><status>attached</status></item></attachmentSet></item></volumeSet>"),

		// Stored images: one unencrypted snapshot that is not public, and one
		// private AMI.
		ec2ItemResponse("aws.ec2.DescribeSnapshots", map[string]string{"Owner.1": "self", "RestorableBy.1": "all"}, "<snapshotSet/>"),
		ec2ItemResponse("aws.ec2.DescribeSnapshots", map[string]string{"Owner.1": "self"},
			"<snapshotSet><item><snapshotId>snap-0kit</snapshotId><volumeId>vol-0kit</volumeId><encrypted>false</encrypted><volumeSize>8</volumeSize><ownerId>111122223333</ownerId></item></snapshotSet>"),
		ec2Response("aws.ec2.DescribeImages", "<imagesSet><item><imageId>ami-0kit</imageId><name>northwind-web-2025-12</name><isPublic>false</isPublic><creationDate>2025-12-01T00:00:00.000Z</creationDate>"+
			"<blockDeviceMapping><item><deviceName>/dev/xvda</deviceName><ebs><snapshotId>snap-0kit</snapshotId><encrypted>true</encrypted><volumeSize>8</volumeSize></ebs></item></blockDeviceMapping></item></imagesSet>"),

		// CloudWatch Logs: a Lambda log group with retention and a key, and a
		// flow log group that never expires.
		jsonResponse("aws.cloudwatchlogs.DescribeLogGroups", regional("logs"), map[string]any{"logGroups": []any{
			map[string]any{"logGroupName": "/aws/lambda/" + kitFunctionName, "arn": "arn:aws:logs:us-east-1:111122223333:log-group:/aws/lambda/" + kitFunctionName + ":*", "creationTime": 1735689600000, "retentionInDays": 30, "storedBytes": 2048, "kmsKeyId": "arn:aws:kms:us-east-1:111122223333:key/" + kitKMSKeyID},
			map[string]any{"logGroupName": "/vpc/flow-logs", "arn": "arn:aws:logs:us-east-1:111122223333:log-group:/vpc/flow-logs:*", "creationTime": 1704067200000, "storedBytes": 4096},
		}}),

		// Monitoring: one alarm on root sign-ins that notifies the alerts
		// topic.
		cborResponse("aws.cloudwatch.DescribeAlarms", "https://monitoring.us-east-1.amazonaws.com/service/GraniteServiceVersion20100801/operation/DescribeAlarms", smithycbor.Map{
			"MetricAlarms": smithycbor.List{smithycbor.Map{
				"AlarmName": smithycbor.String("root-account-usage"), "MetricName": smithycbor.String("RootAccountUsage"), "Namespace": smithycbor.String("CloudTrailMetrics"),
				"ComparisonOperator": smithycbor.String("GreaterThanOrEqualToThreshold"), "Threshold": smithycbor.Float64(1), "EvaluationPeriods": smithycbor.Uint(1),
				"ActionsEnabled": smithycbor.Bool(true), "StateValue": smithycbor.String("OK"),
				"AlarmActions": smithycbor.List{smithycbor.String(kitTopicARN)},
			}},
			"CompositeAlarms": smithycbor.List{},
		}),

		// Load balancers: an internet-facing ALB that redirects HTTP to
		// HTTPS, and one attached target group.
		queryResponse("aws.elasticloadbalancingv2.DescribeLoadBalancers", regional("elasticloadbalancing"), "<LoadBalancers><member>"+
			"<LoadBalancerArn>"+kitALBARN+"</LoadBalancerArn><LoadBalancerName>northwind-web</LoadBalancerName><Scheme>internet-facing</Scheme><Type>application</Type>"+
			"<AvailabilityZones><member><ZoneName>us-east-1a</ZoneName><SubnetId>subnet-0kit</SubnetId></member><member><ZoneName>us-east-1b</ZoneName><SubnetId>subnet-1kit</SubnetId></member></AvailabilityZones>"+
			"</member></LoadBalancers>"),
		queryItemResponse("aws.elasticloadbalancingv2.DescribeListeners", regional("elasticloadbalancing"), map[string]string{"LoadBalancerArn": kitALBARN}, "<Listeners>"+
			"<member><ListenerArn>"+kitALBARN+"/listener/1</ListenerArn><Port>443</Port><Protocol>HTTPS</Protocol><SslPolicy>ELBSecurityPolicy-TLS13-1-2-2021-06</SslPolicy>"+
			"<DefaultActions><member><Type>forward</Type><TargetGroupArn>arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/web/73e2d6bc24d8a067</TargetGroupArn></member></DefaultActions></member>"+
			"<member><ListenerArn>"+kitALBARN+"/listener/2</ListenerArn><Port>80</Port><Protocol>HTTP</Protocol>"+
			"<DefaultActions><member><Type>redirect</Type><RedirectConfig><Protocol>HTTPS</Protocol><Port>443</Port><StatusCode>HTTP_301</StatusCode></RedirectConfig></member></DefaultActions></member>"+
			"</Listeners>"),
		queryResponse("aws.elasticloadbalancingv2.DescribeTargetGroups", regional("elasticloadbalancing"), "<TargetGroups><member>"+
			"<TargetGroupName>web</TargetGroupName><Protocol>HTTP</Protocol><TargetType>instance</TargetType><HealthCheckEnabled>true</HealthCheckEnabled>"+
			"<HealthCheckIntervalSeconds>30</HealthCheckIntervalSeconds><HealthyThresholdCount>5</HealthyThresholdCount><UnhealthyThresholdCount>2</UnhealthyThresholdCount>"+
			"<LoadBalancerArns><member>"+kitALBARN+"</member></LoadBalancerArns></member></TargetGroups>"),

		// SES: one configuration set that requires TLS, used by the one
		// verified domain.
		restResponse("aws.sesv2.ListConfigurationSets", http.MethodGet, "https://email.us-east-1.amazonaws.com/v2/email/configuration-sets", 0,
			kitJSON(map[string]any{"ConfigurationSets": []string{"northwind-tx"}})),
		restResponse("aws.sesv2.GetConfigurationSet", http.MethodGet, "https://email.us-east-1.amazonaws.com/v2/email/configuration-sets/northwind-tx", 0,
			kitJSON(map[string]any{"ConfigurationSetName": "northwind-tx", "DeliveryOptions": map[string]any{"TlsPolicy": "REQUIRE"}})),
		restResponse("aws.sesv2.ListEmailIdentities", http.MethodGet, "https://email.us-east-1.amazonaws.com/v2/email/identities", 0,
			kitJSON(map[string]any{"EmailIdentities": []any{map[string]any{"IdentityName": "northwind.example", "IdentityType": "DOMAIN", "SendingEnabled": true, "VerificationStatus": "SUCCESS"}}})),
		restResponse("aws.sesv2.GetEmailIdentity", http.MethodGet, "https://email.us-east-1.amazonaws.com/v2/email/identities/northwind.example", 0,
			kitJSON(map[string]any{"IdentityType": "DOMAIN", "ConfigurationSetName": "northwind-tx", "VerificationStatus": "SUCCESS"})),

		// ECS: one Fargate service behind the ALB, with a circuit breaker and
		// target-tracking scaling.
		jsonResponse("aws.ecs.ListClusters", regional("ecs"), map[string]any{"clusterArns": []string{kitClusterARN}}),
		jsonItemResponse("aws.ecs.ListServices", regional("ecs"), map[string]any{"cluster": kitClusterARN}, map[string]any{"serviceArns": []string{kitServiceARN}}),
		ecsDescribeServicesResponse(kitECSService()),
		jsonResponse("aws.applicationautoscaling.DescribeScalableTargets", regional("application-autoscaling"), map[string]any{"ScalableTargets": []any{map[string]any{
			"ServiceNamespace": "ecs", "ResourceId": "service/northwind/api", "ScalableDimension": "ecs:service:DesiredCount", "MinCapacity": 2, "MaxCapacity": 10,
			"RoleARN": "arn:aws:iam::111122223333:role/ecs-autoscaling", "CreationTime": 1735689600,
		}}}),
		jsonResponse("aws.applicationautoscaling.DescribeScalingPolicies", regional("application-autoscaling"), map[string]any{"ScalingPolicies": []any{map[string]any{
			"PolicyARN": "arn:aws:autoscaling:us-east-1:111122223333:scalingPolicy:kit", "PolicyName": "cpu", "ServiceNamespace": "ecs", "ResourceId": "service/northwind/api",
			"ScalableDimension": "ecs:service:DesiredCount", "PolicyType": "TargetTrackingScaling", "CreationTime": 1735689600,
			"TargetTrackingScalingPolicyConfiguration": map[string]any{"TargetValue": 60, "PredefinedMetricSpecification": map[string]any{"PredefinedMetricType": "ECSServiceAverageCPUUtilization"}},
		}}}),

		// Auto Scaling: one group across two zones with a launch template and
		// a scaling policy.
		queryResponse("aws.autoscaling.DescribePolicies", regional("autoscaling"), "<ScalingPolicies><member><AutoScalingGroupName>northwind-workers</AutoScalingGroupName>"+
			"<PolicyName>cpu</PolicyName><PolicyType>TargetTrackingScaling</PolicyType><PolicyARN>arn:aws:autoscaling:us-east-1:111122223333:scalingPolicy:kit2</PolicyARN></member></ScalingPolicies>"),
		queryResponse("aws.autoscaling.DescribeAutoScalingGroups", regional("autoscaling"), "<AutoScalingGroups><member>"+
			"<AutoScalingGroupName>northwind-workers</AutoScalingGroupName><MinSize>1</MinSize><MaxSize>4</MaxSize><DesiredCapacity>2</DesiredCapacity>"+
			"<AvailabilityZones><member>us-east-1a</member><member>us-east-1b</member></AvailabilityZones><HealthCheckType>ELB</HealthCheckType><HealthCheckGracePeriod>300</HealthCheckGracePeriod>"+
			"<LaunchTemplate><LaunchTemplateName>workers</LaunchTemplateName><Version>$Latest</Version></LaunchTemplate>"+
			"<TargetGroupARNs><member>arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/web/73e2d6bc24d8a067</member></TargetGroupARNs>"+
			"<SuspendedProcesses/><CreatedTime>2025-01-01T00:00:00Z</CreatedTime></member></AutoScalingGroups>"),

		// KMS: one customer managed key with rotation on.
		jsonResponse("aws.kms.ListAliases", regional("kms"), map[string]any{"Aliases": []any{
			map[string]any{"AliasName": "alias/northwind", "AliasArn": "arn:aws:kms:us-east-1:111122223333:alias/northwind", "TargetKeyId": kitKMSKeyID},
			map[string]any{"AliasName": "alias/aws/s3", "AliasArn": "arn:aws:kms:us-east-1:111122223333:alias/aws/s3"},
		}, "Truncated": false}),
		jsonResponse("aws.kms.ListKeys", regional("kms"), map[string]any{"Keys": []any{map[string]any{"KeyId": kitKMSKeyID, "KeyArn": "arn:aws:kms:us-east-1:111122223333:key/" + kitKMSKeyID}}, "Truncated": false}),
		jsonItemResponse("aws.kms.DescribeKey", regional("kms"), map[string]any{"KeyId": kitKMSKeyID}, map[string]any{"KeyMetadata": map[string]any{
			"KeyId": kitKMSKeyID, "Arn": "arn:aws:kms:us-east-1:111122223333:key/" + kitKMSKeyID, "AWSAccountId": kitAccountID,
			"KeyManager": "CUSTOMER", "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT", "KeyState": "Enabled", "Origin": "AWS_KMS",
			"Enabled": true, "MultiRegion": false, "CreationDate": 1704067200, "Description": "Northwind data key",
		}}),
		jsonItemResponse("aws.kms.GetKeyRotationStatus", regional("kms"), map[string]any{"KeyId": kitKMSKeyID}, map[string]any{"KeyId": "arn:aws:kms:us-east-1:111122223333:key/" + kitKMSKeyID, "KeyRotationEnabled": true, "RotationPeriodInDays": 365}),

		// Secrets Manager: one secret that rotates every 30 days.
		jsonResponse("aws.secretsmanager.ListSecrets", regional("secretsmanager"), map[string]any{"SecretList": []any{map[string]any{
			"ARN": "arn:aws:secretsmanager:us-east-1:111122223333:secret:northwind/db-AbCdEf", "Name": "northwind/db", "Description": "Database credentials",
			"KmsKeyId": "arn:aws:kms:us-east-1:111122223333:key/" + kitKMSKeyID, "RotationEnabled": true,
			"RotationLambdaARN": "arn:aws:lambda:us-east-1:111122223333:function:rotate-db", "RotationRules": map[string]any{"AutomaticallyAfterDays": 30},
			"CreatedDate": 1704067200, "LastChangedDate": 1764547200, "LastAccessedDate": 1767139200, "NextRotationDate": 1767916800,
			"Tags": []any{map[string]any{"Key": "team", "Value": "platform"}},
		}}}),

		// SSM: a SecureString under a customer key and a plain String.
		jsonResponse("aws.ssm.DescribeParameters", regional("ssm"), map[string]any{"Parameters": []any{
			map[string]any{"Name": "/northwind/db-url", "Type": "SecureString", "DataType": "text", "Version": 3, "Tier": "Standard", "KeyId": "alias/northwind", "LastModifiedDate": 1764547200, "LastModifiedUser": "arn:aws:iam::111122223333:user/alice"},
			map[string]any{"Name": "/northwind/region", "Type": "String", "DataType": "text", "Version": 1, "Tier": "Standard", "LastModifiedDate": 1704067200, "LastModifiedUser": "arn:aws:iam::111122223333:user/alice"},
		}}),

		// WAF: a regional web ACL that blocks by default with a rate limit and
		// a managed rule group, logs, and protects the ALB, and a CloudFront
		// web ACL that allows by default with a tighter rate limit, logs, and
		// protects the distribution.
		jsonItemResponse("aws.wafv2.ListWebACLs", regional("wafv2"), map[string]any{"Scope": "REGIONAL"},
			map[string]any{"WebACLs": []any{map[string]any{"Name": "northwind-edge", "Id": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111", "ARN": kitWebACLARN, "LockToken": "kit"}}}),
		jsonItemResponse("aws.wafv2.ListWebACLs", regional("wafv2"), map[string]any{"Scope": "CLOUDFRONT"},
			map[string]any{"WebACLs": []any{map[string]any{"Name": "northwind-cdn", "Id": "b2c3d4e5-6789-01ab-cdef-EXAMPLE22222", "ARN": kitCDNWebACLARN, "LockToken": "kit"}}}),
		jsonItemResponse("aws.wafv2.GetWebACL", regional("wafv2"), map[string]any{"Scope": "REGIONAL", "Name": "northwind-edge", "Id": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"}, map[string]any{"LockToken": "kit", "WebACL": map[string]any{
			"Name": "northwind-edge", "Id": "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111", "ARN": kitWebACLARN, "DefaultAction": map[string]any{"Block": map[string]any{}},
			"VisibilityConfig": map[string]any{"SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "edge"},
			"Rules": []any{
				map[string]any{"Name": "rate-limit", "Priority": 0, "Action": map[string]any{"Block": map[string]any{}},
					"Statement":        map[string]any{"RateBasedStatement": map[string]any{"Limit": 2000, "AggregateKeyType": "IP"}},
					"VisibilityConfig": map[string]any{"SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "rate"}},
				map[string]any{"Name": "common", "Priority": 1, "OverrideAction": map[string]any{"None": map[string]any{}},
					"Statement":        map[string]any{"ManagedRuleGroupStatement": map[string]any{"VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet"}},
					"VisibilityConfig": map[string]any{"SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "common"}},
			},
		}}),
		jsonItemResponse("aws.wafv2.GetWebACL", regional("wafv2"), map[string]any{"Scope": "CLOUDFRONT", "Name": "northwind-cdn", "Id": "b2c3d4e5-6789-01ab-cdef-EXAMPLE22222"}, map[string]any{"LockToken": "kit", "WebACL": map[string]any{
			"Name": "northwind-cdn", "Id": "b2c3d4e5-6789-01ab-cdef-EXAMPLE22222", "ARN": kitCDNWebACLARN, "DefaultAction": map[string]any{"Allow": map[string]any{}},
			"VisibilityConfig": map[string]any{"SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "cdn"},
			"Rules": []any{
				map[string]any{"Name": "rate-limit", "Priority": 0, "Action": map[string]any{"Block": map[string]any{}},
					"Statement":        map[string]any{"RateBasedStatement": map[string]any{"Limit": 1000, "AggregateKeyType": "IP"}},
					"VisibilityConfig": map[string]any{"SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "cdn-rate"}},
			},
		}}),
		jsonItemResponse("aws.wafv2.ListResourcesForWebACL", regional("wafv2"), map[string]any{"WebACLArn": kitWebACLARN}, map[string]any{"ResourceArns": []string{kitALBARN}}),
		jsonItemResponse("aws.wafv2.GetLoggingConfiguration", regional("wafv2"), map[string]any{"ResourceArn": kitWebACLARN}, map[string]any{"LoggingConfiguration": map[string]any{
			"ResourceArn": kitWebACLARN, "LogDestinationConfigs": []string{"arn:aws:firehose:us-east-1:111122223333:deliverystream/aws-waf-logs-northwind"},
		}}),
		jsonItemResponse("aws.wafv2.GetLoggingConfiguration", regional("wafv2"), map[string]any{"ResourceArn": kitCDNWebACLARN}, map[string]any{"LoggingConfiguration": map[string]any{
			"ResourceArn": kitCDNWebACLARN, "LogDestinationConfigs": []string{"arn:aws:firehose:us-east-1:111122223333:deliverystream/aws-waf-logs-northwind-cdn"},
		}}),
	}
}

// kitECSService is the kit's ECS service as DescribeServices returns it: a
// Fargate service behind the ALB, with a circuit breaker.
func kitECSService() map[string]any {
	return map[string]any{
		"serviceArn": kitServiceARN, "serviceName": "api", "clusterArn": kitClusterARN, "launchType": "FARGATE",
		"desiredCount": 2, "runningCount": 2, "enableExecuteCommand": false, "healthCheckGracePeriodSeconds": 60,
		"deploymentConfiguration": map[string]any{"minimumHealthyPercent": 100, "maximumPercent": 200, "deploymentCircuitBreaker": map[string]any{"enable": true, "rollback": true}},
		"networkConfiguration":    map[string]any{"awsvpcConfiguration": map[string]any{"subnets": []string{"subnet-0kit", "subnet-1kit"}, "securityGroups": []string{"sg-0web"}, "assignPublicIp": "DISABLED"}},
		"loadBalancers":           []any{map[string]any{"targetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/web/73e2d6bc24d8a067", "containerName": "api", "containerPort": 8080}},
	}
}

// ecsDescribeServicesResponse answers the read of the kit cluster's services
// with service.
func ecsDescribeServicesResponse(service map[string]any) collectortest.Response {
	return jsonItemResponse("aws.ecs.DescribeServices", regional("ecs"), map[string]any{"cluster": kitClusterARN, "services": []string{kitServiceARN}},
		map[string]any{"services": []any{service}, "failures": []any{}})
}

// kitSecurityResponses answer the account security services: a logging
// organization trail and a stopped local trail into the log bucket, AWS Config,
// GuardDuty with two high findings routed to the alerts topic, an account
// analyzer, and Security Hub with the CIS standard and Inspector findings.
func kitSecurityResponses() []collectortest.Response {
	gd := "https://guardduty.us-east-1.amazonaws.com/detector"
	return []collectortest.Response{
		jsonResponse("aws.cloudtrail.DescribeTrails", regional("cloudtrail"), map[string]any{"trailList": []any{
			map[string]any{"Name": "org-trail", "TrailARN": "arn:aws:cloudtrail:us-east-1:999900001111:trail/org-trail", "HomeRegion": "us-east-1",
				"S3BucketName": kitLogsBucket, "IsMultiRegionTrail": true, "IsOrganizationTrail": true, "LogFileValidationEnabled": true, "IncludeGlobalServiceEvents": true},
			map[string]any{"Name": "northwind-trail", "TrailARN": "arn:aws:cloudtrail:us-east-1:111122223333:trail/northwind-trail", "HomeRegion": "us-east-1",
				"S3BucketName": kitLogsBucket, "S3KeyPrefix": "local", "IsMultiRegionTrail": true, "IsOrganizationTrail": false, "LogFileValidationEnabled": true,
				"KmsKeyId": "arn:aws:kms:us-east-1:111122223333:key/" + kitKMSKeyID, "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:111122223333:log-group:trail:*", "IncludeGlobalServiceEvents": true},
		}}),
		jsonItemResponse("aws.cloudtrail.GetTrailStatus", regional("cloudtrail"), map[string]any{"Name": "arn:aws:cloudtrail:us-east-1:999900001111:trail/org-trail"},
			map[string]any{"IsLogging": true, "LatestDeliveryTime": 1767225000}),
		jsonItemResponse("aws.cloudtrail.GetTrailStatus", regional("cloudtrail"), map[string]any{"Name": "arn:aws:cloudtrail:us-east-1:111122223333:trail/northwind-trail"},
			map[string]any{"IsLogging": false, "LatestDeliveryTime": 1764547200, "StopLoggingTime": 1764547200}),

		jsonResponse("aws.configservice.DescribeConfigurationRecorders", regional("config"), map[string]any{"ConfigurationRecorders": []any{map[string]any{
			"name": "default", "roleARN": "arn:aws:iam::111122223333:role/aws-config", "recordingGroup": map[string]any{"allSupported": true, "includeGlobalResourceTypes": true},
		}}}),
		jsonResponse("aws.configservice.DescribeConfigurationRecorderStatus", regional("config"), map[string]any{"ConfigurationRecordersStatus": []any{map[string]any{
			"name": "default", "recording": true, "lastStatus": "SUCCESS",
		}}}),
		jsonResponse("aws.configservice.DescribeConfigRules", regional("config"), map[string]any{"ConfigRules": []any{map[string]any{
			"ConfigRuleName": "s3-bucket-public-read-prohibited", "ConfigRuleArn": "arn:aws:config:us-east-1:111122223333:config-rule/config-rule-kit", "ConfigRuleState": "ACTIVE",
			"Source": map[string]any{"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"},
		}}}),
		jsonResponse("aws.configservice.DescribeComplianceByConfigRule", regional("config"), map[string]any{"ComplianceByConfigRules": []any{map[string]any{
			"ConfigRuleName": "s3-bucket-public-read-prohibited", "Compliance": map[string]any{"ComplianceType": "COMPLIANT"},
		}}}),
		jsonResponse("aws.configservice.DescribeConfigRuleEvaluationStatus", regional("config"), map[string]any{"ConfigRulesEvaluationStatus": []any{map[string]any{
			"ConfigRuleName": "s3-bucket-public-read-prohibited", "LastSuccessfulEvaluationTime": 1767222000,
		}}}),

		restResponse("aws.guardduty.ListDetectors", http.MethodGet, gd, 0, kitJSON(map[string]any{"detectorIds": []string{kitDetectorID}})),
		restResponse("aws.guardduty.GetDetector", http.MethodGet, gd+"/"+kitDetectorID, 0, kitJSON(map[string]any{
			"status": "ENABLED", "serviceRole": "arn:aws:iam::111122223333:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
			"findingPublishingFrequency": "FIFTEEN_MINUTES",
			"features": []any{
				map[string]any{"name": "S3_DATA_EVENTS", "status": "ENABLED"},
				map[string]any{"name": "EKS_AUDIT_LOGS", "status": "DISABLED"},
				map[string]any{"name": "EBS_MALWARE_PROTECTION", "status": "ENABLED"},
			},
		})),
		// The count of findings stale for 48 hours adds an updatedAt
		// criterion. It comes first because the replay answers with the
		// first response whose request body a call holds.
		withRequestBody(restResponse("aws.guardduty.ListFindings", http.MethodPost, gd+"/"+kitDetectorID+"/findings", 0,
			kitJSON(map[string]any{"findingIds": []string{"f-0kit000000000000000000000000002"}})),
			map[string]any{"findingCriteria": map[string]any{"criterion": map[string]any{"updatedAt": map[string]any{}}}}),
		withRequestBody(restResponse("aws.guardduty.ListFindings", http.MethodPost, gd+"/"+kitDetectorID+"/findings", 0,
			kitJSON(map[string]any{"findingIds": []string{"f-0kit000000000000000000000000001", "f-0kit000000000000000000000000002"}})),
			map[string]any{"findingCriteria": map[string]any{"criterion": map[string]any{"severity": map[string]any{"greaterThanOrEqual": 7}, "service.archived": map[string]any{"equals": []string{"false"}}}}}),
		withRequestBody(restResponse("aws.guardduty.GetFindings", http.MethodPost, gd+"/"+kitDetectorID+"/findings/get", 0, kitJSON(map[string]any{"findings": []any{
			map[string]any{"id": "f-0kit000000000000000000000000001", "accountId": kitAccountID, "arn": "arn:aws:guardduty:us-east-1:111122223333:detector/" + kitDetectorID + "/finding/f-1",
				"type": "UnauthorizedAccess:EC2/SSHBruteForce", "title": "SSH brute force against i-0kit00000000000001", "severity": 8, "region": "us-east-1", "schemaVersion": "2.0",
				"createdAt": "2025-12-20T00:00:00.000Z", "updatedAt": "2025-12-31T00:00:00.000Z",
				"resource": map[string]any{"resourceType": "Instance", "instanceDetails": map[string]any{"instanceId": "i-0kit00000000000001"}}},
			map[string]any{"id": "f-0kit000000000000000000000000002", "accountId": kitAccountID, "arn": "arn:aws:guardduty:us-east-1:111122223333:detector/" + kitDetectorID + "/finding/f-2",
				"type": "Recon:IAMUser/MaliciousIPCaller", "title": "API called from a known malicious IP", "severity": 7.5, "region": "us-east-1", "schemaVersion": "2.0",
				"createdAt": "2025-12-01T00:00:00.000Z", "updatedAt": "2025-12-02T00:00:00.000Z",
				"resource": map[string]any{"resourceType": "AccessKey", "accessKeyDetails": map[string]any{"userName": "carol"}}},
		}})), map[string]any{"findingIds": []string{"f-0kit000000000000000000000000001", "f-0kit000000000000000000000000002"}}),
		restResponse("aws.guardduty.GetAdministratorAccount", http.MethodGet, gd+"/"+kitDetectorID+"/administrator", 0, kitJSON(map[string]any{"administrator": map[string]any{
			"accountId": "999900001111", "invitationId": "kit-invitation", "relationshipStatus": "Enabled", "invitedAt": "2024-01-01T00:00:00.000Z",
		}})),
		jsonResponse("aws.eventbridge.ListRules", regional("events"), map[string]any{"Rules": []any{
			map[string]any{"Name": "guardduty-high", "Arn": "arn:aws:events:us-east-1:111122223333:rule/guardduty-high", "State": "ENABLED",
				"EventPattern": `{"source":["aws.guardduty"],"detail-type":["GuardDuty Finding"],"detail":{"severity":[{"numeric":[">=",7]}]}}`},
			map[string]any{"Name": "nightly-report", "Arn": "arn:aws:events:us-east-1:111122223333:rule/nightly-report", "State": "ENABLED", "ScheduleExpression": "cron(0 6 * * ? *)"},
		}}),
		jsonItemResponse("aws.eventbridge.ListTargetsByRule", regional("events"), map[string]any{"Rule": "guardduty-high"}, map[string]any{"Targets": []any{map[string]any{"Id": "alerts", "Arn": kitTopicARN}}}),

		restResponse("aws.accessanalyzer.ListAnalyzers", http.MethodGet, "https://access-analyzer.us-east-1.amazonaws.com/analyzer", 0, kitJSON(map[string]any{"analyzers": []any{map[string]any{
			"arn": "arn:aws:access-analyzer:us-east-1:111122223333:analyzer/northwind", "name": "northwind", "type": "ACCOUNT", "status": "ACTIVE", "createdAt": "2024-01-01T00:00:00Z",
		}}})),
		withRequestBody(restResponse("aws.accessanalyzer.ListFindings", http.MethodPost, "https://access-analyzer.us-east-1.amazonaws.com/finding", 0, kitJSON(map[string]any{"findings": []any{
			map[string]any{"id": "aa-1", "resourceType": "AWS::S3::Bucket", "resource": "arn:aws:s3:::northwind-app", "status": "ACTIVE", "resourceOwnerAccount": kitAccountID, "analyzedAt": "2025-12-30T00:00:00Z", "createdAt": "2025-12-30T00:00:00Z", "updatedAt": "2025-12-30T00:00:00Z", "condition": map[string]any{}},
			map[string]any{"id": "aa-2", "resourceType": "AWS::IAM::Role", "resource": "arn:aws:iam::111122223333:role/vendor-audit", "status": "ARCHIVED", "resourceOwnerAccount": kitAccountID, "analyzedAt": "2025-12-30T00:00:00Z", "createdAt": "2025-06-01T00:00:00Z", "updatedAt": "2025-12-30T00:00:00Z", "condition": map[string]any{}},
		}})), map[string]any{"analyzerArn": "arn:aws:access-analyzer:us-east-1:111122223333:analyzer/northwind"}),

		restResponse("aws.securityhub.DescribeHub", http.MethodGet, "https://securityhub.us-east-1.amazonaws.com/accounts", 0, kitJSON(map[string]any{
			"HubArn": "arn:aws:securityhub:us-east-1:111122223333:hub/default", "SubscribedAt": "2024-01-01T00:00:00.000Z", "AutoEnableControls": true,
		})),
		restResponse("aws.securityhub.GetEnabledStandards", http.MethodPost, "https://securityhub.us-east-1.amazonaws.com/standards/get", 0, kitJSON(map[string]any{"StandardsSubscriptions": []any{map[string]any{
			"StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:111122223333:subscription/cis-aws-foundations-benchmark/v/1.4.0",
			"StandardsArn":             "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0", "StandardsStatus": "READY", "StandardsInput": map[string]string{},
		}}})),
		restResponse("aws.securityhub.ListEnabledProductsForImport", http.MethodGet, "https://securityhub.us-east-1.amazonaws.com/productSubscriptions", 0, kitJSON(map[string]any{
			"ProductSubscriptions": []string{"arn:aws:securityhub:us-east-1:111122223333:product-subscription/aws/inspector"},
		})),
		withRequestBody(restResponse("aws.securityhub.GetFindings", http.MethodPost, "https://securityhub.us-east-1.amazonaws.com/findings", 0, kitJSON(map[string]any{"Findings": []any{
			map[string]any{"SchemaVersion": "2018-10-08", "Id": "kit-cis-1.10", "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub", "ProductName": "Security Hub",
				"GeneratorId": "cis-aws-foundations-benchmark/v/1.4.0/1.10", "AwsAccountId": kitAccountID, "CreatedAt": "2025-12-01T00:00:00Z", "UpdatedAt": "2025-12-31T00:00:00Z",
				"Title": "1.10 Ensure MFA is enabled for all IAM users that have a console password", "Description": "kit", "Severity": map[string]any{"Label": "MEDIUM"},
				"Resources":  []any{map[string]any{"Type": "AwsAccount", "Id": "AWS::::Account:111122223333"}},
				"Compliance": map[string]any{"Status": "PASSED", "SecurityControlId": "IAM.5", "RelatedRequirements": []string{"CIS AWS Foundations Benchmark v1.4.0/1.10"}},
				"Workflow":   map[string]any{"Status": "RESOLVED"}, "RecordState": "ACTIVE"},
		}})), map[string]any{"Filters": map[string]any{"ComplianceAssociatedStandardsId": []any{map[string]any{"Comparison": "EQUALS", "Value": "standards/cis-aws-foundations-benchmark/v/1.4.0"}}}}),
		withRequestBody(restResponse("aws.securityhub.GetFindings", http.MethodPost, "https://securityhub.us-east-1.amazonaws.com/findings", 0, kitJSON(map[string]any{"Findings": []any{
			map[string]any{"SchemaVersion": "2018-10-08", "Id": "kit-inspector-1", "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/inspector", "ProductName": "Inspector",
				"GeneratorId": "AWSInspector", "AwsAccountId": kitAccountID, "CreatedAt": "2025-12-10T00:00:00Z", "UpdatedAt": "2025-12-31T00:00:00Z",
				"Title": "CVE-2025-0001 - openssl", "Description": "kit", "Severity": map[string]any{"Label": "HIGH"},
				"Resources": []any{map[string]any{"Type": "AwsEc2Instance", "Id": "arn:aws:ec2:us-east-1:111122223333:instance/i-0kit00000000000001"}},
				"Workflow":  map[string]any{"Status": "NEW"}, "RecordState": "ACTIVE"},
		}})), map[string]any{"Filters": map[string]any{"ProductName": []any{map[string]any{"Comparison": "PREFIX", "Value": "Inspector"}}}}),
	}
}

// kitIdentityCenterResponses answer the organization's Identity Center
// instance, which this account owns as the management account, with two
// users, an admin group, and one permission set assigned in the deploy
// account. Identity Center provisions no role in this account.
func kitIdentityCenterResponses() []collectortest.Response {
	sso, ids := regional("sso"), regional("identitystore")
	return []collectortest.Response{
		jsonResponse("aws.ssoadmin.ListInstances", sso, map[string]any{"Instances": []any{map[string]any{"InstanceArn": kitInstanceARN, "IdentityStoreId": kitStoreID, "OwnerAccountId": kitAccountID, "Status": "ACTIVE"}}}),
		jsonResponse("aws.identitystore.ListUsers", ids, map[string]any{"Users": []any{
			map[string]any{"IdentityStoreId": kitStoreID, "UserId": "u-1111", "UserName": "dana", "DisplayName": "Dana Ito", "Emails": []any{map[string]any{"Value": "dana@northwind.example", "Primary": true, "Type": "work"}}},
			map[string]any{"IdentityStoreId": kitStoreID, "UserId": "u-2222", "UserName": "eli", "DisplayName": "Eli Park", "Emails": []any{map[string]any{"Value": "eli@northwind.example", "Primary": true, "Type": "work"}}},
		}}),
		jsonResponse("aws.identitystore.ListGroups", ids, map[string]any{"Groups": []any{map[string]any{"IdentityStoreId": kitStoreID, "GroupId": "g-1111", "DisplayName": "Admins", "Description": "Platform administrators"}}}),
		jsonItemResponse("aws.identitystore.ListGroupMemberships", ids, map[string]any{"GroupId": "g-1111"}, map[string]any{"GroupMemberships": []any{map[string]any{"IdentityStoreId": kitStoreID, "MembershipId": "m-1111", "GroupId": "g-1111", "MemberId": map[string]any{"UserId": "u-1111"}}}}),
		jsonResponse("aws.ssoadmin.ListPermissionSets", sso, map[string]any{"PermissionSets": []string{kitPermSetARN}}),
		jsonItemResponse("aws.ssoadmin.DescribePermissionSet", sso, map[string]any{"PermissionSetArn": kitPermSetARN}, map[string]any{"PermissionSet": map[string]any{"PermissionSetArn": kitPermSetARN, "Name": "AdministratorAccess", "Description": "Full access", "SessionDuration": "PT1H"}}),
		jsonItemResponse("aws.ssoadmin.ListAccountsForProvisionedPermissionSet", sso, map[string]any{"PermissionSetArn": kitPermSetARN}, map[string]any{"AccountIds": []string{"444455556666"}}),
		jsonItemResponse("aws.ssoadmin.ListManagedPoliciesInPermissionSet", sso, map[string]any{"PermissionSetArn": kitPermSetARN}, map[string]any{"AttachedManagedPolicies": []any{map[string]any{"Arn": "arn:aws:iam::aws:policy/AdministratorAccess", "Name": "AdministratorAccess"}}}),
		jsonItemResponse("aws.ssoadmin.GetInlinePolicyForPermissionSet", sso, map[string]any{"PermissionSetArn": kitPermSetARN}, map[string]any{"InlinePolicy": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"organizations:LeaveOrganization","Resource":"*"}]}`}),
		jsonItemResponse("aws.ssoadmin.ListAccountAssignments", sso, map[string]any{"PermissionSetArn": kitPermSetARN, "AccountId": "444455556666"}, map[string]any{"AccountAssignments": []any{map[string]any{"AccountId": "444455556666", "PermissionSetArn": kitPermSetARN, "PrincipalType": "GROUP", "PrincipalId": "g-1111"}}}),
	}
}

// emptyAccountResponses answer an account in the same organization with no
// IAM users, roles, or buckets, nothing deployed in its region, and no
// security services turned on.
func emptyAccountResponses() []collectortest.Response {
	empty := func(op, endpoint, result string) collectortest.Response { return queryResponse(op, endpoint, result) }
	shub := `{"__type":"InvalidAccessException","Code":"InvalidAccessException","Message":"Account 111122223333 is not subscribed to AWS Security Hub"}`
	responses := append(kitSignInResponses(), replaceResponses(kitIAMResponses(kitRootOnlyReport),
		empty("aws.iam.ListAccountAliases", kitIAMURL, "<AccountAliases/><IsTruncated>false</IsTruncated>"),
		empty("aws.iam.ListRoles", kitIAMURL, "<Roles/><IsTruncated>false</IsTruncated>"),
	)...)
	responses = append(responses,
		restResponse("aws.s3.ListBuckets", http.MethodGet, kitS3URL+"/?x-id=ListBuckets", 0, "<ListAllMyBucketsResult><Owner><ID>kit</ID></Owner><Buckets/></ListAllMyBucketsResult>"),
		accountBlockResponse(kitACLBlock),
		restResponse("aws.cloudfront.ListDistributions", http.MethodGet, "https://cloudfront.amazonaws.com/2020-05-31/distribution", 0,
			"<DistributionList><Marker></Marker><MaxItems>100</MaxItems><IsTruncated>false</IsTruncated><Quantity>0</Quantity></DistributionList>"),
		jsonResponse("aws.cloudtrail.DescribeTrails", regional("cloudtrail"), map[string]any{"trailList": []any{}}),
		jsonResponse("aws.configservice.DescribeConfigurationRecorders", regional("config"), map[string]any{"ConfigurationRecorders": []any{}}),
		restResponse("aws.securityhub.DescribeHub", http.MethodGet, "https://securityhub.us-east-1.amazonaws.com/accounts", http.StatusUnauthorized, shub),
		restResponse("aws.securityhub.GetFindings", http.MethodPost, "https://securityhub.us-east-1.amazonaws.com/findings", http.StatusUnauthorized, shub),
	)
	return append(responses, emptyRegionResponses(kitRegion)...)
}

// emptyRegionResponses answer the calls the collector makes in every region
// it scans, for a region with nothing deployed and no regional security
// service turned on.
func emptyRegionResponses(region string) []collectortest.Response {
	empty := func(op, endpoint, result string) collectortest.Response { return queryResponse(op, endpoint, result) }
	return inRegion(region,
		empty("aws.rds.DescribeDBInstances", regional("rds"), "<DBInstances/>"),
		empty("aws.rds.DescribeDBClusters", regional("rds"), "<DBClusters/>"),
		empty("aws.rds.DescribeEventSubscriptions", regional("rds"), "<EventSubscriptionsList/>"),
		ec2Response("aws.ec2.DescribeVpcs", "<vpcSet/>"),
		ec2Response("aws.ec2.DescribeFlowLogs", "<flowLogSet/>"),
		ec2Response("aws.ec2.DescribeSecurityGroups", "<securityGroupInfo/>"),
		ec2Response("aws.ec2.DescribeInstances", "<reservationSet/>"),
		ec2Response("aws.ec2.DescribeVolumes", "<volumeSet/>"),
		ec2Response("aws.ec2.DescribeSnapshots", "<snapshotSet/>"),
		ec2Response("aws.ec2.DescribeImages", "<imagesSet/>"),
		restResponse("aws.lambda.ListFunctions", http.MethodGet, "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions", 0, `{"Functions":[]}`),
		jsonResponse("aws.cloudwatchlogs.DescribeLogGroups", regional("logs"), map[string]any{"logGroups": []any{}}),
		cborResponse("aws.cloudwatch.DescribeAlarms", "https://monitoring.us-east-1.amazonaws.com/service/GraniteServiceVersion20100801/operation/DescribeAlarms",
			smithycbor.Map{"MetricAlarms": smithycbor.List{}, "CompositeAlarms": smithycbor.List{}}),
		empty("aws.elasticloadbalancingv2.DescribeLoadBalancers", regional("elasticloadbalancing"), "<LoadBalancers/>"),
		empty("aws.elasticloadbalancingv2.DescribeTargetGroups", regional("elasticloadbalancing"), "<TargetGroups/>"),
		restResponse("aws.sesv2.ListConfigurationSets", http.MethodGet, "https://email.us-east-1.amazonaws.com/v2/email/configuration-sets", 0, `{"ConfigurationSets":[]}`),
		restResponse("aws.sesv2.ListEmailIdentities", http.MethodGet, "https://email.us-east-1.amazonaws.com/v2/email/identities", 0, `{"EmailIdentities":[]}`),
		jsonResponse("aws.ecs.ListClusters", regional("ecs"), map[string]any{"clusterArns": []string{}}),
		jsonResponse("aws.applicationautoscaling.DescribeScalableTargets", regional("application-autoscaling"), map[string]any{"ScalableTargets": []any{}}),
		jsonResponse("aws.applicationautoscaling.DescribeScalingPolicies", regional("application-autoscaling"), map[string]any{"ScalingPolicies": []any{}}),
		empty("aws.autoscaling.DescribePolicies", regional("autoscaling"), "<ScalingPolicies/>"),
		empty("aws.autoscaling.DescribeAutoScalingGroups", regional("autoscaling"), "<AutoScalingGroups/>"),
		jsonResponse("aws.kms.ListAliases", regional("kms"), map[string]any{"Aliases": []any{}, "Truncated": false}),
		jsonResponse("aws.kms.ListKeys", regional("kms"), map[string]any{"Keys": []any{}, "Truncated": false}),
		jsonResponse("aws.secretsmanager.ListSecrets", regional("secretsmanager"), map[string]any{"SecretList": []any{}}),
		jsonResponse("aws.ssm.DescribeParameters", regional("ssm"), map[string]any{"Parameters": []any{}}),
		jsonResponse("aws.wafv2.ListWebACLs", regional("wafv2"), map[string]any{"WebACLs": []any{}}),
		restResponse("aws.guardduty.ListDetectors", http.MethodGet, "https://guardduty.us-east-1.amazonaws.com/detector", 0, `{"detectorIds":[]}`),
		restResponse("aws.accessanalyzer.ListAnalyzers", http.MethodGet, "https://access-analyzer.us-east-1.amazonaws.com/analyzer", 0, `{"analyzers":[]}`),
		jsonResponse("aws.ssoadmin.ListInstances", regional("sso"), map[string]any{"Instances": []any{}}),
	)
}

// inRegion returns responses answering in region what they answer in the
// kit's region.
func inRegion(region string, responses ...collectortest.Response) []collectortest.Response {
	out := make([]collectortest.Response, 0, len(responses))
	for _, r := range responses {
		r.URL = strings.Replace(r.URL, "."+kitRegion+".", "."+region+".", 1)
		out = append(out, r)
	}
	return out
}

// samlProvidersResponse answers the SAML provider listing with a provider of
// each name.
func samlProvidersResponse(names ...string) collectortest.Response {
	var list strings.Builder
	for _, name := range names {
		fmt.Fprintf(&list, "<member><Arn>arn:aws:iam::111122223333:saml-provider/%s</Arn><ValidUntil>2030-01-01T00:00:00Z</ValidUntil><CreateDate>2024-01-01T00:00:00Z</CreateDate></member>", name)
	}
	return queryResponse("aws.iam.ListSAMLProviders", kitIAMURL, "<SAMLProviderList>"+list.String()+"</SAMLProviderList>")
}

// identityCenterRolesResponse answers the listing of the roles under IAM
// Identity Center's path with the role it provisions for each permission set
// named. The kit's listing of every role leaves them out.
func identityCenterRolesResponse(permissionSets ...string) collectortest.Response {
	var roles strings.Builder
	for i, ps := range permissionSets {
		name := fmt.Sprintf("AWSReservedSSO_%s_%016x", ps, i+1)
		fmt.Fprintf(&roles, "<member><Path>%sus-east-1/</Path><RoleName>%s</RoleName><RoleId>AROAKITSSO%04d</RoleId><Arn>arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/us-east-1/%s</Arn>"+
			"<CreateDate>2024-01-01T00:00:00Z</CreateDate><AssumeRolePolicyDocument>%s</AssumeRolePolicyDocument></member>",
			identityCenterRolePath, name, i, name, kitTrustPolicy(`{"Federated":"arn:aws:iam::111122223333:saml-provider/AWSSSO_kit1111222233334444_DO_NOT_DELETE"}`))
	}
	return queryItemResponse("aws.iam.ListRoles", kitIAMURL, map[string]string{"PathPrefix": identityCenterRolePath}, "<Roles>"+roles.String()+"</Roles><IsTruncated>false</IsTruncated>")
}

// noIdentityCenterResponses answer as kitResponsesWithReport does, for an
// account that sees no Identity Center instance in its region.
func noIdentityCenterResponses(report string) []collectortest.Response {
	return replaceResponses(kitResponsesWithReport(report), jsonResponse("aws.ssoadmin.ListInstances", regional("sso"), map[string]any{"Instances": []any{}}))
}

// memberAccountResponses answer a member account with no IAM users that
// cannot see its organization's Identity Center instance, where Identity
// Center has provisioned two permission sets' roles and its SAML provider.
func memberAccountResponses() []collectortest.Response {
	responses := replaceResponses(noIdentityCenterResponses(kitRootOnlyReport), samlProvidersResponse("AWSSSO_kit1111222233334444_DO_NOT_DELETE"))
	return append([]collectortest.Response{identityCenterRolesResponse("AdministratorAccess", "ReadOnlyAccess")}, responses...)
}

// directSAMLResponses answer an account with no IAM users and no Identity
// Center whose people sign in through a SAML provider it trusts directly.
func directSAMLResponses() []collectortest.Response {
	return replaceResponses(noIdentityCenterResponses(kitRootOnlyReport), samlProvidersResponse("NorthwindOkta"))
}

// secondRegionInstanceResponses answer the kit account scanned in its own
// region and an empty us-west-2, where Identity Center's instance lives.
func secondRegionInstanceResponses() []collectortest.Response {
	responses := append(noIdentityCenterResponses(kitCredentialReport), emptyRegionResponses("us-west-2")...)
	responses = replaceResponses(responses, inRegion("us-west-2", kitIdentityCenterResponses()[0])...)
	return append(responses, inRegion("us-west-2", kitIdentityCenterResponses()[1:]...)...)
}

// The issuers of the external IDs on the identity store users in
// externalIDUsersResponses: the SCIM provisioning tenant IAM Identity Center
// records when an identity provider provisions a user, and a directory a
// sync might name instead. No output may carry an issuer or an ID.
const (
	kitSCIMIssuer      = "arn:aws:identitystore::111122223333:identitystore/d-9067111111/provisioningtenant/a1b2c3d4-5678-90ab-cdef-111111111111"
	kitDirectoryIssuer = "arn:aws:ds:us-east-1:111122223333:directory/d-9067222222"
	kitDanaExternalID  = "00ukitdana0000000001"
	kitEliExternalID   = "00ukiteli00000000002"
)

// externalIDCanaries are the issuers and external IDs in
// externalIDUsersResponses as scenario secrets, which the kit fails a run
// for printing or emitting.
func externalIDCanaries() map[string]string {
	return map[string]string{
		"KIT_SCIM_ISSUER":      kitSCIMIssuer,
		"KIT_DIRECTORY_ISSUER": kitDirectoryIssuer,
		"KIT_DANA_EXTERNAL_ID": kitDanaExternalID,
		"KIT_ELI_EXTERNAL_ID":  kitEliExternalID,
	}
}

// externalIDUsersResponses answer as kitResponsesWithReport does, with each
// Identity Center user carrying an external ID: dana's from danaIssuer and
// eli's from eliIssuer.
func externalIDUsersResponses(report, danaIssuer, eliIssuer string) []collectortest.Response {
	user := func(id, name, display, email, issuer, externalID string) map[string]any {
		return map[string]any{
			"IdentityStoreId": kitStoreID, "UserId": id, "UserName": name, "DisplayName": display,
			"Emails":      []any{map[string]any{"Value": email, "Primary": true, "Type": "work"}},
			"ExternalIds": []any{map[string]any{"Issuer": issuer, "Id": externalID}},
		}
	}
	return replaceResponses(kitResponsesWithReport(report), jsonResponse("aws.identitystore.ListUsers", regional("identitystore"), map[string]any{"Users": []any{
		user("u-1111", "dana@northwind.example", "Dana Ito", "dana@northwind.example", danaIssuer, kitDanaExternalID),
		user("u-2222", "eli@northwind.example", "Eli Park", "eli@northwind.example", eliIssuer, kitEliExternalID),
	}}))
}
