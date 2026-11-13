module github.com/locktivity/epack-collector-aws

go 1.26.0

toolchain go1.26.11

require (
	github.com/aws/aws-sdk-go-v2 v1.48.0
	github.com/aws/aws-sdk-go-v2/config v1.33.18
	github.com/aws/aws-sdk-go-v2/credentials v1.21.0
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.57.12
	github.com/aws/aws-sdk-go-v2/service/applicationautoscaling v1.51.12
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.81.0
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.75.6
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.65.12
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.75.7
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.92.2
	github.com/aws/aws-sdk-go-v2/service/configservice v1.74.12
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.344.3
	github.com/aws/aws-sdk-go-v2/service/ecs v1.105.1
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.64.0
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.55.11
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.101.7
	github.com/aws/aws-sdk-go-v2/service/iam v1.65.0
	github.com/aws/aws-sdk-go-v2/service/identitystore v1.49.9
	github.com/aws/aws-sdk-go-v2/service/inspector2 v1.62.5
	github.com/aws/aws-sdk-go-v2/service/kms v1.62.6
	github.com/aws/aws-sdk-go-v2/service/lambda v1.114.4
	github.com/aws/aws-sdk-go-v2/service/organizations v1.62.8
	github.com/aws/aws-sdk-go-v2/service/rds v1.133.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.114.10
	github.com/aws/aws-sdk-go-v2/service/s3control v1.80.1
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.50.12
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.86.3
	github.com/aws/aws-sdk-go-v2/service/sesv2 v1.79.9
	github.com/aws/aws-sdk-go-v2/service/sns v1.48.0
	github.com/aws/aws-sdk-go-v2/service/ssm v1.82.1
	github.com/aws/aws-sdk-go-v2/service/ssoadmin v1.52.6
	github.com/aws/aws-sdk-go-v2/service/sts v1.52.0
	github.com/aws/aws-sdk-go-v2/service/wafv2 v1.85.2
	github.com/aws/smithy-go v1.28.9
	github.com/locktivity/epack v0.12.2
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.27 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.9 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.25 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.13.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.39.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.44.5 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
