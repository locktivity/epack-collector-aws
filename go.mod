module github.com/locktivity/epack-collector-aws

go 1.26.0

require (
	github.com/aws/aws-sdk-go-v2 v1.43.6
	github.com/aws/aws-sdk-go-v2/config v1.29.14
	github.com/aws/aws-sdk-go-v2/credentials v1.17.67
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.38.3
	github.com/aws/aws-sdk-go-v2/service/applicationautoscaling v1.45.6
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.72.1
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.67.6
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.48.4
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.66.5
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.74.0
	github.com/aws/aws-sdk-go-v2/service/configservice v1.54.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.210.1
	github.com/aws/aws-sdk-go-v2/service/ecs v1.90.2
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.58.7
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.55.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.41.1
	github.com/aws/aws-sdk-go-v2/service/identitystore v1.36.7
	github.com/aws/aws-sdk-go-v2/service/kms v1.51.1
	github.com/aws/aws-sdk-go-v2/service/lambda v1.90.1
	github.com/aws/aws-sdk-go-v2/service/organizations v1.53.0
	github.com/aws/aws-sdk-go-v2/service/rds v1.97.2
	github.com/aws/aws-sdk-go-v2/service/s3 v1.107.2
	github.com/aws/aws-sdk-go-v2/service/s3control v1.55.0
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.41.7
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.59.0
	github.com/aws/aws-sdk-go-v2/service/sesv2 v1.66.6
	github.com/aws/aws-sdk-go-v2/service/sns v1.42.6
	github.com/aws/aws-sdk-go-v2/service/ssm v1.68.6
	github.com/aws/aws-sdk-go-v2/service/ssoadmin v1.38.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.19
	github.com/aws/smithy-go v1.27.8
	github.com/locktivity/epack v0.1.34
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.18 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.30 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.37 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.37 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.38 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.30 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.37 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.38 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.25.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.30.1 // indirect
)
