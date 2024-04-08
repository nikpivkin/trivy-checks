package cloudfront

import (
	"github.com/aquasecurity/trivy-policies/internal/cheks"
	"github.com/aquasecurity/trivy-policies/pkg/providers"
	"github.com/aquasecurity/trivy-policies/pkg/scan"
	"github.com/aquasecurity/trivy-policies/pkg/severity"
	"github.com/aquasecurity/trivy-policies/pkg/state"
)

var CheckEnableLogging = cheks.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0010",
		Provider:    providers.AWSProvider,
		Service:     "cloudfront",
		ShortCode:   "enable-logging",
		Summary:     "Cloudfront distribution should have Access Logging configured",
		Impact:      "Logging provides vital information about access and usage",
		Resolution:  "Enable logging for CloudFront distributions",
		Explanation: `You should configure CloudFront Access Logging to create log files that contain detailed information about every user request that CloudFront receives`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableLoggingGoodExamples,
			BadExamples:         terraformEnableLoggingBadExamples,
			Links:               terraformEnableLoggingLinks,
			RemediationMarkdown: terraformEnableLoggingRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableLoggingGoodExamples,
			BadExamples:         cloudFormationEnableLoggingBadExamples,
			Links:               cloudFormationEnableLoggingLinks,
			RemediationMarkdown: cloudFormationEnableLoggingRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, dist := range s.AWS.Cloudfront.Distributions {
			if dist.Logging.Bucket.IsEmpty() {
				results.Add(
					"Distribution does not have logging enabled.",
					dist.Logging.Bucket,
				)
			} else {
				results.AddPassed(&dist)
			}
		}
		return
	},
)
