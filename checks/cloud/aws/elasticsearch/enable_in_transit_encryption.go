package elasticsearch

import (
	"github.com/aquasecurity/trivy-policies/internal/cheks"
	"github.com/aquasecurity/trivy-policies/pkg/providers"
	"github.com/aquasecurity/trivy-policies/pkg/scan"
	"github.com/aquasecurity/trivy-policies/pkg/severity"
	"github.com/aquasecurity/trivy-policies/pkg/state"
)

var CheckEnableInTransitEncryption = cheks.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0043",
		Provider:    providers.AWSProvider,
		Service:     "elastic-search",
		ShortCode:   "enable-in-transit-encryption",
		Summary:     "Elasticsearch domain uses plaintext traffic for node to node communication.",
		Impact:      "In transit data between nodes could be read if intercepted",
		Resolution:  "Enable encrypted node to node communication",
		Explanation: `Traffic flowing between Elasticsearch nodes should be encrypted to ensure sensitive data is kept private.`,
		Links: []string{
			"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableInTransitEncryptionGoodExamples,
			BadExamples:         terraformEnableInTransitEncryptionBadExamples,
			Links:               terraformEnableInTransitEncryptionLinks,
			RemediationMarkdown: terraformEnableInTransitEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableInTransitEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableInTransitEncryptionBadExamples,
			Links:               cloudFormationEnableInTransitEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableInTransitEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, domain := range s.AWS.Elasticsearch.Domains {
			if domain.TransitEncryption.Enabled.IsFalse() {
				results.Add(
					"Domain does not have in-transit encryption enabled.",
					domain.TransitEncryption.Enabled,
				)
			} else {
				results.AddPassed(&domain)
			}
		}
		return
	},
)
