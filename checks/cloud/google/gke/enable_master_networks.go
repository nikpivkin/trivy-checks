package gke

import (
	"github.com/aquasecurity/trivy-policies/internal/cheks"
	"github.com/aquasecurity/trivy-policies/pkg/providers"
	"github.com/aquasecurity/trivy-policies/pkg/scan"
	"github.com/aquasecurity/trivy-policies/pkg/severity"
	"github.com/aquasecurity/trivy-policies/pkg/state"
)

var CheckEnableMasterNetworks = cheks.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0061",
		Provider:    providers.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-master-networks",
		Summary:     "Master authorized networks should be configured on GKE clusters",
		Impact:      "Unrestricted network access to the master",
		Resolution:  "Enable master authorized networks",
		Explanation: `Enabling authorized networks means you can restrict master access to a fixed set of CIDR ranges`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableMasterNetworksGoodExamples,
			BadExamples:         terraformEnableMasterNetworksBadExamples,
			Links:               terraformEnableMasterNetworksLinks,
			RemediationMarkdown: terraformEnableMasterNetworksRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.Metadata.IsUnmanaged() {
				continue
			}
			if cluster.MasterAuthorizedNetworks.Enabled.IsFalse() {
				results.Add(
					"Cluster does not have master authorized networks enabled.",
					cluster.MasterAuthorizedNetworks.Enabled,
				)
			} else {
				results.AddPassed(&cluster)
			}

		}
		return
	},
)
