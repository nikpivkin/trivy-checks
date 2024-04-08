package gke

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/google/gke"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableAutoRepair(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Node pool auto repair disabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodePools: []gke.NodePool{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Management: gke.Management{
									Metadata:         trivyTypes.NewTestMetadata(),
									EnableAutoRepair: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Node pool auto repair enabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodePools: []gke.NodePool{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Management: gke.Management{
									Metadata:         trivyTypes.NewTestMetadata(),
									EnableAutoRepair: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.GKE = test.input
			results := CheckEnableAutoRepair.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAutoRepair.LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
