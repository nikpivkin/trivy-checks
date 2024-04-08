package msk

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/aws/msk"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableAtRestEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    msk.MSK
		expected bool
	}{
		{
			name: "Cluster with at rest encryption enabled",
			input: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EncryptionAtRest: msk.EncryptionAtRest{
							Metadata:  trivyTypes.NewTestMetadata(),
							KMSKeyARN: trivyTypes.String("foo-bar-key", trivyTypes.NewTestMetadata()),
							Enabled:   trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Cluster with at rest encryption disabled",
			input: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.MSK = test.input
			results := CheckEnableAtRestEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAtRestEncryption.LongID() {
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
