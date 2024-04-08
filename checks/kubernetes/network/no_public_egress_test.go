package network

import (
	"testing"

	"github.com/aquasecurity/trivy-policies/pkg/providers/kubernetes"
	"github.com/aquasecurity/trivy-policies/pkg/scan"
	"github.com/aquasecurity/trivy-policies/pkg/state"
	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicEgress(t *testing.T) {
	tests := []struct {
		name     string
		input    []kubernetes.NetworkPolicy
		expected bool
	}{
		{
			name: "Public destination CIDR",
			input: []kubernetes.NetworkPolicy{
				{
					Metadata: trivyTypes.NewTestMetadata(),
					Spec: kubernetes.NetworkPolicySpec{
						Metadata: trivyTypes.NewTestMetadata(),
						Egress: kubernetes.Egress{
							Metadata: trivyTypes.NewTestMetadata(),
							DestinationCIDRs: []trivyTypes.StringValue{
								trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Private destination CIDR",
			input: []kubernetes.NetworkPolicy{
				{
					Metadata: trivyTypes.NewTestMetadata(),
					Spec: kubernetes.NetworkPolicySpec{
						Metadata: trivyTypes.NewTestMetadata(),
						Egress: kubernetes.Egress{
							Metadata: trivyTypes.NewTestMetadata(),
							DestinationCIDRs: []trivyTypes.StringValue{
								trivyTypes.String("10.0.0.0/16", trivyTypes.NewTestMetadata()),
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
			testState.Kubernetes.NetworkPolicies = test.input
			results := CheckNoPublicEgress.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicEgress.LongID() {
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
