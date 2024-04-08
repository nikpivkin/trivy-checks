package compute

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/google/compute"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIngress(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Firewall ingress rule with multiple public source addresses",
			input: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Firewall: &compute.Firewall{
							Metadata: trivyTypes.NewTestMetadata(),
							IngressRules: []compute.IngressRule{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									FirewallRule: compute.FirewallRule{
										Metadata: trivyTypes.NewTestMetadata(),
										IsAllow:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
										Enforced: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
									},
									SourceRanges: []trivyTypes.StringValue{
										trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
										trivyTypes.String("1.2.3.4/32", trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall ingress rule with public source address",
			input: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Firewall: &compute.Firewall{
							Metadata: trivyTypes.NewTestMetadata(),
							IngressRules: []compute.IngressRule{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									FirewallRule: compute.FirewallRule{
										Metadata: trivyTypes.NewTestMetadata(),
										IsAllow:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
										Enforced: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
									},
									SourceRanges: []trivyTypes.StringValue{
										trivyTypes.String("1.2.3.4/32", trivyTypes.NewTestMetadata()),
									},
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
			testState.Google.Compute = test.input
			results := CheckNoPublicIngress.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicIngress.LongID() {
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
