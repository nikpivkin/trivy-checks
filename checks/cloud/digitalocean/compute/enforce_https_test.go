package compute

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/digitalocean/compute"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnforceHttps(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Load balancer forwarding rule using HTTP",
			input: compute.Compute{
				LoadBalancers: []compute.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ForwardingRules: []compute.ForwardingRule{
							{
								Metadata:      trivyTypes.NewTestMetadata(),
								EntryProtocol: trivyTypes.String("http", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Load balancer forwarding rule using HTTPS",
			input: compute.Compute{
				LoadBalancers: []compute.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ForwardingRules: []compute.ForwardingRule{
							{
								Metadata:      trivyTypes.NewTestMetadata(),
								EntryProtocol: trivyTypes.String("https", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Load balancer forwarding rule using HTTP, but HTTP redirection to HTTPS is enabled",
			input: compute.Compute{
				LoadBalancers: []compute.LoadBalancer{
					{
						Metadata:            trivyTypes.NewTestMetadata(),
						RedirectHttpToHttps: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						ForwardingRules: []compute.ForwardingRule{
							{
								Metadata:      trivyTypes.NewTestMetadata(),
								EntryProtocol: trivyTypes.String("http", trivyTypes.NewTestMetadata()),
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
			testState.DigitalOcean.Compute = test.input
			results := CheckEnforceHttps.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnforceHttps.LongID() {
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
