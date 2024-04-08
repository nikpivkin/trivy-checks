package dns

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/google/dns"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableDnssec(t *testing.T) {
	tests := []struct {
		name     string
		input    dns.DNS
		expected bool
	}{
		{
			name: "DNSSec disabled and required when visibility explicitly public",
			input: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Visibility: trivyTypes.String("public", trivyTypes.NewTestMetadata()),
						DNSSec: dns.DNSSec{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "DNSSec enabled",
			input: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Visibility: trivyTypes.String("public", trivyTypes.NewTestMetadata()),
						DNSSec: dns.DNSSec{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "DNSSec not required when private",
			input: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Visibility: trivyTypes.String("private", trivyTypes.NewTestMetadata()),
						DNSSec: dns.DNSSec{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
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
			testState.Google.DNS = test.input
			results := CheckEnableDnssec.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableDnssec.LongID() {
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
