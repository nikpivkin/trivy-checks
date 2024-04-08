package dns

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/google/dns"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoRsaSha1(t *testing.T) {
	tests := []struct {
		name     string
		input    dns.DNS
		expected bool
	}{
		{
			name: "Zone signing using RSA SHA1 key",
			input: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						DNSSec: dns.DNSSec{
							Metadata: trivyTypes.NewTestMetadata(),
							DefaultKeySpecs: []dns.KeySpecs{
								{
									Metadata:  trivyTypes.NewTestMetadata(),
									Algorithm: trivyTypes.String("rsasha1", trivyTypes.NewTestMetadata()),
									KeyType:   trivyTypes.String("keySigning", trivyTypes.NewTestMetadata()),
								},
								{
									Metadata:  trivyTypes.NewTestMetadata(),
									Algorithm: trivyTypes.String("rsasha1", trivyTypes.NewTestMetadata()),
									KeyType:   trivyTypes.String("zoneSigning", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Zone signing using RSA SHA512 key",
			input: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						DNSSec: dns.DNSSec{
							Metadata: trivyTypes.NewTestMetadata(),
							DefaultKeySpecs: []dns.KeySpecs{
								{
									Metadata:  trivyTypes.NewTestMetadata(),
									Algorithm: trivyTypes.String("rsasha512", trivyTypes.NewTestMetadata()),
									KeyType:   trivyTypes.String("keySigning", trivyTypes.NewTestMetadata()),
								},
								{
									Metadata:  trivyTypes.NewTestMetadata(),
									Algorithm: trivyTypes.String("rsasha512", trivyTypes.NewTestMetadata()),
									KeyType:   trivyTypes.String("zoneSigning", trivyTypes.NewTestMetadata()),
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
			testState.Google.DNS = test.input
			results := CheckNoRsaSha1.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoRsaSha1.LongID() {
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
