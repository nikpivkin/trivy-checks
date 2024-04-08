package appservice

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/azure/appservice"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckUseSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    appservice.AppService
		expected bool
	}{
		{
			name: "Minimum TLS version TLS1_0",
			input: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       trivyTypes.BoolValue
							MinimumTLSVersion trivyTypes.StringValue
						}{
							EnableHTTP2:       trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							MinimumTLSVersion: trivyTypes.String("1.0", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Minimum TLS version TLS1_2",
			input: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       trivyTypes.BoolValue
							MinimumTLSVersion trivyTypes.StringValue
						}{
							EnableHTTP2:       trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							MinimumTLSVersion: trivyTypes.String("1.2", trivyTypes.NewTestMetadata()),
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
			testState.Azure.AppService = test.input
			results := CheckUseSecureTlsPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckUseSecureTlsPolicy.LongID() {
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
