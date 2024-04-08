package apigateway

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	v1 "github.com/aquasecurity/trivy-policies/pkg/providers/aws/apigateway/v1"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckUseSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    v1.APIGateway
		expected bool
	}{
		{
			name: "API Gateway domain name with TLS version 1.0",
			input: v1.APIGateway{
				DomainNames: []v1.DomainName{
					{
						Metadata:       trivyTypes.NewTestMetadata(),
						SecurityPolicy: trivyTypes.String("TLS_1_0", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "API Gateway domain name with TLS version 1.2",
			input: v1.APIGateway{
				DomainNames: []v1.DomainName{
					{
						Metadata:       trivyTypes.NewTestMetadata(),
						SecurityPolicy: trivyTypes.String("TLS_1_2", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.APIGateway.V1 = test.input
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
