package compute

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/openstack"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPlaintextPassword(t *testing.T) {
	tests := []struct {
		name     string
		input    openstack.Compute
		expected bool
	}{
		{
			name: "Instance admin with plaintext password set",
			input: openstack.Compute{
				Instances: []openstack.Instance{
					{
						Metadata:      trivyTypes.NewTestMetadata(),
						AdminPassword: trivyTypes.String("very-secret", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance admin with no plaintext password",
			input: openstack.Compute{
				Instances: []openstack.Instance{
					{
						Metadata:      trivyTypes.NewTestMetadata(),
						AdminPassword: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.OpenStack.Compute = test.input
			results := CheckNoPlaintextPassword.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPlaintextPassword.LongID() {
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
