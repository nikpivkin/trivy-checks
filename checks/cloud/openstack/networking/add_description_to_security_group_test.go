package compute

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/openstack"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckSecurityGroupHasDescription(t *testing.T) {
	tests := []struct {
		name     string
		input    openstack.Networking
		expected bool
	}{
		{
			name: "Security group missing description",
			input: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Security group with description",
			input: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("this is for connecting to the database", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.OpenStack.Networking = test.input
			results := CheckSecurityGroupHasDescription.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckSecurityGroupHasDescription.LongID() {
					found = true
				}
			}
			assert.Equal(t, test.expected, found, "Rule should have been found")
		})
	}
}
