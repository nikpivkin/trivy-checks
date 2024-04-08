package computing

import (
	"testing"

	"github.com/aquasecurity/trivy-policies/pkg/providers/nifcloud/computing"
	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAddSecurityGroupToInstance(t *testing.T) {
	tests := []struct {
		name     string
		input    computing.Computing
		expected bool
	}{
		{
			name: "NIFCLOUD instance with no security group provided",
			input: computing.Computing{
				Instances: []computing.Instance{
					{
						Metadata:      trivyTypes.NewTestMetadata(),
						SecurityGroup: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "NIFCLOUD instance with security group",
			input: computing.Computing{
				Instances: []computing.Instance{
					{
						Metadata:      trivyTypes.NewTestMetadata(),
						SecurityGroup: trivyTypes.String("some security group", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Nifcloud.Computing = test.input
			results := CheckAddSecurityGroupToInstance.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAddSecurityGroupToInstance.LongID() {
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
