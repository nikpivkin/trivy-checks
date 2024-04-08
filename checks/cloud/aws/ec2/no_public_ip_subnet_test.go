package ec2

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/providers/aws/ec2"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIpSubnet(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "Subnet with public access",
			input: ec2.EC2{
				Subnets: []ec2.Subnet{
					{
						Metadata:            trivyTypes.NewTestMetadata(),
						MapPublicIpOnLaunch: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Subnet without public access",
			input: ec2.EC2{
				Subnets: []ec2.Subnet{
					{
						Metadata:            trivyTypes.NewTestMetadata(),
						MapPublicIpOnLaunch: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.EC2 = test.input
			results := CheckNoPublicIpSubnet.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicIpSubnet.LongID() {
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
