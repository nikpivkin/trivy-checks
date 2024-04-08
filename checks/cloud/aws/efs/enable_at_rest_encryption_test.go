package efs

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/aws/efs"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableAtRestEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    efs.EFS
		expected bool
	}{
		{
			name: "positive result",
			input: efs.EFS{
				FileSystems: []efs.FileSystem{
					{
						Metadata:  trivyTypes.NewTestMetadata(),
						Encrypted: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					}},
			},
			expected: true,
		},
		{
			name: "negative result",
			input: efs.EFS{
				FileSystems: []efs.FileSystem{
					{
						Metadata:  trivyTypes.NewTestMetadata(),
						Encrypted: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					}},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.EFS = test.input
			results := CheckEnableAtRestEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAtRestEncryption.LongID() {
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
