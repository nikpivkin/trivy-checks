package iam

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/aws/iam"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoUserAttachedPolicies(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "user without policies attached",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Name:     trivyTypes.String("example", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "user with a policy attached",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Name:     trivyTypes.String("example", trivyTypes.NewTestMetadata()),
						Policies: []iam.Policy{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Name:     trivyTypes.String("another.policy", trivyTypes.NewTestMetadata()),
								Document: iam.Document{
									Metadata: trivyTypes.NewTestMetadata(),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := checkNoUserAttachedPolicies.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == checkNoUserAttachedPolicies.LongID() {
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
