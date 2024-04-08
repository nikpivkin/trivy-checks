package spaces

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/digitalocean/spaces"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckVersioningEnabled(t *testing.T) {
	tests := []struct {
		name     string
		input    spaces.Spaces
		expected bool
	}{
		{
			name: "Space bucket versioning disabled",
			input: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Versioning: spaces.Versioning{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Space bucket versioning enabled",
			input: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Versioning: spaces.Versioning{
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
			testState.DigitalOcean.Spaces = test.input
			results := CheckVersioningEnabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckVersioningEnabled.LongID() {
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
