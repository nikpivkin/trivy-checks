package s3

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/aws/s3"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckVersioningIsEnabled(t *testing.T) {
	tests := []struct {
		name     string
		input    s3.S3
		expected bool
	}{
		{
			name: "S3 bucket versioning disabled",
			input: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Versioning: s3.Versioning{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "S3 bucket versioning enabled",
			input: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Versioning: s3.Versioning{
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
			testState.AWS.S3 = test.input
			results := CheckVersioningIsEnabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckVersioningIsEnabled.LongID() {
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
