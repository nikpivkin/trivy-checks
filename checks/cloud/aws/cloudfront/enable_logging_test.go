package cloudfront

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/aws/cloudfront"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    cloudfront.Cloudfront
		expected bool
	}{
		{
			name: "CloudFront distribution missing logging configuration",
			input: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: cloudfront.Logging{
							Metadata: trivyTypes.NewTestMetadata(),
							Bucket:   trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "CloudFront distribution with logging configured",
			input: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: cloudfront.Logging{
							Metadata: trivyTypes.NewTestMetadata(),
							Bucket:   trivyTypes.String("mylogs.s3.amazonaws.com", trivyTypes.NewTestMetadata()),
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
			testState.AWS.Cloudfront = test.input
			results := CheckEnableLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableLogging.LongID() {
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
