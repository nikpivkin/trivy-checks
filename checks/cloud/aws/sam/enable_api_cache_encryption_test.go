package sam

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/aws/sam"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableApiCacheEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    sam.SAM
		expected bool
	}{
		{
			name: "API unencrypted cache data",
			input: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						RESTMethodSettings: sam.RESTMethodSettings{
							Metadata:           trivyTypes.NewTestMetadata(),
							CacheDataEncrypted: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "API encrypted cache data",
			input: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						RESTMethodSettings: sam.RESTMethodSettings{
							Metadata:           trivyTypes.NewTestMetadata(),
							CacheDataEncrypted: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
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
			testState.AWS.SAM = test.input
			results := CheckEnableApiCacheEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableApiCacheEncryption.LongID() {
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
