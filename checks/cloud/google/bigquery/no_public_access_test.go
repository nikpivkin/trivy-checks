package bigquery

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/google/bigquery"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    bigquery.BigQuery
		expected bool
	}{
		{
			name: "positive result",
			input: bigquery.BigQuery{
				Datasets: []bigquery.Dataset{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						AccessGrants: []bigquery.AccessGrant{
							{
								SpecialGroup: trivyTypes.String(
									bigquery.SpecialGroupAllAuthenticatedUsers,
									trivyTypes.NewTestMetadata(),
								),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "negative result",
			input: bigquery.BigQuery{
				Datasets: []bigquery.Dataset{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						AccessGrants: []bigquery.AccessGrant{
							{
								SpecialGroup: trivyTypes.String(
									"anotherGroup",
									trivyTypes.NewTestMetadata(),
								),
							},
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
			testState.Google.BigQuery = test.input
			results := CheckNoPublicAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicAccess.LongID() {
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
