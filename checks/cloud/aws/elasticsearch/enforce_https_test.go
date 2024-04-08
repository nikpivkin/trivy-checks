package elasticsearch

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/aws/elasticsearch"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnforceHttps(t *testing.T) {
	tests := []struct {
		name     string
		input    elasticsearch.Elasticsearch
		expected bool
	}{
		{
			name: "Elasticsearch domain with enforce HTTPS disabled",
			input: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Endpoint: elasticsearch.Endpoint{
							Metadata:     trivyTypes.NewTestMetadata(),
							EnforceHTTPS: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Elasticsearch domain with enforce HTTPS enabled",
			input: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Endpoint: elasticsearch.Endpoint{
							Metadata:     trivyTypes.NewTestMetadata(),
							EnforceHTTPS: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
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
			testState.AWS.Elasticsearch = test.input
			results := CheckEnforceHttps.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnforceHttps.LongID() {
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
