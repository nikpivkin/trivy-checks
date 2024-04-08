package storage

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/azure/storage"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckQueueServicesLoggingEnabled(t *testing.T) {
	tests := []struct {
		name     string
		input    storage.Storage
		expected bool
	}{
		{
			name: "Storage account queue properties logging disabled",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						QueueProperties: storage.QueueProperties{
							Metadata:      trivyTypes.NewTestMetadata(),
							EnableLogging: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
						Queues: []storage.Queue{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Name:     trivyTypes.String("my-queue", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Storage account queue properties logging disabled with no queues",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						QueueProperties: storage.QueueProperties{
							Metadata:      trivyTypes.NewTestMetadata(),
							EnableLogging: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Storage account queue properties logging enabled",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						QueueProperties: storage.QueueProperties{
							Metadata:      trivyTypes.NewTestMetadata(),
							EnableLogging: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
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
			testState.Azure.Storage = test.input
			results := CheckQueueServicesLoggingEnabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckQueueServicesLoggingEnabled.LongID() {
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
