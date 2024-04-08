package rdb

import (
	"testing"

	"github.com/aquasecurity/trivy-policies/pkg/providers/nifcloud/rdb"
	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoCommonPrivateDBInstance(t *testing.T) {
	tests := []struct {
		name     string
		input    rdb.RDB
		expected bool
	}{
		{
			name: "NIFCLOUD db instance with common private",
			input: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:  trivyTypes.NewTestMetadata(),
						NetworkID: trivyTypes.String("net-COMMON_PRIVATE", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "NIFCLOUD db instance with private LAN",
			input: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:  trivyTypes.NewTestMetadata(),
						NetworkID: trivyTypes.String("net-some-private-lan", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Nifcloud.RDB = test.input
			results := CheckNoCommonPrivateDBInstance.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoCommonPrivateDBInstance.LongID() {
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
