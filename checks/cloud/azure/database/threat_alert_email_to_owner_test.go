package database

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/azure/database"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckThreatAlertEmailToOwner(t *testing.T) {
	tests := []struct {
		name     string
		input    database.Database
		expected bool
	}{
		{
			name: "MS SQL Server alert account admins disabled",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata:           trivyTypes.NewTestMetadata(),
								EmailAccountAdmins: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MS SQL Server alert account admins enabled",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata:           trivyTypes.NewTestMetadata(),
								EmailAccountAdmins: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
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
			testState.Azure.Database = test.input
			results := CheckThreatAlertEmailToOwner.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckThreatAlertEmailToOwner.LongID() {
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
