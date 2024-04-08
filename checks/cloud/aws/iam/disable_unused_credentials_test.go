package iam

import (
	"testing"
	"time"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/aws/iam"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckUnusedCredentialsDisabled(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "User logged in today",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("user", trivyTypes.NewTestMetadata()),
						LastAccess: trivyTypes.Time(time.Now(), trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "User never logged in, but used access key today",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("user", trivyTypes.NewTestMetadata()),
						LastAccess: trivyTypes.TimeUnresolvable(trivyTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								AccessKeyId:  trivyTypes.String("AKIACKCEVSQ6C2EXAMPLE", trivyTypes.NewTestMetadata()),
								Active:       trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								CreationDate: trivyTypes.Time(time.Now().Add(-time.Hour*24*30), trivyTypes.NewTestMetadata()),
								LastAccess:   trivyTypes.Time(time.Now(), trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "User logged in 100 days ago",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("user", trivyTypes.NewTestMetadata()),
						LastAccess: trivyTypes.Time(time.Now().Add(-time.Hour*24*100), trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "User last used access key 100 days ago but it is no longer active",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("user", trivyTypes.NewTestMetadata()),
						LastAccess: trivyTypes.TimeUnresolvable(trivyTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								AccessKeyId:  trivyTypes.String("AKIACKCEVSQ6C2EXAMPLE", trivyTypes.NewTestMetadata()),
								Active:       trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								CreationDate: trivyTypes.Time(time.Now().Add(-time.Hour*24*120), trivyTypes.NewTestMetadata()),
								LastAccess:   trivyTypes.Time(time.Now().Add(-time.Hour*24*100), trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "User last used access key 100 days ago and it is active",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("user", trivyTypes.NewTestMetadata()),
						LastAccess: trivyTypes.TimeUnresolvable(trivyTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								AccessKeyId:  trivyTypes.String("AKIACKCEVSQ6C2EXAMPLE", trivyTypes.NewTestMetadata()),
								Active:       trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								CreationDate: trivyTypes.Time(time.Now().Add(-time.Hour*24*120), trivyTypes.NewTestMetadata()),
								LastAccess:   trivyTypes.Time(time.Now().Add(-time.Hour*24*100), trivyTypes.NewTestMetadata()),
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
			results := CheckUnusedCredentialsDisabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckUnusedCredentialsDisabled.LongID() {
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
