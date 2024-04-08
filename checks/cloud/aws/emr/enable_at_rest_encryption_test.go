package emr

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/providers/aws/emr"
	"github.com/aquasecurity/trivy-policies/pkg/scan"
	"github.com/aquasecurity/trivy-policies/pkg/state"
	"github.com/stretchr/testify/assert"
)

func TestEnableAtRestEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    emr.EMR
		expected bool
	}{
		{
			name: "EMR cluster with at-rest encryption disabled",
			input: emr.EMR{
				SecurityConfiguration: []emr.SecurityConfiguration{
					{
						Name: trivyTypes.String("test", trivyTypes.NewTestMetadata()),
						Configuration: trivyTypes.String(`{
							"EncryptionConfiguration": {
							  "AtRestEncryptionConfiguration": {
								"S3EncryptionConfiguration": {
								  "EncryptionMode": "SSE-S3"
								},
								"LocalDiskEncryptionConfiguration": {
								  "EncryptionKeyProviderType": "AwsKms",
								  "AwsKmsKey": "arn:aws:kms:us-west-2:187416307283:alias/tf_emr_test_key"
								}
							  },
							  "EnableAtRestEncryption": false
							}
						  }`, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "EMR cluster with at-rest encryption enabled",
			input: emr.EMR{
				SecurityConfiguration: []emr.SecurityConfiguration{
					{
						Name: trivyTypes.String("test", trivyTypes.NewTestMetadata()),
						Configuration: trivyTypes.String(`{
							"EncryptionConfiguration": {
							  "AtRestEncryptionConfiguration": {
								"S3EncryptionConfiguration": {
								  "EncryptionMode": "SSE-S3"
								},
								"LocalDiskEncryptionConfiguration": {
								  "EncryptionKeyProviderType": "AwsKms",
								  "AwsKmsKey": "arn:aws:kms:us-west-2:187416307283:alias/tf_emr_test_key"
								}
							  },
							  "EnableAtRestEncryption": true
							}
						  }`, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.EMR = test.input
			results := CheckEnableAtRestEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAtRestEncryption.LongID() {
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
