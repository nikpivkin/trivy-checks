package s3

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/aws/cloudtrail"
	"github.com/aquasecurity/trivy-policies/pkg/providers/aws/s3"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableObjectWriteLogging(t *testing.T) {
	tests := []struct {
		name       string
		s3         s3.S3
		cloudtrail cloudtrail.CloudTrail
		expected   bool
	}{
		{
			name: "S3 bucket with no cloudtrail logging",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "S3 bucket with ReadOnly cloudtrail logging (all of s3)",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
					},
				},
			},
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EventSelectors: []cloudtrail.EventSelector{
							{
								Metadata:      trivyTypes.NewTestMetadata(),
								ReadWriteType: trivyTypes.String("ReadOnly", trivyTypes.NewTestMetadata()),
								DataResources: []cloudtrail.DataResource{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Type:     trivyTypes.String("AWS::S3::Object", trivyTypes.NewTestMetadata()),
										Values: []trivyTypes.StringValue{
											trivyTypes.String("arn:aws:s3", trivyTypes.NewTestMetadata()),
										},
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "S3 bucket with WriteOnly cloudtrail logging (all of s3)",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
					},
				},
			},
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EventSelectors: []cloudtrail.EventSelector{
							{
								Metadata:      trivyTypes.NewTestMetadata(),
								ReadWriteType: trivyTypes.String("WriteOnly", trivyTypes.NewTestMetadata()),
								DataResources: []cloudtrail.DataResource{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Type:     trivyTypes.String("AWS::S3::Object", trivyTypes.NewTestMetadata()),
										Values: []trivyTypes.StringValue{
											trivyTypes.String("arn:aws:s3", trivyTypes.NewTestMetadata()),
										},
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (all of s3)",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
					},
				},
			},
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EventSelectors: []cloudtrail.EventSelector{
							{
								Metadata:      trivyTypes.NewTestMetadata(),
								ReadWriteType: trivyTypes.String("All", trivyTypes.NewTestMetadata()),
								DataResources: []cloudtrail.DataResource{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Type:     trivyTypes.String("AWS::S3::Object", trivyTypes.NewTestMetadata()),
										Values: []trivyTypes.StringValue{
											trivyTypes.String("arn:aws:s3", trivyTypes.NewTestMetadata()),
										},
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (only this bucket)",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
					},
				},
			},
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EventSelectors: []cloudtrail.EventSelector{
							{
								Metadata:      trivyTypes.NewTestMetadata(),
								ReadWriteType: trivyTypes.String("All", trivyTypes.NewTestMetadata()),
								DataResources: []cloudtrail.DataResource{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Type:     trivyTypes.String("AWS::S3::Object", trivyTypes.NewTestMetadata()),
										Values: []trivyTypes.StringValue{
											trivyTypes.String("arn:aws:s3:::test-bucket/", trivyTypes.NewTestMetadata()),
										},
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (only another bucket)",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
					},
				},
			},
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EventSelectors: []cloudtrail.EventSelector{
							{
								Metadata:      trivyTypes.NewTestMetadata(),
								ReadWriteType: trivyTypes.String("All", trivyTypes.NewTestMetadata()),
								DataResources: []cloudtrail.DataResource{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Type:     trivyTypes.String("AWS::S3::Object", trivyTypes.NewTestMetadata()),
										Values: []trivyTypes.StringValue{
											trivyTypes.String("arn:aws:s3:::test-bucket2/", trivyTypes.NewTestMetadata()),
										},
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (this bucket, missing slash)",
			s3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
					},
				},
			},
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EventSelectors: []cloudtrail.EventSelector{
							{
								Metadata:      trivyTypes.NewTestMetadata(),
								ReadWriteType: trivyTypes.String("All", trivyTypes.NewTestMetadata()),
								DataResources: []cloudtrail.DataResource{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Type:     trivyTypes.String("AWS::S3::Object", trivyTypes.NewTestMetadata()),
										Values: []trivyTypes.StringValue{
											trivyTypes.String("arn:aws:s3:::test-bucket", trivyTypes.NewTestMetadata()),
										},
									},
								},
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
			testState.AWS.S3 = test.s3
			testState.AWS.CloudTrail = test.cloudtrail
			results := CheckEnableObjectWriteLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableObjectWriteLogging.LongID() {
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
