
Enable Cloudtrail in all regions

```yaml
Resources:
  GoodExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: true
      S3BucketName: CloudtrailBucket
      S3KeyPrefix: /trailing
      TrailName: Cloudtrail
```


