
Enable ignoring the application of public ACLs in PUT calls

```yaml
Resources:
  GoodExample:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: Private
      PublicAccessBlockConfiguration:
        IgnorePublicAcls: true
```


