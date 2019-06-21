# flowlog

Limits the outbound Internet access of an AWS security group to a set of domains by carrying out DNS lookups periodically.

## Requirements

* AWS CLI already configured with Administrator permission
* [Golang](https://golang.org)

## Setup process

### Building

```shell
make build
```

### Deployment

Configure the `template.yaml` to set the environment variables to set which URLs are allowed to be accessed by the security group:

```yaml
      Environment:
        Variables:
          URLS: https://example.com,http://example.net
          SECURITY_GROUPS: sg-12345,sg-54321
```

Create an `S3 bucket` to upload the Lambda function.

```bash
aws s3 mb s3://domain-whitelist-lambda
```

Run the following command to package the Lambda to S3:

```bash
sam package \
    --output-template-file packaged.yaml \
    --s3-bucket domain-whitelist-lambda
```

Next, the following command will create a Cloudformation Stack and deploy your SAM resources.

```bash
sam deploy \
    --template-file packaged.yaml \
    --stack-name sgwhitelist \
    --capabilities CAPABILITY_IAM
```

# Appendix

### Golang installation

Please ensure Go 1.x (where 'x' is the latest version) is installed as per the instructions on the official golang website: https://golang.org/doc/install
