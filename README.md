# Cloud WAF Logging Integration Tool
Radware Cloud WAF Log Integration Tool: Extends Cloud WAF's AWS S3 log exporting capabilities by enabling reformatting and distribution to various formats and cloud providers. Enhances integration with diverse services and SIEMs through AWS Lambda-powered transformation and management.

## Version Updates

- **Version 1.0 (Initial Release)**:
  - Initial release of the tool.

## Features

- **Log Reformatting**: Converts AWS S3 logs from `.json.gz` to `ndjson`, `json`, or `json.gz` (for Azure).
- **Decompression**: Decompress `.json.gz` files to extract JSON content.
- **AWS S3 and Azure Blob Transfer**: Uploads files to Azure Blob Storage or specified S3 bucket.
- **Flexible Destination Control**: Choose between internal or external S3 buckets, or Azure Blob Storage.
- **Suffix Handling**: Add or remove suffixes in the folder name for saved files.
- **Optional File Deletion**: Delete original files post-processing.

## Prerequisites

1. AWS Lambda execution role with necessary permissions.
2. Azure Blob Storage account and container (for Azure Blob Storage transfer).
3. SAS token for Azure Blob Storage account (for Azure Blob Storage transfer).

## Configuration

Set the following in the Lambda function code:

- `DELETE_ORIGINAL` (bool): If `True`, original files are deleted after processing. Default is `True`.
  - Example: `DELETE_ORIGINAL = True`
- `DESTINATION` (str): Determines where the file will be uploaded. Options are `"Internal S3"`, `"External S3"`, `"Azure"`.
  - Example: `DESTINATION = "Azure"`
- `OUTPUT_FORMAT` (str): Format of the transformed file. Options are `"ndjson"`, `"json"`, `"json.gz"` (json.gz is for Azure only).
  - Example: `OUTPUT_FORMAT = "json"`
- `SUFFIX_MODE` (str): Modes for handling folder name suffixes. Options are `"add"` or `"remove"`.
  - Example: `SUFFIX_MODE = "add"`
- `ORIGINAL_SUFFIX` (str): Suffix in the original folder name to be removed if `SUFFIX_MODE` is `"remove"`.
  - Example: `ORIGINAL_SUFFIX = "unprocessed"`
- `NEW_SUFFIX` (str): New suffix to add to the folder name if `SUFFIX_MODE` is `"add"`.
  - Example: `NEW_SUFFIX = "processed"`
- `INTERNAL_DESTINATION_BUCKET` (str or None): The S3 bucket where the transformed file will be uploaded if `DESTINATION` is `"Internal S3"`. If `None`, defaults to the source bucket.
  - Example: `INTERNAL_DESTINATION_BUCKET = "my-internal-bucket"`

For External S3 Destination:
- `EXTERNAL_AWS_ACCESS_KEY_ID`, `EXTERNAL_AWS_SECRET_ACCESS_KEY`, `EXTERNAL_BUCKET_REGION`: Credentials and region for the external S3 bucket.
- `EXTERNAL_DESTINATION_BUCKET` (str): The S3 bucket where the transformed file will be uploaded if `DESTINATION` is `"External S3"`.
- `EXTERNAL_PREFIX` (str): Prefix for the transformed file in the external S3 bucket. End with a slash if specified.
  - Example: `EXTERNAL_DESTINATION_BUCKET = "my-external-bucket"`

For Azure Destination:
- `ACCOUNT_NAME` (str): Name of the Azure storage account.
  - Example: `ACCOUNT_NAME = "myazureaccount"`
- `CONTAINER_NAME` (str): Name of the Azure storage container.
  - Example: `CONTAINER_NAME = "mycontainer"`
- `SAS_TOKEN` (str): SAS token for Azure Blob Storage access.
  - Example: `SAS_TOKEN = "?sv=...[token]..."`

## Deployment & Setup

1. Download the script from GitHub.
2. Create a ZIP file with `lambda_function.py` at the root.
3. Create an AWS Lambda function using Python 3.11.
4. Upload the ZIP file to the Lambda function.
5. Set the function's handler to `lambda_function.lambda_handler`.
6. Increase the Lambda function timeout to 5 minutes.
7. Set the Lambda function memory to at least 256 MB.
8. Set up an S3 event trigger for new `.json.gz` file uploads.

## Usage

When a `.json.gz` file is uploaded to the S3 bucket, the Lambda function will process it according to the configurations set, transforming and transferring the file to the specified destination.

## Lambda IAM Permissions

- Permissions for S3 bucket access (`GetObject`, `PutObject`, `DeleteObject`).
- Permissions for logging to Amazon CloudWatch Logs.
- Additional permissions for external S3 bucket interactions, if applicable.

## Troubleshooting

- Check CloudWatch Logs for errors.
- Verify all configurations and permissions, especially for SAS tokens and AWS access keys.

## Conclusion

This Lambda function automates the transformation and transfer of Cloud WAF logs from AWS S3 to various formats and destinations, enhancing integration capabilities with different cloud environments and SIEMs.

