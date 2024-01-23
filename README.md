# Cloud WAAP Logging Integration Tool

## Overview
The Cloud WAAP Logging Integration Tool is specifically designed to work with Radware's Cloud WAAP. Its primary function is to facilitate the handling of logs once they are transferred to an AWS S3 bucket. This tool is pivotal in transforming and efficiently managing these logs, enhancing their compatibility for integration with various services and SIEMs.

This guide provides detailed instructions on utilizing an AWS Lambda function for effective log format transformation and management.

Additionally, the tool's key capabilities include decompressing .json.gz files for easier access, transforming logs into JSON or NDJSON formats to suit different analytical needs, and offering the flexibility to transfer logs to either internal/external AWS S3 buckets or Azure Blob Storage.

## Prerequisites
- **Download Zip Package:** Download the latest zip package available in Github with the name Cloud-WAAP-Logging-Integration-Tool-Lambda.zip.
- **AWS Knowledge:** A basic understanding of the AWS cloud platform.
- **AWS Account:** An AWS account with access to S3 and Lambda services.
- **Radware Cloud WAAP:** Radware's Cloud WAAP configured to send logs to an AWS S3 bucket.
- **For Azure Blob Storage Transfer:**
  - **Azure Knowledge:** A basic understanding of the Azure cloud platform.
  - **Azure Storage Account:** An Azure Storage Account and a corresponding SAS Token.

## Current Version
Version 1.2

## Features
- **Decompression:** Decompress JSON.GZ files to extract JSON content.
- **Log Reformatting:** Converts AWS S3 logs from JSON.GZ format to NDJSON or JSON.
- **Transfer to Custom AWS S3 or Azure Blob:** Uploads files to Azure Blob Storage or specified S3 bucket.
- **Flexible Folder Structure:** Option to retain original folder structure or consolidate files into a specific directory.
- **Folder Suffix Customization:** Add or remove suffixes in the folder name for saved files (applicable when original folder structure is retained).
- **Optional File Deletion:** Delete original files post-processing.

## Operational Sequence
The tool operates in the following sequence:

### 1. Initiation
- The process commences when Radware's Cloud WAAP sends logs to a designated AWS S3 bucket.

### 2. Event Trigger
- The deposition of a new log file in the S3 bucket automatically triggers an event.

### 3. Lambda Function Execution
- The Lambda function performs the following actions:
  - Downloads the new file from the S3 bucket.
  - Adjusts the file's format based on predefined settings.
  - Sends the reformatted file to the chosen destination.
  - Optionally, removes the original file from the S3 bucket.


## Configuration

Set the following in the Lambda function code:

- `DELETE_ORIGINAL` (bool): If `True`, original files are deleted after processing. Default is `True`.
  - Example: `DELETE_ORIGINAL = True`
- `DESTINATION` (str): Determines where the file will be uploaded. Options are `"Internal S3"`, `"External S3"`, `"Azure"`.
  - Example: `DESTINATION = "Azure"`
- `OUTPUT_FORMAT` (str): Format of the transformed file. Options are `"ndjson"`, `"json"`, `"json.gz"` (json.gz is for Azure only).
  - Example: `OUTPUT_FORMAT = "ndjson"`
- `KEEP_ORIGINAL_FOLDER_STRUCTURE` (bool): Set to `False` to ignore original folder structure.
  - Example: `KEEP_ORIGINAL_FOLDER_STRUCTURE = False`
- `DESTINATION_FOLDER` (str): Used when `KEEP_ORIGINAL_FOLDER_STRUCTURE` is `False`.
  - Example: `DESTINATION_FOLDER = "specific_directory"`

Note: `SUFFIX_MODE`, `ORIGINAL_SUFFIX`, and `NEW_SUFFIX` are only relevant if `KEEP_ORIGINAL_FOLDER_STRUCTURE` is `True`.

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


## Changelog

### Version 1.2 - 21/01/2024
- Added options to control folder structure in the destination storage.
- Enhanced configuration flexibility for Azure Blob and S3 destinations.
### Version 1.1 - 02/01/2024
- Added Lambda-initiated temporary file deletion to prevent /tmp folder overuse during high-rate concurrent invocations.
### Version 1.0 - 23/11/2023
- Initial release of the tool.

## Lambda IAM Permissions

- Permissions for S3 bucket access (`GetObject`, `PutObject`, `DeleteObject`).
- Permissions for logging to Amazon CloudWatch Logs.
- Additional permissions for external S3 bucket interactions, if applicable.

## Troubleshooting

### Common Issues and Solutions

1. **Logs Not Being Sent to Initial S3 Bucket**
   - **Potential Cause:** Incorrect configuration in Radware's Cloud WAAP.
   - **Solution:** Verify S3 integration settings in Cloud WAAP. Ensure correct configuration of the S3 bucket name, access key, and secret key. Check under Application Configurations / Advanced tab in the Cloud WAAP console and use the Test Configuration feature.

2. **Lambda Function Not Triggering**
   - **Potential Cause:** Misconfiguration of the S3 event trigger.
   - **Solution:** Check the event trigger settings in the Lambda function. Ensure correct setup of bucket name, event type, prefix, and suffix.

3. **Incorrect File Format Conversion**
   - **Potential Cause:** Misconfigured script variables in the Lambda function.
   - **Solution:** Verify and adjust script configuration variables within the Lambda function for correct file format conversion.

4. **Processed Files Not Appearing in Destination Bucket**
   - **Potential Cause:** Incorrect destination bucket settings or permission issues.
   - **Solution:** Confirm DESTINATION and INTERNAL_DESTINATION_BUCKET settings in Lambda function. Ensure Lambda execution role has necessary permissions.

5. **Original File Not Deleted After Processing**
   - **Potential Cause:** DELETE_ORIGINAL variable set to False.
   - **Solution:** Check and set the DELETE_ORIGINAL variable in the script to True if original file deletion is required.

6. **Performance Issues or Timeouts**
   - **Potential Cause:** Large file sizes or insufficient Lambda function timeout/memory settings.
   - **Solution:** Adjust the timeout and memory settings of the Lambda function as needed.
