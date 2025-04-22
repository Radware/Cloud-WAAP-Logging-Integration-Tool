# Cloud WAAP Logging Integration Tool

## Overview
The Cloud WAAP Logging Integration Tool is specifically designed to work with Radware's Cloud WAAP. Its primary function is to facilitate the handling of logs once they are transferred to an AWS S3 bucket. The tool is pivotal in transforming and efficiently managing these logs, enhancing their compatibility for integration with various services and SIEMs.

This guide provides detailed instructions on utilizing an AWS Lambda function for effective log format transformation and management.

## Prerequisites
- **AWS Account**: An active AWS account with permissions to manage Lambda and S3 services.
- **Lambda Runtime**: Support Lambda Python runtime version 3.8 up to 3.12.
- **Radware Cloud WAAP**: Configuration in place to send logs to an AWS S3 bucket.
- **Permissions**: Proper IAM roles and policies that allow the Lambda function to read from S3 buckets and write to the desired destinations.
- **Lambda Layer**: Required `lambda_layer.zip` containing paramiko library for SFTP support.
- **For SFTP Transfers**:
  - SFTP server access with credentials or SSH keys for secure file transfer.
- **For Azure Blob Storage Transfer**:
  - An Azure Storage Account and access credentials, such as a SAS Token.

## Current Version
Version 2.1.2

## Features
- **Multiple Destination Support**: Internal S3, External S3, Custom S3 (S3-compatible: Synology, MinIO, Dell ECS, etc.), SFTP, Azure Blob.
- **Flexible Output Formatting**: `ndjson`, `json`, `json.gz`.
- **Enhanced Folder Structure Control**: Maintain or flatten folder hierarchy.
- **Suffix Management**: Add/remove suffixes for folder names.
- **Security and Compliance**: Secure log transfer.
- **Automated Post-Processing Cleanup**: Optionally delete original files.
- **Password-Protected ZIP**: Create password-protected ZIP files before upload (with standard ZIP password protection).

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
  - Optionally, creates a password-protected ZIP file.
  - Sends the reformatted file to the chosen destination.
  - Optionally, removes the original file from the S3 bucket.

## Configuration

Set the following in the Lambda function code:

- `DELETE_ORIGINAL` (bool): If `True`, original files are deleted after processing. Default is `True`.
  - Example: `DELETE_ORIGINAL = True`
- `DESTINATION` (str): Determines where the file will be uploaded. Options are `"Internal S3"`, `"External S3"`, `"Custom S3"`, `"SFTP"`, `"Azure"`.
  - Example: `DESTINATION = "Custom S3"`
- `OUTPUT_FORMAT` (str): Format of the transformed file. Options are `"ndjson"`, `"json"`, `"json.gz"` (json.gz is for Azure, Custom S3 and SFTP only).
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

### Password-Protected ZIP Options
- `PASSWORD_PROTECT_ZIP` (bool): Enable password protection using ZIP format.
  - Example: `PASSWORD_PROTECT_ZIP = True`
- `ZIP_PASSWORD_ENV_VAR` (str): Name of the Lambda environment variable containing the ZIP password.
  - Example: `ZIP_PASSWORD_ENV_VAR = "ZIP_PASSWORD"`
- `PROTECTED_ZIP_SUFFIX` (str): Suffix added to password-protected ZIP files.
  - Example: `PROTECTED_ZIP_SUFFIX = ".zip"`

### External & Custom S3 Options

#### General Options (Used by both AWS External and Custom S3)
- `EXTERNAL_ACCESS_KEY_ID` (str): Access key for external AWS S3 or Custom S3 access.
  - Example: `EXTERNAL_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"`
- `EXTERNAL_SECRET_ACCESS_KEY` (str): Secret access key for external AWS S3 or Custom S3 access.
  - Example: `EXTERNAL_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`
- `EXTERNAL_DESTINATION_BUCKET` (str): The name of the external bucket where logs will be uploaded.
  - Example: `EXTERNAL_DESTINATION_BUCKET = "my-external-bucket"`
- `EXTERNAL_PREFIX` (str): Optional prefix for organizing uploaded files.
  - Example: `EXTERNAL_PREFIX = "logs/"`

#### External AWS S3 Specific Options
- `EXTERNAL_BUCKET_REGION` (str): AWS region where the external S3 bucket is located.
  - Example: `EXTERNAL_BUCKET_REGION = "us-east-1"`

#### Custom S3 Specific Options (e.g., Synology, MinIO, Dell ECS)
- `EXTERNAL_ENDPOINT_URL` (str): Endpoint URL for S3-compatible storage.
  - Example: `EXTERNAL_ENDPOINT_URL = "https://storage.example.com"`
- `EXTERNAL_ENDPOINT_SSL_VERIFY` (bool): Whether to verify SSL certificates.
  - Example: `EXTERNAL_ENDPOINT_SSL_VERIFY = True`
- `EXTERNAL_ENDPOINT_SIGNATURE_VERSION` (str): S3 signature version.
  - Example: `EXTERNAL_ENDPOINT_SIGNATURE_VERSION = "s3v4"`

### Azure Destination Options
- `ACCOUNT_NAME` (str): Name of the Azure storage account.
  - Example: `ACCOUNT_NAME = "myazureaccount"`
- `CONTAINER_NAME` (str): Name of the Azure storage container.
  - Example: `CONTAINER_NAME = "mycontainer"`
- `SAS_TOKEN` (str): SAS token for Azure Blob Storage access.
  - Example: `SAS_TOKEN = "?sv=...[token]..."`

### SFTP Destination Options

- `SFTP_SERVER` (str): Hostname or IP address of the SFTP server.
  - Example: `SFTP_SERVER = "sftp.example.com"`
- `SFTP_PORT` (int): Port number used for the SFTP connection. Typically, this is port 22.
  - Example: `SFTP_PORT = 22`
- `SFTP_USERNAME` (str): Username for SFTP authentication.
  - Example: `SFTP_USERNAME = "myusername"`
- `SFTP_PASSWORD` (str): Password for SFTP authentication. Use this if not using SSH key-based authentication. For enhanced security, it is recommended to use SSH keys.
  - Example: `SFTP_PASSWORD = "mypassword"`
- `SFTP_USE_KEY_AUTH` (bool): Set to `True` to enable authentication with an SSH private key, otherwise set to `False` to use password authentication.
  - Example: `SFTP_USE_KEY_AUTH = True`
- `SFTP_PRIVATE_KEY_ENV_VAR` (str): Name of the environment variable that contains the private SSH key. The private key should be in PEM format.
  - Example: `SFTP_PRIVATE_KEY_ENV_VAR = "SFTP_PRIVATE_KEY"`
- `SFTP_TARGET_DIR` (str): Target directory on the SFTP server where files will be uploaded.
  - Example: `SFTP_TARGET_DIR = "/path/to/destination/directory"`

**Note**: When using key-based authentication (`SFTP_USE_KEY_AUTH = True`), the private key must be stored in the Lambda environment variable specified by `SFTP_PRIVATE_KEY_ENV_VAR`.

## Deployment & Setup

1. Download the script and Lambda layer from GitHub.
2. Create a ZIP file with `lambda_function.py` at the root.
3. Create an AWS Lambda function using Python 3.12.
4. Upload the ZIP file to the Lambda function.
5. Add the `lambda_layer.zip` as a Lambda layer:
   - Go to Lambda > Layers > Create layer
   - Upload `lambda_layer.zip`
   - Select compatible runtimes (Python 3.8-3.12)
   - Attach the layer to your Lambda function
6. Set the function's handler to `lambda_function.lambda_handler`.
7. Increase the Lambda function timeout to 5 minutes.
8. Set the Lambda function memory to at least 256 MB.
9. Set up an S3 event trigger for new `.json.gz` file uploads.
10. If using ZIP protection, set the `ZIP_PASSWORD` environment variable.

## Usage

When a `.json.gz` file is uploaded to the S3 bucket, the Lambda function will process it according to the configurations set, transforming and transferring the file to the specified destination.

## Changelog

### Version 2.1.2 - 15/11/2024
- Added password-protected ZIP functionality for secure file transfers
- Renamed "Dell ECS S3" destination to "Custom S3" for broader S3-compatible storage support
- Enhanced error handling and retry mechanisms with proper DLQ support
- Added support for Synology, MinIO, and other S3-compatible storage systems
- Updated configuration structure for better clarity and flexibility
### Version 2.1.1 - 10/11/2024
- Added support for SFTP authentication using SSH private keys, enabling secure file transfers without needing a password.
- Updated `upload_to_sftp` function to conditionally use either password or key-based authentication based on configuration.
### Version 2.1.0 - 11/04/2024
- **Support for json.gz for Custom S3 and SFTP**: Added support to send logs in json.gz format with destination Custom S3 and SFTP.
- **Added support for test txt file**: Added support to send the test txt file using the lambda to help with initial configuration and deployment testing.
### Version 2.0.0 - 10/04/2024
- **Added Support for Custom S3 and SFTP**: Expanded the destination options to include Custom S3 S3-compatible storage and SFTP servers, allowing for a wider range of log transfer destinations.
- **Log Enrichment Features**: Introduced log enrichment capabilities to ensure each log contains an `applicationName` and to add a `logType` to every log. This enhancement improves the quality and usability of the log data for analysis and integration with various services and SIEMs.
- **Paramiko Layer for SFTP Transfers**: Implemented the use of a `paramiko-layer.zip` Lambda layer to facilitate secure SFTP file transfers. This layer is necessary for the function's operation with SFTP destinations and is compatible with Python runtimes 3.8 to 3.12.
### Version 1.3.0 - 01/02/2024
- Enhanced error handeling when reading from AWS event dictionary.
### Version 1.2.0 - 21/01/2024
- Added options to control folder structure in the destination storage.
- Enhanced configuration flexibility for Azure Blob and S3 destinations.
### Version 1.1.0 - 02/01/2024
- Added Lambda-initiated temporary file deletion to prevent /tmp folder overuse during high-rate concurrent invocations.
### Version 1.0.0 - 23/11/2023
- Initial release of the tool.

## Lambda IAM Permissions

- Permissions for S3 bucket access (`GetObject`, `PutObject`, `DeleteObject`).
- Permissions for logging to Amazon CloudWatch Logs.
- Additional permissions for external S3 bucket interactions, if applicable.

## Additional Notes for SFTP Transfers

The Lambda layer (`lambda_layer.zip`) now includes paramiko for SFTP transfers. This layer is required for:
- SFTP file transfers using paramiko

### Adding the Lambda Layer

1. **Download the Lambda Layer**:
   - The `lambda_layer.zip` is available for download from the GitHub release page.
   - Navigate to the [Releases](https://github.com/Radware/Cloud-WAAP-Logging-Integration-Tool/releases) section and download the latest `lambda_layer.zip`.

2. **Upload the Layer to AWS Lambda**:
   - In the AWS Lambda Console, go to the Layers section and click on "Create layer".
   - Upload the downloaded `lambda_layer.zip` file.
   - Specify the compatible runtimes as Python 3.8, 3.9, 3.10, 3.11, and 3.12.

3. **Attach the Layer to Your Lambda Function**:
   - Open your Lambda function configuration.
   - Under "Layers", choose "Add a layer" and select the uploaded layer.
   - Save the changes to apply the layer.

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

7. **ZIP Password Protection Issues**
   - **Potential Cause:** Missing ZIP password environment variable or incorrect configuration
   - **Solution:** Verify the `ZIP_PASSWORD` environment variable is set in Lambda configuration and `PASSWORD_PROTECT_ZIP` is enabled

8. **Custom S3 Connection Issues**
    - **Potential Cause:** Incorrect endpoint URL or authentication details
    - **Solution:** Verify `EXTERNAL_ENDPOINT_URL` and credentials for your S3-compatible storage system
