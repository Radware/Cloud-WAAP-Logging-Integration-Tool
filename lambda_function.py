import boto3
from botocore.client import Config
import gzip
import json
import urllib.parse
import urllib3
import certifi
import os
import shutil
from cloudwaap_log_utils import CloudWAAPProcessor

s3_client = boto3.client('s3')

# Radware Cloud WAAP Logging Integration Tool
# Lambda function - Version 2.2.0b

# ======================================================================
# General Script Options
# ======================================================================
DELETE_ORIGINAL = True  # Whether to delete the original file after processing.
DESTINATION = "Internal S3"  # Destination type: "Internal S3", "External S3", "Dell ECS S3", "SFTP" or "Azure".
OUTPUT_FORMAT = "ndjson"  # Output file format: "ndjson", "json", "json.gz" ("json.gz" is for Azure, Dell ECS S3 and SFTP only).
KEEP_ORIGINAL_FOLDER_STRUCTURE = True  # Whether to retain the original folder structure in the destination.
DESTINATION_FOLDER = ""  # Destination folder when not retaining the original structure (empty for root).
ENRICH_LOGS = False  # Enrich logs with additional metadata (logType, applicationName, tenantName) Does not work when output format is set to json.gz.

# ======================================================================
# S3 Destination Options
# ======================================================================
SUFFIX_MODE = "remove"  # Suffix modification mode: "add" or "remove".
ORIGINAL_SUFFIX = "unprocessed"  # Suffix to remove if SUFFIX_MODE is "remove".
NEW_SUFFIX = ""  # New suffix to add if SUFFIX_MODE is "add".

# --------------------
# Internal S3 Options
# --------------------
INTERNAL_DESTINATION_BUCKET = None  # Bucket for internal S3 destination (defaults to source bucket if None).

# ======================================================================
# External S3 Options
# ======================================================================

# ---------------------------------------
# External S3 General Options
# ---------------------------------------
EXTERNAL_ACCESS_KEY_ID = ''
EXTERNAL_SECRET_ACCESS_KEY = ''
EXTERNAL_DESTINATION_BUCKET = ''
EXTERNAL_PREFIX = ''  # Prefix for external S3 destination (end with "/" if specified).

# ---------------------------------------
# External AWS S3 Options
# ---------------------------------------
EXTERNAL_BUCKET_REGION = ''  # AWS region for the external S3 bucket.

# ---------------------------------------
# External Dell ECS S3 Options
# ---------------------------------------
EXTERNAL_ENDPOINT_URL = ''  # Endpoint URL for Dell ECS S3-compatible storage.
EXTERNAL_ENDPOINT_SSL_VERIFY = False  # Whether to verify SSL for Dell ECS S3 access.
EXTERNAL_ENDPOINT_SIGNATURE_VERSION = "s3" # Choose between regular "s3", "s3v2" and "s3v4"

# ======================================================================
# Azure Destination Options
# ======================================================================
ACCOUNT_NAME = ''  # Azure storage account name.
CONTAINER_NAME = ''  # Container name in the Azure storage account.
SAS_TOKEN = ''  # SAS token for Azure container access.

# ======================================================================
# SFTP Destination Options
# ======================================================================
SFTP_SERVER = ''  # Hostname or IP of the SFTP server.
SFTP_PORT = 22  # Port number for the SFTP server.
SFTP_USERNAME = ''  # Username for SFTP authentication.
SFTP_PASSWORD = ''  # Password for SFTP authentication (consider SSH key for security).
SFTP_TARGET_DIR = ''  # Target directory on the SFTP server for file uploads.

# ======================================================================
# Log Filtering Options
# ======================================================================
ENABLE_FILTERING = True
DISABLE_PER_APPLICATION = []
OVERRIDE_APPLICATION_FILTER_CONFIG = {
    # "example":{
    #     "Access":{
    #         "enable": True,
    #         "action": []
    #     },
    #     "WAF":{
    #         "enable": True,
    #         "action": [],
    #         "violationType": []
    #     },
    #     "Bot":{
    #         "enable": True,
    #         "action": []
    #     },
    #     "DDoS":{
    #         "enable": True
    #     },
    #     "WebDDoS":{
    #         "enable": True
    #     },
    #     "CSP":{
    #         "enable": True
    #     }
    # }
}
LOG_FILTERING = {
    "Access": {
        "enable": True,
        "action": []
    },
    "WAF": {
        "enable": True,
        "action": [],
        "violationType": []
    },
    "Bot": {
        "enable": True,
        "action": []
    },
    "DDoS": {
        "enable": True
    },
    "WebDDoS": {
        "enable": True
    },
    "CSP": {
        "enable": True
    }
}


# Conditional import for paramiko
if 'SFTP' in DESTINATION:
    try:
        import paramiko
    except ImportError as e:
        print("paramiko module is not available. SFTP functionality will not work.")

if DESTINATION == "External S3":
    external_s3_client = boto3.client(
        's3',
        aws_access_key_id=EXTERNAL_ACCESS_KEY_ID,
        aws_secret_access_key=EXTERNAL_SECRET_ACCESS_KEY,
        region_name=EXTERNAL_BUCKET_REGION
    )

elif DESTINATION == "Dell ECS S3":
    # Set up the ECS S3 client
    ecs_s3_client = boto3.client(
        's3',
        endpoint_url=EXTERNAL_ENDPOINT_URL,
        aws_access_key_id=EXTERNAL_ACCESS_KEY_ID,
        aws_secret_access_key=EXTERNAL_SECRET_ACCESS_KEY,
        verify=EXTERNAL_ENDPOINT_SSL_VERIFY,
        config=Config(signature_version=EXTERNAL_ENDPOINT_SIGNATURE_VERSION),  # ECS uses S3 signature version
    )


def filter_log_entry(log, application_name, log_type):
    """
    Determine if a log entry should be kept based on filtering configurations.
    Logs with specified field values will be omitted.

    Parameters:
        log (dict): The log entry as a dictionary.
        application_name (str): The application name to which the log belongs.
        log_type (str): The type of the log (e.g., Access, WAF, DDoS).

    Returns:
        bool: True if the log should be kept, False if it should be filtered out.
    """
    # Retrieve the applicable configuration, checking for overrides first
    app_config = OVERRIDE_APPLICATION_FILTER_CONFIG.get(application_name, {})
    log_config = app_config.get(log_type, LOG_FILTERING.get(log_type, {}))

    # If filtering is disabled for this log type, keep the log
    if not log_config.get("enable", True):
        return False

    # Check specific fields like 'action' and 'violationType' if they are specified
    # Logs with these values in the fields are omitted.
    if "action" in log_config and log_config["action"] and log.get("action") in log_config["action"]:
        return False  # Filter out this log because its action matches one of the specified actions to omit

    if "violationType" in log_config and log_config["violationType"] and log.get("violationType") in log_config["violationType"]:
        return False  # Filter out this log because its violationType matches one of the specified types to omit

    # Log does not match the omitted conditions and passes all filters
    return True



def enrich_and_filter_logs(logs, log_type, application_name, tenant_name, enable_enrichment, enable_filtering):
    """
    Enrich and/or filter each log entry based on specified criteria and configuration flags.

    Parameters:
        logs (list): List of log dictionaries.
        log_type (str): The type of the log.
        application_name (str): Name of the application.
        tenant_name (str): Name of the tenant.
        enable_enrichment (bool): Flag to indicate whether enrichment is enabled.
        enable_filtering (bool): Flag to indicate whether filtering is enabled.

    Returns:
        list: The list of processed log entries, enriched and/or filtered as configured.
    """
    processed_logs = []
    for log in logs:
        # Filter log entries if filtering is enabled
        if enable_filtering and not filter_log_entry(log, application_name, log_type):
            continue

        # Apply enrichment if enabled
        if enable_enrichment:
            log['logType'] = log_type
            if log_type == 'WebDDoS':
                if 'applicationName' not in log:
                    log['applicationName'] = application_name
            if log_type != "Access" and 'tenantName' not in log:
                log['tenantName'] = tenant_name
        processed_logs.append(log)
    return processed_logs


def should_process_log_type(application_name, log_type):
    """ Determine whether a log file should be processed based on its log type and application-specific rules. """
    app_config = OVERRIDE_APPLICATION_FILTER_CONFIG.get(application_name, LOG_FILTERING)
    log_config = app_config.get(log_type, {})
    return log_config.get("enable", True)


def clean_up_and_exit(bucket, key, path):
    """ Clean up temporary files and optionally delete the original S3 file. """
    if DELETE_ORIGINAL:
        s3_client.delete_object(Bucket=bucket, Key=key)
    os.remove(path)
    print(f"Cleaned up local and S3 storage for {key}.")


def upload_to_sftp(file_path, target_dir, keep_original_folder_structure=True):
    transport = paramiko.Transport((SFTP_SERVER, SFTP_PORT))
    transport.connect(username=SFTP_USERNAME, password=SFTP_PASSWORD)  # Consider key-based authentication
    sftp = paramiko.SFTPClient.from_transport(transport)

    if keep_original_folder_structure:
        # Ensure target directory exists
        try:
            sftp.chdir(target_dir)  # Test if target_dir exists
        except IOError:
            # Create directory structure if it does not exist
            current_dir = ''
            for dir in target_dir.split('/'):
                current_dir = os.path.join(current_dir, dir)
                try:
                    sftp.chdir(current_dir)  # Test if this part of the dir exists
                except IOError:
                    sftp.mkdir(current_dir)  # Create if it does not exist

    # Once the directory is confirmed to exist or if not keeping the original structure, upload the file
    target_path = os.path.join(target_dir,
                               os.path.basename(file_path)) if keep_original_folder_structure else target_dir
    sftp.put(file_path, target_path)

    sftp.close()
    transport.close()
    print(f"File {file_path} uploaded to SFTP at {target_path}.")


def lambda_handler(event, context):
    print("Lambda invoked.")

    # Check if /tmp has any files or directories
    tmp_dir = '/tmp'
    if os.listdir(tmp_dir):  # This checks if the list is non-empty
        print("Data found in /tmp, proceeding to delete.")
        # Iterate through each item in /tmp and delete
        for filename in os.listdir(tmp_dir):
            file_path = os.path.join(tmp_dir, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print(f'Failed to delete {file_path}. Reason: {e}')
    else:
        print("No data in /tmp. No deletion needed.")

    try:
        output_extension = f".{OUTPUT_FORMAT}"
        # Extract bucket and file key from the event
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'])

        print(f"Bucket: {bucket}")
        print(f"Key: {key}")

        file_extension = os.path.splitext(key)[1].lower()

        # Download the file to a temporary path
        download_path = '/tmp/{}'.format(key.split('/')[-1])
        s3_client.download_file(bucket, key, download_path)
    except KeyError as e:
        print(f"Error: Event structure not as expected, missing key: {e}")
        # Output the event for debugging purposes in a readable way
        print("Event data:", json.dumps(event, indent=4))
        return {
            'statusCode': 400,
            'body': json.dumps('Event structure not as expected, execution stopped.')
        }
    except Exception as e:
        print(f"Error processing file: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps('Failed to download file from S3.')
        }

    output_path = download_path

    print("File contents read successfully.")

    if OUTPUT_FORMAT != "json.gz" and file_extension != ".txt":
        try:
            with gzip.open(download_path, 'rt') as f:
                data = json.load(f)

            if ENRICH_LOGS or ENABLE_FILTERING:
                log_type = CloudWAAPProcessor.identify_log_type(key)

                if log_type == "Access":
                    tenant_name, application_name = CloudWAAPProcessor.parse_names_from_log_data(data)
                else:
                    application_name = CloudWAAPProcessor.parse_application_name(key)
                    tenant_name = CloudWAAPProcessor.parse_tenant_name(key)

                # Filtering based on log type and application name
                if application_name not in DISABLE_PER_APPLICATION and not should_process_log_type(application_name,
                                                                                                   log_type):
                    print(
                        f"Skipping file processing based on log type '{log_type}' for application '{application_name}'.")
                    clean_up_and_exit(bucket, key, download_path)
                    return {
                        'statusCode': 200,
                        'body': json.dumps('File skipped based on filtering criteria.')
                    }

                # Call the function with appropriate flags
                processed_data = enrich_and_filter_logs(
                    data,
                    log_type,
                    application_name,
                    tenant_name,
                    enable_enrichment=ENRICH_LOGS,
                    enable_filtering=ENABLE_FILTERING
                )
            else:
                processed_data = data

            # Continue processing with transformed_content
            if OUTPUT_FORMAT == "ndjson":
                transformed_content = '\n'.join(json.dumps(item) for item in processed_data)
            elif OUTPUT_FORMAT == "json":
                transformed_content = json.dumps(processed_data)

            # Write to a new file
            output_path = '/tmp/{}'.format(key.split('/')[-1])
            with open(output_path, 'w') as f:
                f.write(transformed_content)

        except (gzip.BadGzipFile, json.JSONDecodeError) as e:
            print(f"Error during file transformation: {e}")
            return {
                'statusCode': 500,
                'body': json.dumps('Failed during file transformation.')
            }
    elif OUTPUT_FORMAT == "json.gz" or file_extension == ".txt" and DESTINATION in ['External S3', 'Dell ECS S3',
                                                                                    'SFTP']:
        output_path = download_path  # Directly use the downloaded file for upload
    print(f"Transformation to {OUTPUT_FORMAT} done.")

    if DESTINATION.endswith("S3"):
        if KEEP_ORIGINAL_FOLDER_STRUCTURE:
            first_folder = key.split('/')[0]
            if SUFFIX_MODE == 'remove':
                first_folder = first_folder.replace(f'-{ORIGINAL_SUFFIX}', '')
            elif SUFFIX_MODE == 'add':
                first_folder = f'{first_folder}-{NEW_SUFFIX}'
            output_key = key.replace(key.split('/')[0], first_folder).replace('.json.gz', output_extension)
        else:
            # Use the DESTINATION_FOLDER for the output key
            file_name = key.split('/')[-1]
            output_key = f"{DESTINATION_FOLDER}/{file_name}".replace('.json.gz', output_extension)

        if not output_key.endswith(output_extension):
            output_key += output_extension

        print(f"Uploading transformed content to S3 bucket: {bucket} and key: {output_key}")

        # Determine the destination bucket
        if DESTINATION == 'Internal S3':
            destination_bucket = INTERNAL_DESTINATION_BUCKET or bucket
            destination_key = output_key
            s3_upload_client = s3_client
        elif DESTINATION == 'External S3':
            destination_bucket = EXTERNAL_DESTINATION_BUCKET
            destination_key = f"{EXTERNAL_PREFIX}{output_key}"
            s3_upload_client = external_s3_client
        if DESTINATION == 'Dell ECS S3':
            destination_bucket = EXTERNAL_DESTINATION_BUCKET
            # Construct the initial destination_key
            if KEEP_ORIGINAL_FOLDER_STRUCTURE:
                destination_key = f"{EXTERNAL_PREFIX}{output_key}"
            else:
                # If not keeping the original folder structure, use only the filename with the external prefix
                filename = key.split('/')[-1]
                destination_key = f"{EXTERNAL_PREFIX}{filename}".replace('.json.gz',
                                                                         output_extension) if OUTPUT_FORMAT != "json.gz" else f"{EXTERNAL_PREFIX}{filename}"

            # Check if the destination_key starts with a '/', remove it if true
            if destination_key.startswith('/'):
                destination_key = destination_key[1:]

            s3_upload_client = ecs_s3_client

        try:
            s3_upload_client.upload_file(output_path, destination_bucket, destination_key)
            print("Upload complete")
        except Exception as e:
            print(f"Error uploading to {DESTINATION}: {e}")
            return {
                'statusCode': 500,
                'body': json.dumps('Failed to process file!')
            }

    if DESTINATION == "SFTP":

        # For txt files, use the download path directly without renaming
        if file_extension == ".txt":
            output_path = download_path
        else:
            # For other file types, continue with the existing logic
            old_path = output_path
            output_path = output_path.replace('.json.gz',
                                              output_extension) if OUTPUT_FORMAT != "json.gz" else output_path
            download_path = download_path.replace('.json.gz',
                                                  output_extension) if OUTPUT_FORMAT != "json.gz" else download_path
            os.rename(old_path, output_path)

        # Determine the target directory based on whether to keep the original folder structure
        full_sftp_target_dir = SFTP_TARGET_DIR
        if KEEP_ORIGINAL_FOLDER_STRUCTURE:
            original_path_dirs = '/'.join(key.split('/')[:-1])  # Exclude the filename
            full_sftp_target_dir = os.path.join(SFTP_TARGET_DIR, original_path_dirs)

        # Proceed to upload the file to the specified SFTP directory
        upload_to_sftp(output_path, full_sftp_target_dir, KEEP_ORIGINAL_FOLDER_STRUCTURE)



    elif DESTINATION == 'Azure':
        if KEEP_ORIGINAL_FOLDER_STRUCTURE:
            path_parts = key.split('/')
            first_folder = path_parts[0]
            if SUFFIX_MODE == 'remove':
                first_folder = first_folder.replace(f'-{ORIGINAL_SUFFIX}', '')
            elif SUFFIX_MODE == 'add':
                first_folder = f'{first_folder}-{NEW_SUFFIX}'
            modified_directory_structure = '/'.join([first_folder] + path_parts[1:-1])
            file_name = path_parts[-1].rsplit('.json.gz', 1)[0] + f".{OUTPUT_FORMAT}"
            BLOB_NAME = f"{modified_directory_structure}/{file_name}"
        elif (file_extension == ".txt"):
            file_name = key.split('/')[-1]
            BLOB_NAME = f"{DESTINATION_FOLDER}/{file_name}"
        else:
            # Use the DESTINATION_FOLDER for the BLOB name
            file_name = key.split('/')[-1].rsplit('.json.gz', 1)[0] + f".{OUTPUT_FORMAT}"
            BLOB_NAME = f"{DESTINATION_FOLDER}/{file_name}"

        url = f"https://{ACCOUNT_NAME}.blob.core.windows.net/{CONTAINER_NAME}/{BLOB_NAME}{SAS_TOKEN}"

        # Set headers based on the output format
        headers = {
            'x-ms-blob-type': 'BlockBlob',
            'Content-Type': 'application/x-ndjson' if OUTPUT_FORMAT == "ndjson" else 'application/json; charset=utf-8'
        }

        # Read file content for upload
        with open(output_path, 'rb') as f:
            upload_content = f.read()

        # Initialize HTTP client and upload to Azure Blob Storage
        http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=certifi.where())
        response = http.request('PUT', url, body=upload_content, headers=headers)

        if response.status != 201:
            raise Exception(
                f"Failed to upload blob. Status: {response.status}, Reason: {response.data.decode('utf-8')}")

    # Optionally delete the original file
    if DELETE_ORIGINAL:
        s3_client.delete_object(Bucket=bucket, Key=key)

    # Delete the downloaded file
    try:
        os.remove(download_path)
        print(f"Downloaded file {download_path} deleted.")
    except Exception as e:
        print(f"Warning: Could not delete the downloaded file: {e}")

    print("Lambda execution completed.")

    return {
        'statusCode': 200,
        'body': json.dumps('File processed successfully!')
    }