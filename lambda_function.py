import boto3
from botocore.client import Config
import gzip
import json
import urllib.parse
import urllib3
import certifi
import os
import shutil
import io
import re
from cloudwaap_log_utils import CloudWAAPProcessor

s3_client = boto3.client('s3')

# Radware Cloud WAAP Logging Integration Tool
# Lambda function - Version 2.1.1

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
SFTP_USE_KEY_AUTH = False  # Set to True to enable private key authentication.
SFTP_PRIVATE_KEY_ENV_VAR = 'SFTP_PRIVATE_KEY'  # Environment variable name holding the private key.
SFTP_TARGET_DIR = ''  # Target directory on the SFTP server for file uploads.

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


def enrich_log_data(logs, log_type, application_name, tenant_name):
    """
    Enrich each log entry with tenantName, logType, and applicationName.

    :param logs: List of log dictionaries.
    :param log_type: The type of the log.
    :param application_name: Name of the application.
    :param tenant_name: Name of the tenant.
    :return: The enriched log list.
    """
    for log in logs:
        log['logType'] = log_type
        if log_type == 'WebDDoS':
            if 'applicationName' not in log:
                log['applicationName'] = application_name
        if log_type != "Access" and 'tenantName' not in log:
            log['tenantName'] = tenant_name
    return logs


def load_private_key():
    # Retrieve the key from the environment variable
    private_key_data = os.getenv(SFTP_PRIVATE_KEY_ENV_VAR)

    if private_key_data:
        # Remove any leading/trailing whitespace from the environment variable
        private_key_data = private_key_data.strip()

        # Check for and remove any existing headers/footers to avoid duplication
        private_key_data = re.sub(r"-----BEGIN RSA PRIVATE KEY-----", "", private_key_data)
        private_key_data = re.sub(r"-----END RSA PRIVATE KEY-----", "", private_key_data)

        # Replace any escaped newline sequences (`\\n`) with actual newlines
        private_key_data = private_key_data.replace("\\n", "\n")

        # Remove any spaces and newlines from the key body to clean it up
        private_key_data = private_key_data.replace(" ", "").replace("\n", "")

        # Rebuild the key with 64-character line breaks, then add the headers and footers
        header = "-----BEGIN RSA PRIVATE KEY-----"
        footer = "-----END RSA PRIVATE KEY-----"
        key_body = "\n".join([private_key_data[i:i + 64] for i in range(0, len(private_key_data), 64)])

        # Construct the final formatted key
        formatted_key = f"{header}\n{key_body}\n{footer}"

        return io.StringIO(formatted_key)
    else:
        raise ValueError(f"Private key data not found in environment variable '{SFTP_PRIVATE_KEY_ENV_VAR}'")


def upload_to_sftp(file_path, target_dir, keep_original_folder_structure=True):
    transport = paramiko.Transport((SFTP_SERVER, SFTP_PORT))

    # Use key-based or password-based authentication based on configuration
    if SFTP_USE_KEY_AUTH:
        try:
            private_key_stream = load_private_key()
            private_key = paramiko.RSAKey.from_private_key(private_key_stream)
            transport.connect(username=SFTP_USERNAME, pkey=private_key)
        except paramiko.SSHException as e:
            print("Failed to load private key:", e)
            raise
    else:
        transport.connect(username=SFTP_USERNAME, password=SFTP_PASSWORD)

    # Set up the SFTP client
    sftp = paramiko.SFTPClient.from_transport(transport)

    if keep_original_folder_structure:
        # Ensure target directory exists
        try:
            sftp.chdir(target_dir)  # Test if target_dir exists
        except IOError:
            # Create directory structure if it does not exist
            current_dir = '/'
            for dir in target_dir.split('/'):
                if dir:  # Skip any empty strings resulting from split
                    current_dir = os.path.join(current_dir, dir)
                    try:
                        sftp.chdir(current_dir)  # Test if this part of the dir exists
                    except IOError:
                        sftp.mkdir(current_dir)  # Create if it does not exist

    # Once the directory is confirmed to exist or if not keeping the original structure, upload the file
    target_path = os.path.join(target_dir,
                               os.path.basename(file_path)) if keep_original_folder_structure else target_dir
    sftp.put(file_path, target_path)

    # Close the SFTP client and transport connection
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

            if ENRICH_LOGS:
                log_type = CloudWAAPProcessor.identify_log_type(key)
                application_name = CloudWAAPProcessor.parse_application_name(key)
                tenant_name = CloudWAAPProcessor.parse_tenant_name(key)

                # Enrich the log data
                data = enrich_log_data(data, log_type, application_name, tenant_name)

            if OUTPUT_FORMAT == "ndjson":
                transformed_content = '\n'.join(json.dumps(item) for item in data)
            elif OUTPUT_FORMAT == "json":  # Assuming "json"
                transformed_content = json.dumps(data)

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
