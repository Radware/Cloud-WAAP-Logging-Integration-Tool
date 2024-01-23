import boto3
import gzip
import json
import urllib.parse
import urllib3
import certifi
import os
import shutil

s3_client = boto3.client('s3')

# Radware Cloud WAAP Logging Intergration Tool
# Labmda function - version 1.2 


# General script options
DELETE_ORIGINAL = True  # Delete the original file after processing
DESTINATION = "Internal S3"  # Destination type: "Internal S3", "External S3", or "Azure"
OUTPUT_FORMAT = "ndjson"  # Output file format: "ndjson", "json", "json.gz" (json.gz for Azure only)
KEEP_ORIGINAL_FOLDER_STRUCTURE = True  # Control whether to keep the original folder structure
DESTINATION_FOLDER = ""  # Destination folder when not retaining the original structure

# Note: S3 options regarding suffix/prefix are relevant only if original folder structure is retained
# S3 General Destination Options
SUFFIX_MODE = "remove"  # Suffix modification mode: "add" or "remove"
ORIGINAL_SUFFIX = "unprocessed"  # Suffix in the original folder name to be removed or replaced
NEW_SUFFIX = ""  # Suffix to add in the new folder name, if SUFFIX_MODE is 'add'

# S3 Internal Destination Options
INTERNAL_DESTINATION_BUCKET = None  # Default to the source bucket if None

# S3 External Destination Options
EXTERNAL_AWS_ACCESS_KEY_ID = ''
EXTERNAL_AWS_SECRET_ACCESS_KEY = ''
EXTERNAL_BUCKET_REGION = ''
EXTERNAL_DESTINATION_BUCKET = ''
EXTERNAL_PREFIX = ''  # Prefix for external S3 destination (end with a slash if specified)

# Azure Destination Options
ACCOUNT_NAME = ''  # Azure storage account name
CONTAINER_NAME = ''  # Azure storage account container name
SAS_TOKEN = ''  # SAS token for Azure access

if DESTINATION == "External S3":
    external_s3_client = boto3.client(
        's3',
        aws_access_key_id=EXTERNAL_AWS_ACCESS_KEY_ID,
        aws_secret_access_key=EXTERNAL_AWS_SECRET_ACCESS_KEY,
        region_name=EXTERNAL_BUCKET_REGION
    )


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

    
    output_extension = f".{OUTPUT_FORMAT}"
    # Extract bucket and file key from the event
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'])

    print(f"Bucket: {bucket}")
    print(f"Key: {key}")

    # Download the file to a temporary path
    download_path = '/tmp/{}'.format(key.split('/')[-1])
    try:
        s3_client.download_file(bucket, key, download_path)
    except Exception as e:
        print(f"Error downloading file from S3: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps('Failed to download file from S3.')
        }

    output_path = download_path

    print("File contents read successfully.")

    if OUTPUT_FORMAT != "json.gz":
        try:
            with gzip.open(download_path, 'rt') as f:
                data = json.load(f)

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
        destination_bucket = INTERNAL_DESTINATION_BUCKET if DESTINATION == 'Internal S3' else EXTERNAL_DESTINATION_BUCKET
        if not destination_bucket:  # If INTERNAL_DESTINATION_BUCKET is None, use the source bucket
            destination_bucket = bucket

        # Ensure destination_key is set properly
        destination_key = f"{EXTERNAL_PREFIX}{output_key}" if DESTINATION == 'External S3' else output_key

        # Select the appropriate S3 client
        s3_upload_client = s3_client if DESTINATION == 'Internal S3' else external_s3_client

        try:
            s3_upload_client.upload_file(output_path, destination_bucket, destination_key)
            print("Upload complete")
        except Exception as e:
            print(f"Error uploading to {DESTINATION}: {e}")
            return {
                'statusCode': 500,
                'body': json.dumps('Failed to process file!')
            }
    
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
            raise Exception(f"Failed to upload blob. Status: {response.status}, Reason: {response.data.decode('utf-8')}")


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
