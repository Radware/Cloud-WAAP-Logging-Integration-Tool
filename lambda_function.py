import boto3
import gzip
import json
import urllib.parse
import urllib3
import certifi

s3_client = boto3.client('s3')

# General script options
DELETE_ORIGINAL = True  # Set to False if you don't want to delete the original file
DESTINATION = "Internal S3" # Options "Internal S3" or "External S3" or "Azure"
OUTPUT_FORMAT = "json"  # Options: "ndjson", "json", "json.gz" (json.gz option is for azure only)

# S3 General Destination Options
SUFFIX_MODE = "remove"  # Modes: "add" or "remove"

ORIGINAL_SUFFIX = "unprocessed"  # The suffix in the original folder name (E.g. Cloud WAF sends original files to 'logs-unprocessed'; reformatted logs are then moved to 'logs' prefix).
NEW_SUFFIX = ""  # The suffix to add in the new folder name (E.g. Cloud WAF sends original files to 'logs'; reformatted logs are then moved to 'logs-ndjson' prefix).

# S3 Internal Destination Options

INTERNAL_DESTINATION_BUCKET = None  # If None, it'll default to the source bucket

# S3 External Destination Options

EXTERNAL_AWS_ACCESS_KEY_ID = ''
EXTERNAL_AWS_SECRET_ACCESS_KEY = ''
EXTERNAL_BUCKET_REGION = ''
EXTERNAL_DESTINATION_BUCKET = ''
EXTERNAL_PREFIX = ''  # End with a slash if specified, otherwise, keep it empty

# Azure Destination Options
ACCOUNT_NAME = '' # enter the name of the azure storage account
CONTAINER_NAME= '' # enter the name of the storage account container
SAS_TOKEN = ''  # SAS token details

if DESTINATION == "External S3":
    external_s3_client = boto3.client(
        's3',
        aws_access_key_id=EXTERNAL_AWS_ACCESS_KEY_ID,
        aws_secret_access_key=EXTERNAL_AWS_SECRET_ACCESS_KEY,
        region_name=EXTERNAL_BUCKET_REGION
    )

def lambda_handler(event, context):
    print("Lambda invoked.")
    output_extension = f".{OUTPUT_FORMAT}"
    # Extract bucket and file key from the event
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'])

    print(f"Bucket: {bucket}")
    print(f"Key: {key}")

    # Get the file from S3
    s3_response = s3_client.get_object(Bucket=bucket, Key=key)
    file_content = s3_response['Body'].read()

    print("File contents read successfully.")

    if OUTPUT_FORMAT == "ndjson":
        # Transform JSON.gz to NDJSON
        data = json.loads(gzip.decompress(file_content).decode('utf-8'))
        ndjson_content = '\n'.join(json.dumps(item) for item in data)
        file_content = ndjson_content.encode('utf-8')  # Convert back to bytes for upload

    elif OUTPUT_FORMAT == "json":
        # Decompress the JSON.gz to JSON
        file_content = gzip.decompress(file_content)

    print(f"Transformation to {OUTPUT_FORMAT} done.")

    if DESTINATION.endswith("S3"):
        # Determine the output path
        first_folder = key.split('/')[0]
        if SUFFIX_MODE == 'remove':
            first_folder = first_folder.replace(f'-{ORIGINAL_SUFFIX}', '')
        elif SUFFIX_MODE == 'add':
            first_folder = f'{first_folder}-{NEW_SUFFIX}'

        # Modify the output path logic
        output_key = key.replace(key.split('/')[0], first_folder).replace('.json.gz', output_extension)
        output_path = f'/tmp/{output_key.split("/")[-1]}'
        print(f"Writing transformed content to: {output_path}")

        with open(output_path, 'w') as f:
            f.write(file_content)

        # Upload the transformed content to the different folder in the same AWS S3 bucket
        print(f"Uploading transformed content to S3 bucket: {bucket} and key: {output_key}")
        s3_client.upload_file(output_path, bucket, output_key)
        if DESTINATION == 'Internal S3':
            if INTERNAL_DESTINATION_BUCKET:
                # Upload the transformed content to different AWS S3 bucket in the same account
                destination_bucket = INTERNAL_DESTINATION_BUCKET
            else:
                destination_bucket = bucket
            try:
                s3_client.upload_file(output_path, destination_bucket, output_key)
            except Exception as e:
                print(f"Error uploading to internal S3: {e}")
                return {
                    'statusCode': 500,
                    'body': json.dumps('Failed to process file!')
                }
         # Upload the transformed content to External AWS S3 bucket
        elif DESTINATION == 'External S3':
            if not 'external_s3_client' in globals():
                print("Error: External S3 client not initialized.")
                return {
                    'statusCode': 500,
                    'body': json.dumps('Failed to process file!')
                }

            destination_bucket = EXTERNAL_DESTINATION_BUCKET
            destination_key = f"{EXTERNAL_PREFIX}{output_key}"

            try:
                external_s3_client.upload_file(output_path, destination_bucket, destination_key)
                print("upload complete")
            except Exception as e:
                print(f"Error uploading to external S3: {e}")
                return {
                    'statusCode': 500,
                    'body': json.dumps('Failed to process file!')
                }
    # Upload the content to an Azure Storage blob 
    elif DESTINATION == 'Azure':
        base_blob_name = key.rsplit('.json.gz', 1)[0]  # Remove .json.gz extension
        BLOB_NAME = f"{base_blob_name}.{OUTPUT_FORMAT}"
        # Use urllib3 with SAS token
        url = f"https://{ACCOUNT_NAME}.blob.core.windows.net/{CONTAINER_NAME}/{BLOB_NAME}{SAS_TOKEN}"

        # Headers for the request
        headers = {
            'x-ms-blob-type': 'BlockBlob',
            'Content-Type': 'application/json; charset=utf-8',
        }
        if format == "ndjson":
            headers['Content-Type'] = 'application/x-ndjson'


        # Initialize the HTTP client
        http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=certifi.where())

        # Upload to Azure Blob Storage using urllib3
        response = http.request('PUT', url, body=file_content, headers=headers)

        if response.status != 201:  # 201 is the expected status code for a successful blob creation
            raise Exception(
                f"Failed to upload blob. Status: {response.status}, Reason: {response.data.decode('utf-8')}")
    # Optionally delete the original file
    if DELETE_ORIGINAL:
        s3_client.delete_object(Bucket=bucket, Key=key)

    print("Lambda execution completed.")

    return {
        'statusCode': 200,
        'body': json.dumps('File processed successfully!')
    }
