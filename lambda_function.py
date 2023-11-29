import boto3
import gzip
import json
import urllib.parse
import urllib3
import certifi

s3_client = boto3.client('s3')

# General script options
DELETE_ORIGINAL = True  # Set to False if you don't want to delete the original file
DESTINATION = "Internal S3"  # Options "Internal S3" or "External S3" or "Azure"
OUTPUT_FORMAT = "ndjson"  # Options: "ndjson", "json", "json.gz" (json.gz option is for azure only)

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
ACCOUNT_NAME = ''  # enter the name of the azure storage account
CONTAINER_NAME = ''  # enter the name of the storage account container
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
        first_folder = key.split('/')[0]
        if SUFFIX_MODE == 'remove':
            first_folder = first_folder.replace(f'-{ORIGINAL_SUFFIX}', '')
        elif SUFFIX_MODE == 'add':
            first_folder = f'{first_folder}-{NEW_SUFFIX}'
    
        # Construct the output key by replacing the original first folder with the modified one
        output_key = key.replace(key.split('/')[0], first_folder).replace('.json.gz', output_extension)

        if not output_key.endswith(output_extension):
            output_key = output_key.replace('.json.gz', '') + output_extension
    
        print(f"Uploading transformed content to S3 bucket: {bucket} and key: {output_key}")
    
        # Determine the destination bucket
        destination_bucket = INTERNAL_DESTINATION_BUCKET if DESTINATION == 'Internal S3' else EXTERNAL_DESTINATION_BUCKET
        if not destination_bucket:  # If INTERNAL_DESTINATION_BUCKET is None, use the source bucket
            destination_bucket = bucket
    
        # Ensure destination_key is set properly
        destination_key = f"{EXTERNAL_PREFIX}{output_key}" if DESTINATION == 'External S3' else output_key
    
        # Ensure output_path is not None
        if not output_path:
            print("Error: Output path is None.")
            return {
                'statusCode': 500,
                'body': json.dumps('Output path is None.')
            }
    
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
        # Split the key to get individual parts
        path_parts = key.split('/')
    
        # Modify the first folder based on SUFFIX_MODE
        first_folder = path_parts[0]
        if SUFFIX_MODE == 'remove':
            first_folder = first_folder.replace(f'-{ORIGINAL_SUFFIX}', '')
        elif SUFFIX_MODE == 'add':
            first_folder = f'{first_folder}-{NEW_SUFFIX}'
    
        # Reconstruct the directory structure with the modified first folder
        modified_directory_structure = '/'.join([first_folder] + path_parts[1:-1])
    
        # Get file name without '.json.gz' and add the correct output format
        file_name = path_parts[-1].rsplit('.json.gz', 1)[0] + f".{OUTPUT_FORMAT}"
    
        # Construct BLOB_NAME with the correct folder structure and file extension
        BLOB_NAME = f"{modified_directory_structure}/{file_name}"
    
        # Azure Blob Storage URL
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

    print("Lambda execution completed.")

    return {
        'statusCode': 200,
        'body': json.dumps('File processed successfully!')
    }
