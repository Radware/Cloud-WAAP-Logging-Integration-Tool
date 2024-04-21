import boto3
import urllib.parse

def parse_s3_event(event):
    """
    Parse the S3 event to get the bucket and key of the uploaded file.
    """
    record = event['Records'][0]
    bucket = record['s3']['bucket']['name']
    key = urllib.parse.unquote_plus(record['s3']['object']['key'], encoding='utf-8')
    return bucket, key

def download_file_from_s3(bucket, key, download_path):
    """
    Download a file from S3 to a specified local path.
    """
    s3_client = boto3.client('s3')
    s3_client.download_file(Bucket=bucket, Key=key, Filename=download_path)
    print(f"Downloaded {key} from bucket {bucket} to {download_path}")

def upload_file_to_s3(file_path, bucket, key):
    """
    Upload a file to an S3 bucket at a specified key.
    """
    s3_client = boto3.client('s3')
    s3_client.upload_file(Filename=file_path, Bucket=bucket, Key=key)
    print(f"Uploaded {file_path} to bucket {bucket} at key {key}")
