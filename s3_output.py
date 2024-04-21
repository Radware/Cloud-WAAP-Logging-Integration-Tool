import boto3

class S3Output(OutputDestination):
    def __init__(self, bucket_name):
        self.s3_client = boto3.client('s3')
        self.bucket_name = bucket_name

    def upload(self, file_path, destination_path):
        self.s3_client.upload_file(Filename=file_path, Bucket=self.bucket_name, Key=destination_path)
        print(f"Uploaded {file_path} to S3 bucket {self.bucket_name} at {destination_path}")
