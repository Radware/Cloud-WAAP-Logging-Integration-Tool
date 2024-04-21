from s3_output import S3Output

class ExternalS3Output(S3Output):
    def __init__(self, bucket_name, region_name, access_key, secret_access_key):
        self.s3_client = boto3.client(
            's3',
            region_name=region_name,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_access_key
        )
        self.bucket_name = bucket_name
