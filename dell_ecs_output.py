from s3_output import S3Output

class DellECSOutput(S3Output):
    def __init__(self, bucket_name, endpoint_url, access_key, secret_access_key, verify_ssl, signature_version):
        self.s3_client = boto3.client(
            's3',
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_access_key,
            config=boto3.session.Config(signature_version=signature_version),
            verify=verify_ssl
        )
        self.bucket_name = bucket_name
