import urllib3
import certifi
from output_destination import OutputDestination

class AzureBlobOutput(OutputDestination):
    def __init__(self, account_name, container_name, sas_token):
        self.base_url = f"https://{account_name}.blob.core.windows.net/{container_name}"
        self.sas_token = sas_token
        self.http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=certifi.where())

    def upload(self, file_path, destination_path):
        url = f"{self.base_url}/{destination_path}{self.sas_token}"
        headers = {'x-ms-blob-type': 'BlockBlob'}
        with open(file_path, 'rb') as f:
            response = self.http.request('PUT', url, body=f.read(), headers=headers)
        if response.status != 201:
            raise Exception(f"Failed to upload blob. Status: {response.status}, Reason: {response.data.decode('utf-8')}")
