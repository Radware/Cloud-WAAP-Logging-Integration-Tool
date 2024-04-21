import paramiko
from output_destination import OutputDestination

class SFTPOutput(OutputDestination):
    def __init__(self, hostname, port, username, password):
        self.transport = paramiko.Transport((hostname, port))
        self.transport.connect(username=username, password=password)
        self.sftp = paramiko.SFTPClient.from_transport(self.transport)

    def upload(self, file_path, destination_path):
        self.sftp.put(file_path, destination_path)
        self.sftp.close()
        self.transport.close()
        print(f"Uploaded {file_path} to SFTP at {destination_path}")
