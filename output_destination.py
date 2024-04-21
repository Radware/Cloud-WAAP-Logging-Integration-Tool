class OutputDestination:
    def upload(self, file_path, destination_path):
        raise NotImplementedError("Each subclass must implement the 'upload' method.")
