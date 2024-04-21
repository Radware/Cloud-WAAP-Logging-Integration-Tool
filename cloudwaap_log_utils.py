import re
from urllib.parse import urlparse
from datetime import datetime


class CloudWAAPProcessor:
    """
    CloudWAAPProcessor provides a collection of static methods designed to process
    and analyze Cloud WAAP logs. It includes functionalities for identifying log types,
    parsing various components of the logs, and extracting detailed information from log entries.
    """

    @staticmethod
    def identify_log_type(key):
        """
        Identify the type of Cloud WAAP log based on the key or file name.

        Args:
            key (str): The S3 key or file name of the log.

        Returns:
            str: The identified type of log ('Access', a specific log type, or 'Unknown').
        """
        try:
            log_type = "Unknown"
            parts = key.split("/")

            if parts:
                last_part = parts[-1]
                if last_part.startswith("rdwr_log"):
                    log_type = "Access"
                elif last_part.startswith("rdwr_event"):
                    log_type = parts[-2]

            return log_type
        except Exception as e:
            print(f"Error identifying log type for key '{key}': {e}")
            return "Unknown"

    @staticmethod
    def identify_application_id(key, log_type):
        """
        Identify and return specific parts of a Cloud WAAP log key based on the log type.

        Args:
            key (str): The S3 key or file name of the log.
            log_type (str): The type of log, e.g., "Bot" or other specified types.

        Returns:
            str: The identified part of the log key (e.g., application ID if log_type is "Bot", or 'Unknown').
        """
        try:
            # Default value in case of failure to identify
            result = "Unknown"

            # Split the key into parts
            parts = key.split("/")

            if parts and log_type == "Bot":
                result = parts[-3]
            else:
                # For other types of logs, implement the logic as needed
                pass

            return result
        except Exception as e:
            print(f"Error processing key '{key}' with log_type '{log_type}': {e}")
            return "Unknown"

    @staticmethod
    def parse_tenant_name(key):
        """
        Extract the tenant name from the S3 key.

        Args:
            key (str): The S3 key of the log file.

        Returns:
            str: The extracted tenant name.
        """
        try:
            parts = key.split("/")
            if len(parts) >= 4:
                tenant_name = parts[-4]
                return tenant_name
            print(f"Unable to extract tenant name from key: {key}")
            return ""
        except Exception as e:
            print(f"Error extracting tenant name from key '{key}': {e}")
            return ""

    @staticmethod
    def parse_application_name(key):
        """
        Extract the application name from the S3 key based on a regular expression pattern.

        Args:
            key (str): The S3 key of the log file.

        Returns:
            str or None: The extracted application name, or None if not found.
        """
        try:
            tenant_name = CloudWAAPProcessor.parse_tenant_name(key)
            pattern = r"rdwr_event_{}_([^_]+)_(\d{{8}}H\d{{6}})".format(tenant_name)
            match = re.search(pattern, key)

            if match:
                application_name = match.group(1)
                return application_name
            else:
                print(f"No application name found in key: {key}")
                return None
        except Exception as e:
            print(f"Error parsing application name from key '{key}': {e}")
            return None

    @staticmethod
    def parse_names_from_log_data(log_data):
        """
        Extracts both the tenant name and application name from the first entry in the log data.

        Args:
            log_data (list of dict): The log data loaded, usually a list of dictionaries.

        Returns:
            tuple: The extracted tenant name and application name. Each will be an empty string
                   if not found or if an error occurs.
        """
        try:
            if log_data and len(log_data) > 0:
                tenant_name = log_data[0].get('tenant_name', '')
                application_name = log_data[0].get('application_name', '')
                return (tenant_name, application_name)
        except Exception as e:
            print(f"Error parsing names from log data: {e}")
        return ("", "")