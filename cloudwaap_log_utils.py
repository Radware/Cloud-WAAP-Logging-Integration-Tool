import re
from urllib.parse import urlparse
from datetime import datetime


class CloudWAAPProcessor:
    """
    Utility class for processing Cloud WAAP logs and extracting metadata.
    Handles log type identification, tenant parsing, and application details extraction.
    """

    @staticmethod
    def identify_log_type(key):
        """
        Extract the log type from a Cloud WAAP log file key.

        Args:
            key (str): S3 object key or file path

        Returns:
            str: Log type ('Access', specific event type, or 'Unknown')
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
            print(f"ERROR: Log type identification failed for '{key}': {e}")
            return "Unknown"

    @staticmethod
    def identify_application_id(key, log_type):
        """
        Extract application ID from log key based on log type.

        Args:
            key (str): S3 object key or file path
            log_type (str): Type of log being processed

        Returns:
            str: Application ID or 'Unknown'
        """
        try:
            result = "Unknown"
            parts = key.split("/")

            if parts and log_type == "Bot":
                result = parts[-3]

            return result
        except Exception as e:
            print(f"ERROR: Application ID extraction failed for '{key}': {e}")
            return "Unknown"

    @staticmethod
    def parse_tenant_name(key):
        """
        Extract tenant name from log file key.

        Args:
            key (str): S3 object key or file path

        Returns:
            str: Tenant name or empty string if not found
        """
        try:
            parts = key.split("/")
            if len(parts) >= 4:
                return parts[-4]
            return ""
        except Exception as e:
            print(f"ERROR: Tenant name extraction failed for '{key}': {e}")
            return ""

    @staticmethod
    def parse_application_name(key):
        """
        Extract application name from log file key using regex pattern.

        Args:
            key (str): S3 object key or file path

        Returns:
            str or None: Application name or None if not found
        """
        try:
            tenant_name = CloudWAAPProcessor.parse_tenant_name(key)
            pattern = r"rdwr_event_{}_([^_]+)_(\d{{8}}H\d{{6}})".format(tenant_name)
            match = re.search(pattern, key)

            if match:
                return match.group(1)
            return None
        except Exception as e:
            print(f"ERROR: Application name extraction failed for '{key}': {e}")
            return None