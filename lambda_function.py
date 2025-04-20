# -*- coding: utf-8 -*-
import boto3
from botocore.client import Config
import gzip
import json
import urllib.parse
import urllib3
import certifi
import os
import re
import shutil
import io
from cloudwaap_log_utils import CloudWAAPProcessor  # Assuming this utility file exists in your package

s3_client = boto3.client('s3')

# Radware Cloud WAAP Logging Integration Tool
# Lambda function - Version 2.1.2 (Encryption generalized and optional for all destinations)

# ======================================================================
# General Script Options
# ======================================================================
DELETE_ORIGINAL = True  # Whether to delete the original file after processing.
DESTINATION = "SFTP"  # Destination type: "Internal S3", "External S3", "Dell ECS S3", "SFTP" or "Azure".
OUTPUT_FORMAT = "json.gz"  # Output file format: "ndjson", "json", "json.gz".
KEEP_ORIGINAL_FOLDER_STRUCTURE = False  # Whether to retain the original folder structure in the destination.
DESTINATION_FOLDER = "/RADWARE"  # Destination folder when not retaining the original structure (empty for root). Use forward slashes.
ENRICH_LOGS = False  # Enrich logs with additional metadata. Only works if transformation occurs (i.e., OUTPUT_FORMAT is not json.gz from a json.gz source).

# ======================================================================
# Encryption Options (NEW - Generalized: Applied optionally before any destination upload)
# ======================================================================
ENCRYPT_OUTPUT = False  # <<< SET TO True TO ENABLE ENCRYPTION FOR THE SELECTED DESTINATION >>>
# Name of the environment variable holding the encryption password
# **RECOMMENDATION**: Use AWS Secrets Manager or Parameter Store in production!
ENCRYPTION_PASSWORD_ENV_VAR = 'ENCRYPTION_PASSWORD'
# Buffer size for encryption (adjust as needed, 64k is common)
ENCRYPTION_BUFFER_SIZE = 64 * 1024
# Suffix added to the local temporary file AND the destination filename if encryption is enabled.
ENCRYPTED_FILE_SUFFIX = ".aes"

# ======================================================================
# S3 Destination Options
# ======================================================================
SUFFIX_MODE = "remove"  # Suffix modification mode for source folder name: "add" or "remove".
ORIGINAL_SUFFIX = "unprocessed"  # Suffix to remove if SUFFIX_MODE is "remove".
NEW_SUFFIX = ""  # New suffix to add if SUFFIX_MODE is "add".

# --------------------
# Internal S3 Options
# --------------------
INTERNAL_DESTINATION_BUCKET = None  # Bucket for internal S3 destination (defaults to source bucket if None).

# ======================================================================
# External S3 Options (Includes Dell ECS Configuration)
# ======================================================================

# ---------------------------------------
# External S3 General Options (Used by both AWS External and Dell ECS)
# ---------------------------------------
EXTERNAL_ACCESS_KEY_ID = ''  # Access Key for External S3 or Dell ECS
EXTERNAL_SECRET_ACCESS_KEY = ''  # Secret Key for External S3 or Dell ECS
EXTERNAL_DESTINATION_BUCKET = ''  # Bucket Name for External S3 or Dell ECS
EXTERNAL_PREFIX = ''  # Optional prefix (folder path) within the external bucket (end with "/").

# ---------------------------------------
# External AWS S3 Specific Options
# ---------------------------------------
EXTERNAL_BUCKET_REGION = ''  # AWS region for the external S3 bucket (Only used if DESTINATION is 'External S3').

# ---------------------------------------
# External Dell ECS S3 Specific Options
# ---------------------------------------
EXTERNAL_ENDPOINT_URL = ''  # Endpoint URL for Dell ECS S3-compatible storage.
EXTERNAL_ENDPOINT_SSL_VERIFY = True  # Whether to verify SSL for Dell ECS S3 access.
EXTERNAL_ENDPOINT_SIGNATURE_VERSION = "s3v4"  # S3 signature version for Dell ECS ("s3", "s3v2", "s3v4").

# ======================================================================
# Azure Destination Options
# ======================================================================
ACCOUNT_NAME = ''  # Azure storage account name.
CONTAINER_NAME = ''  # Container name in the Azure storage account.
SAS_TOKEN = ''  # SAS token for Azure container access (include leading '?' if needed).

# ======================================================================
# SFTP Destination Options
# ======================================================================
SFTP_SERVER = '193.93.108.83'  # Hostname or IP of the SFTP server.
SFTP_PORT = 2222  # Port number for the SFTP server.
SFTP_USERNAME = 'radwusr'  # Username for SFTP authentication.
SFTP_PASSWORD = ''  # Password for SFTP authentication (only used if SFTP_USE_KEY_AUTH is False).
SFTP_USE_KEY_AUTH = True  # Set to True to enable private key authentication.
SFTP_PRIVATE_KEY_FILE_NAME = 'CDPProd'  # Name of the private key file expected in the Lambda package root.
SFTP_TARGET_DIR = '/RADWARE'  # Target directory on the SFTP server for file uploads. Use forward slashes.

# --- Conditional Imports ---

# Paramiko for SFTP
paramiko_present = False
paramiko = None  # Initialize module variable
if 'SFTP' in DESTINATION:
    try:
        import paramiko
        from paramiko import RSAKey, DSSKey, ECDSAKey, Ed25519Key  # Import key types too

        # shutil is standard, import near usage is fine
        paramiko_present = True
        print("Paramiko library loaded successfully for SFTP.")
    except ImportError as e:
        print("WARNING: paramiko module is not available but DESTINATION is SFTP. SFTP functionality will FAIL.")
        # paramiko_present remains False

# pyAesCrypt for Optional Encryption (Imported based ONLY on ENCRYPT_OUTPUT flag)
pyAesCrypt_present = False
pyAesCrypt = None  # Initialize module variable
if ENCRYPT_OUTPUT:  # Check only the flag
    try:
        import pyAesCrypt  # Import the actual library object

        pyAesCrypt_present = True
        print("pyAesCrypt library loaded successfully for optional encryption.")
    except ImportError as e:
        print(
            f"WARNING: pyAesCrypt module not found, but encryption is enabled (ENCRYPT_OUTPUT=True). Encryption step will FAIL.")
        # pyAesCrypt_present remains False

# --- Initialize S3 Clients (Conditionally) ---
# Default client for source bucket operations and potentially internal S3 target
internal_s3_client = s3_client

# External clients initialized only if needed
external_s3_client = None  # For standard AWS S3 external
ecs_s3_client = None  # For Dell ECS S3

if DESTINATION == "External S3":
    if not all(
            [EXTERNAL_ACCESS_KEY_ID, EXTERNAL_SECRET_ACCESS_KEY, EXTERNAL_DESTINATION_BUCKET, EXTERNAL_BUCKET_REGION]):
        print("WARNING: DESTINATION is External S3, but one or more required EXTERNAL_* configurations are missing.")
    else:
        try:
            external_s3_client = boto3.client(
                's3',
                aws_access_key_id=EXTERNAL_ACCESS_KEY_ID,
                aws_secret_access_key=EXTERNAL_SECRET_ACCESS_KEY,
                region_name=EXTERNAL_BUCKET_REGION
            )
            print("External AWS S3 client initialized.")
        except Exception as e:
            print(f"Error initializing External AWS S3 client: {e}")

elif DESTINATION == "Dell ECS S3":
    if not all(
            [EXTERNAL_ENDPOINT_URL, EXTERNAL_ACCESS_KEY_ID, EXTERNAL_SECRET_ACCESS_KEY, EXTERNAL_DESTINATION_BUCKET]):
        print("WARNING: DESTINATION is Dell ECS S3, but one or more required EXTERNAL_* configurations are missing.")
    else:
        try:
            ecs_s3_client = boto3.client(
                's3',
                endpoint_url=EXTERNAL_ENDPOINT_URL,
                aws_access_key_id=EXTERNAL_ACCESS_KEY_ID,
                aws_secret_access_key=EXTERNAL_SECRET_ACCESS_KEY,
                verify=EXTERNAL_ENDPOINT_SSL_VERIFY,
                config=Config(signature_version=EXTERNAL_ENDPOINT_SIGNATURE_VERSION),
            )
            print("Dell ECS S3 client initialized.")
        except Exception as e:
            print(f"Error initializing Dell ECS S3 client: {e}")


# --- Helper Functions ---

def enrich_log_data(logs, log_type, application_name, tenant_name):
    """
    Enrich each log entry with tenantName, logType, and applicationName.
    (Original function from v2.1.1)
    """
    # Ensure logs is a list before iterating
    if not isinstance(logs, list):
        print("Warning: Data passed to enrich_log_data is not a list. Skipping enrichment.")
        return logs

    for log in logs:
        # Ensure log is a dictionary
        if isinstance(log, dict):
            log['logType'] = log_type
            if log_type == 'WebDDoS':
                if 'applicationName' not in log:
                    log['applicationName'] = application_name
            if log_type != "Access" and 'tenantName' not in log:
                log['tenantName'] = tenant_name
        else:
            print(f"Warning: Found non-dictionary item in logs during enrichment: {type(log)}. Skipping item.")
    return logs


def load_private_key():
    """
    Loads the SFTP private key from the specified file in the Lambda environment root.
    (Original function from v2.1.1)
    Requires paramiko.
    """
    if not paramiko_present:
        raise ImportError("paramiko library not loaded, cannot load private key.")

    key_path = f'./{SFTP_PRIVATE_KEY_FILE_NAME}'  # Path relative to Lambda execution root
    print(f"Attempting to load SFTP private key from {key_path}.")

    if not os.path.exists(key_path):
        print(f"ERROR: Private key file not found at path: {key_path}")
        raise FileNotFoundError(f"SFTP Private key file '{key_path}' not found in Lambda package.")

    try:
        with open(key_path, 'r') as key_file:
            private_key_data = key_file.read()

        if not private_key_data:
            print(f"ERROR: Private key file '{key_path}' is empty.")
            raise ValueError(f"The private key file '{key_path}' is empty.")
        print(f"Read {len(private_key_data)} characters from key file.")
        print(f"Key data starts with: {private_key_data[:30]}...")  # Debugging line
        print(f"Key data ends with: ...{private_key_data[-30:]}")  # Debugging line

        private_key_stream = io.StringIO(private_key_data)
        key_loaded = False
        private_key = None
        supported_key_types = [RSAKey, DSSKey, ECDSAKey, Ed25519Key]  # Order matters sometimes

        for pkey_class in supported_key_types:
            try:
                private_key_stream.seek(0)
                print(f"Attempting to load private key as {pkey_class.__name__}...")
                pkey = pkey_class.from_private_key(private_key_stream)
                print(f"Private key loaded successfully as {pkey_class.__name__}.")
                private_key = pkey
                key_loaded = True
                break
            except paramiko.SSHException:
                print(f"Key is not {pkey_class.__name__} type or format invalid, trying next...")
                continue
            except Exception as e:
                print(f"Unexpected error loading key as {pkey_class.__name__}: {e}")
                continue

        if not key_loaded:
            print(
                "ERROR: No valid private key format found after trying all paramiko types (RSA, DSS, ECDSA, Ed25519).")
            raise paramiko.SSHException(
                "Could not load private key using any supported format. Check key file format and content.")

        return private_key

    except FileNotFoundError:
        # Already checked above, but keep for robustness
        print(f"ERROR: Private key file not found at path: {key_path}")
        raise
    except Exception as e:
        print(f"ERROR: Failed to load private key. Reason: {e}")
        raise


def upload_to_sftp(file_path, target_dir, keep_original_folder_structure=True):
    """
    Uploads a file to the configured SFTP server using key or password auth.
    Handles directory creation based on keep_original_folder_structure.
    (Function from v2.1.1, requires paramiko)
    """
    if not paramiko_present:
        raise ImportError("paramiko library not loaded, cannot perform SFTP upload.")

    transport = None
    sftp = None

    try:
        if not os.path.exists(file_path):
            print(f"ERROR: Local file for SFTP upload does not exist: {file_path}")
            raise FileNotFoundError(f"Local file {file_path} not found for SFTP upload.")
        local_file_size = os.path.getsize(file_path)
        if local_file_size == 0:
            print(f"Warning: Local file {file_path} is empty (0 bytes). Uploading empty file.")

        print(f"Local file {file_path} found (Size: {local_file_size} bytes). Proceeding with SFTP connection.")

        print(f"Connecting to SFTP server {SFTP_SERVER}:{SFTP_PORT}...")
        transport = paramiko.Transport((SFTP_SERVER, SFTP_PORT))
        # Consider adding transport.set_keepalive(interval)

        if SFTP_USE_KEY_AUTH:
            print(f"Attempting SFTP connection using private key authentication for user '{SFTP_USERNAME}'.")
            private_key = load_private_key()
            transport.connect(username=SFTP_USERNAME, pkey=private_key)
        else:
            print(f"Attempting SFTP connection using password authentication for user '{SFTP_USERNAME}'.")
            if not SFTP_PASSWORD:
                print("Warning: SFTP_USE_KEY_AUTH is False, but SFTP_PASSWORD is not set.")
            transport.connect(username=SFTP_USERNAME, password=SFTP_PASSWORD)

        print("SFTP transport connection established.")
        sftp = paramiko.SFTPClient.from_transport(transport)
        print("SFTP client initialized.")

        # Normalize target directory path (use forward slashes, remove trailing slash if not root)
        target_dir = target_dir.replace("\\", "/")
        if target_dir != '/' and target_dir.endswith('/'):
            target_dir = target_dir[:-1]

        # Determine final target path and ensure directory exists
        final_target_path = ""
        final_target_dir = target_dir  # Base directory for upload

        if keep_original_folder_structure:
            # Directory creation logic from v2.1.1, ensures subdirs exist
            print(f"Ensuring SFTP directory structure exists for target base: {target_dir}")
            current_remote_dir = ''
            # Split respecting leading slash for absolute paths
            path_parts = target_dir.strip('/').split('/')
            base_dir = '/' if target_dir.startswith('/') else ''

            for dir_part in path_parts:
                if not dir_part: continue  # Skip empty parts from '//' or trailing '/'
                current_remote_dir = os.path.join(base_dir, current_remote_dir.strip('/'), dir_part).replace("\\", "/")
                try:
                    sftp.stat(current_remote_dir)
                    # print(f"SFTP directory '{current_remote_dir}' exists.") # Verbose
                except IOError:
                    print(f"SFTP directory '{current_remote_dir}' not found, creating...")
                    try:
                        sftp.mkdir(current_remote_dir)
                        print(f"SFTP directory '{current_remote_dir}' created.")
                    except IOError as mkdir_err:
                        # Handle race condition: check if dir exists now
                        try:
                            sftp.stat(current_remote_dir)
                            print(
                                f"SFTP directory '{current_remote_dir}' exists after mkdir attempt (race condition?).")
                        except IOError:
                            print(
                                f"ERROR: Failed to create SFTP directory '{current_remote_dir}' and it doesn't exist. Error: {mkdir_err}")
                            raise mkdir_err  # Re-raise if creation truly failed

            final_target_dir = target_dir  # The full path is the target dir
            final_target_path = os.path.join(final_target_dir, os.path.basename(file_path)).replace("\\", "/")
            print(f"Target SFTP path (keeping structure): {final_target_path}")

        else:
            # Not keeping structure, ensure only the base target_dir exists
            try:
                sftp.stat(target_dir)
                # print(f"Base SFTP target directory '{target_dir}' exists.") # Verbose
            except IOError:
                print(f"Base SFTP target directory '{target_dir}' not found, creating...")
                sftp.mkdir(target_dir)  # Create just the base folder if needed
                print(f"Base SFTP target directory '{target_dir}' created.")

            final_target_dir = target_dir  # Upload goes into this base dir
            final_target_path = os.path.join(final_target_dir, os.path.basename(file_path)).replace("\\", "/")
            print(f"Target SFTP path (NOT keeping structure): {final_target_path}")

        # Perform the upload using putfo
        print(f"Starting SFTP upload of '{file_path}' to '{final_target_path}'...")
        with open(file_path, 'rb') as local_file:
            sftp_attr = sftp.putfo(local_file, final_target_path, callback=None)  # Add callback for progress if needed
            print(f"SFTP putfo completed. Attributes: {sftp_attr}")

        # Optional: Verify file size after upload
        try:
            remote_file_stat = sftp.stat(final_target_path)
            print(f"Verification: Remote file size: {remote_file_stat.st_size} bytes.")
            if local_file_size != remote_file_stat.st_size:
                print(
                    f"Warning: Uploaded file size ({remote_file_stat.st_size}) does not match local file size ({local_file_size}).")
        except Exception as stat_err:
            print(f"Warning: Could not verify remote file size after upload. Error: {stat_err}")

        print(f"SFTP upload completed successfully: {final_target_path}")

    except Exception as e:
        print(f"ERROR during SFTP operation: {e}")
        import traceback
        traceback.print_exc()
        raise
    finally:
        if sftp:
            print("Closing SFTP client connection.")
            sftp.close()
        if transport and transport.is_active():
            print("Closing SFTP transport connection.")
            transport.close()


# --- Main Lambda Handler ---

def lambda_handler(event, context):
    # Log initial settings
    print(
        f"Lambda invoked. Destination: {DESTINATION}, Output Format: {OUTPUT_FORMAT}, Keep Structure: {KEEP_ORIGINAL_FOLDER_STRUCTURE}")
    print(f"Encryption Enabled: {ENCRYPT_OUTPUT}")
    print(f"SFTP Key Auth Enabled: {SFTP_USE_KEY_AUTH}")

    # --- Initialize paths and state variables ---
    download_path = None
    output_path = None  # Path of the file ready for upload (after transformation/encryption)
    transformed_path = None  # Intermediate path if transformation occurs
    encrypted_path = None  # Intermediate path if encryption occurs
    encryption_password = None  # Store retrieved password if needed
    bucket = None
    key = None

    # --- Cleanup /tmp ---
    tmp_dir = '/tmp'
    try:
        print("Checking /tmp directory for cleanup...")
        items = os.listdir(tmp_dir)
        if items:
            print(f"Found {len(items)} items in /tmp, proceeding with cleanup.")
            for item_name in items:
                item_path = os.path.join(tmp_dir, item_name)
                try:
                    if os.path.isfile(item_path) or os.path.islink(item_path):
                        os.unlink(item_path)
                    elif os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                    # print(f"Deleted item from /tmp: {item_path}") # Verbose
                except Exception as e:
                    print(f'Warning: Failed to delete {item_path} from /tmp. Reason: {e}')
            print("/tmp cleanup finished.")
        else:
            print("/tmp directory is already empty.")
    except Exception as e:
        print(f"Warning: Error during /tmp cleanup phase: {e}")

    try:
        # --- Process Event and Download File ---
        try:
            record = event['Records'][0]
            bucket = record['s3']['bucket']['name']
            key = urllib.parse.unquote_plus(record['s3']['object']['key'], encoding='utf-8')
            print(f"Processing event for s3://{bucket}/{key}")
        except (KeyError, IndexError, TypeError) as e:
            print(f"Error: Could not parse S3 event structure. Event: {json.dumps(event)}")
            raise ValueError(f"Invalid S3 event structure: {e}")

        file_extension = os.path.splitext(key)[1].lower()
        base_filename = os.path.basename(key)

        # Define download path (using filename only in /tmp root, as per v2.1.1)
        download_path = os.path.join(tmp_dir, base_filename)
        print(f"Attempting download: s3://{bucket}/{key} -> {download_path}")
        s3_client.download_file(bucket, key, download_path)
        print(f"S3 object downloaded successfully to {download_path}.")

        # Set initial output path to the downloaded file
        output_path = download_path

    # Handle specific configuration/setup errors before main processing
    except ValueError as e:
        print(f"Configuration or Event Error: {e}")
        return {'statusCode': 400, 'body': json.dumps(f'Configuration/Event Error: {e}')}
    except ImportError as e:
        print(f"Dependency Error: {e}")
        return {'statusCode': 500, 'body': json.dumps(f'Dependency Error: {e}')}
    except Exception as e:
        print(f"Error during initial processing or S3 download: {e}")
        import traceback
        traceback.print_exc()
        if download_path and os.path.exists(download_path):
            try:
                os.remove(download_path)
            except OSError:
                pass
        return {'statusCode': 500, 'body': json.dumps(f'Failed during setup or S3 download: {e}')}

    try:
        # --- Transformation Logic (Optional) ---
        target_output_extension = f".{OUTPUT_FORMAT}"
        if file_extension == ".txt":
            target_output_extension = ".txt"

        # Determine if transformation is needed based on formats
        # Transform if output format differs from input, unless input is txt
        needs_transformation = (target_output_extension != file_extension and file_extension != ".txt")

        if needs_transformation:
            print(f"Starting transformation from '{file_extension}' to '{target_output_extension}'...")
            # Define path for the transformed file
            transformed_filename_base = os.path.splitext(base_filename)[0]
            transformed_path = os.path.join(tmp_dir, transformed_filename_base + target_output_extension)

            # Check assumption: transformation usually means from .json.gz
            if file_extension != ".json.gz":
                print(f"Warning: Transformation assumes input is gzipped JSON, but source is '{file_extension}'.")

            try:
                with gzip.open(output_path, 'rt', encoding='utf-8') as f_in:  # Read from current output_path
                    data = json.load(f_in)

                if ENRICH_LOGS:
                    # Ensure data is suitable for enrichment (list of dicts)
                    if isinstance(data, list):
                        log_type = CloudWAAPProcessor.identify_log_type(key)
                        application_name = CloudWAAPProcessor.parse_application_name(key)
                        tenant_name = CloudWAAPProcessor.parse_tenant_name(key)
                        print(f"Enriching logs. Type: {log_type}, App: {application_name}, Tenant: {tenant_name}")
                        data = enrich_log_data(data, log_type, application_name, tenant_name)
                    else:
                        print("Warning: ENRICH_LOGS is True, but loaded data is not a list. Skipping enrichment.")

                # Write transformed data
                if OUTPUT_FORMAT == "ndjson":
                    print(f"Writing transformed NDJSON content to {transformed_path}")
                    with open(transformed_path, 'w', encoding='utf-8') as f_out:
                        if isinstance(data, list):
                            for item in data: json.dump(item, f_out); f_out.write('\n')
                        else:
                            json.dump(data, f_out); f_out.write('\n')  # Handle single object case
                elif OUTPUT_FORMAT == "json":
                    print(f"Writing transformed JSON content to {transformed_path}")
                    with open(transformed_path, 'w', encoding='utf-8') as f_out:
                        json.dump(data, f_out, indent=None)  # Compact JSON
                else:
                    print(f"Warning: Unsupported OUTPUT_FORMAT '{OUTPUT_FORMAT}' during transformation write.")
                    # If unsupported format, keep original file? Or fail? Let's keep original.
                    transformed_path = output_path  # Revert path

                # Update the main output_path to the transformed file
                output_path = transformed_path
                print(f"Transformation complete. Current output file: {output_path}")

            except (gzip.BadGzipFile, json.JSONDecodeError, UnicodeDecodeError) as e:
                print(
                    f"ERROR during file transformation: Input file {output_path} might not be valid gzipped JSON. Error: {e}")
                raise RuntimeError(f"Failed during file transformation: {e}")
            except Exception as e:
                print(f"ERROR during file transformation: An unexpected error occurred. Error: {e}")
                raise RuntimeError(f"Unexpected transformation error: {e}")
        else:
            print(f"No transformation needed. Using file as is: {output_path}")

        # --- Encryption Step (Optional, Universal) ---
        if ENCRYPT_OUTPUT:
            print(f"Encryption step: ENCRYPT_OUTPUT is True. Preparing to encrypt.")
            if not pyAesCrypt_present:
                print("ERROR: Encryption enabled (ENCRYPT_OUTPUT=True), but pyAesCrypt library failed to load.")
                raise ImportError("pyAesCrypt library is required for encryption but not available.")

            # Retrieve password now, just before use
            try:
                # **SECURITY**: Fetch from Secrets Manager/Parameter Store in production
                encryption_password = os.environ.get(ENCRYPTION_PASSWORD_ENV_VAR)
                if not encryption_password:
                    raise ValueError(f"Missing encryption password environment variable: {ENCRYPTION_PASSWORD_ENV_VAR}")
                print("Encryption password retrieved.")  # Do not log the password
            except Exception as e:
                print(f"ERROR retrieving encryption password: {e}")
                raise  # Fail fast

            # Define encrypted file path
            encrypted_path = output_path + ENCRYPTED_FILE_SUFFIX
            print(f"Encrypting '{output_path}' to '{encrypted_path}'...")

            try:
                pyAesCrypt.encryptFile(output_path, encrypted_path, encryption_password, ENCRYPTION_BUFFER_SIZE)
                print(f"Encryption successful.")
                # Update the main output_path to point to the encrypted file for subsequent upload steps
                output_path = encrypted_path
                print(f"Updated output_path to encrypted file: {output_path}")
            except Exception as e:
                print(f"ERROR during pyAesCrypt encryption: {e}")
                # Clean up potentially created encrypted file fragment
                if encrypted_path and os.path.exists(encrypted_path):
                    try:
                        os.remove(encrypted_path)
                    except OSError:
                        pass
                raise RuntimeError(f"Failed during file encryption: {e}")
        else:
            print("Encryption step: ENCRYPT_OUTPUT is False. Skipping encryption.")

        # --- Destination Upload Logic ---
        print(f"Preparing upload for destination: {DESTINATION}")
        print(f"Final file to upload: {output_path}")  # This path includes transformation and encryption effects

        # --- S3 Destinations (Internal, External AWS, Dell ECS) ---
        if DESTINATION in ["Internal S3", "External S3", "Dell ECS S3"]:
            s3_upload_client = None
            destination_bucket = None
            destination_prefix = ""

            # Select client and config
            if DESTINATION == 'Internal S3':
                s3_upload_client = internal_s3_client
                destination_bucket = INTERNAL_DESTINATION_BUCKET or bucket
                print(f"Configured for Internal S3. Target Bucket: {destination_bucket}")
            elif DESTINATION == 'External S3':
                s3_upload_client = external_s3_client
                destination_bucket = EXTERNAL_DESTINATION_BUCKET
                destination_prefix = EXTERNAL_PREFIX
                print(
                    f"Configured for External AWS S3. Target Bucket: {destination_bucket}, Prefix: {destination_prefix}")
            elif DESTINATION == 'Dell ECS S3':
                s3_upload_client = ecs_s3_client
                destination_bucket = EXTERNAL_DESTINATION_BUCKET
                destination_prefix = EXTERNAL_PREFIX
                print(f"Configured for Dell ECS S3. Target Bucket: {destination_bucket}, Prefix: {destination_prefix}")

            if not s3_upload_client: raise ValueError(f"S3 Upload client not initialized for {DESTINATION}.")
            if not destination_bucket: raise ValueError(f"Destination bucket not configured for {DESTINATION}.")

            # Determine Destination S3 Key (uses the final output_path's basename)
            final_filename = os.path.basename(output_path)  # Includes .aes if encrypted
            output_key_unprefixed = ""

            if KEEP_ORIGINAL_FOLDER_STRUCTURE:
                key_parts = key.split('/')
                first_folder = key_parts[0]
                modified_first_folder = first_folder
                if SUFFIX_MODE == 'remove' and ORIGINAL_SUFFIX:
                    modified_first_folder = first_folder.replace(f'-{ORIGINAL_SUFFIX}', '')
                elif SUFFIX_MODE == 'add' and NEW_SUFFIX:
                    modified_first_folder = f'{first_folder}-{NEW_SUFFIX}'

                if len(key_parts) > 1:
                    # Combine modified first folder with rest of original path (excluding filename)
                    original_dirs_part = os.path.dirname(os.path.join(*key_parts[1:]))
                    key_structure_base = os.path.join(modified_first_folder,
                                                      original_dirs_part) if original_dirs_part else modified_first_folder
                else:
                    key_structure_base = modified_first_folder  # Assume first part is dir if only one part

                output_key_unprefixed = os.path.join(key_structure_base, final_filename)
                print(f"Keeping folder structure. Base S3 key structure: {output_key_unprefixed}")
            else:
                output_key_unprefixed = os.path.join(DESTINATION_FOLDER,
                                                     final_filename) if DESTINATION_FOLDER else final_filename
                print(f"Not keeping folder structure. Base S3 key: {output_key_unprefixed}")

            # Combine prefix and base key, normalize
            destination_key = os.path.join(destination_prefix, output_key_unprefixed)
            destination_key = destination_key.replace("\\", "/")
            if destination_key.startswith('/'): destination_key = destination_key[1:]

            # Upload to S3
            print(f"Starting upload to {DESTINATION}:")
            print(f"  Source File: '{output_path}'")
            print(f"  Destination Bucket: '{destination_bucket}'")
            print(f"  Destination Key: '{destination_key}'")
            s3_upload_client.upload_file(output_path, destination_bucket, destination_key)
            print(f"Upload to {DESTINATION} completed successfully.")


        # --- SFTP Destination ---
        elif DESTINATION == "SFTP":
            if not paramiko_present: raise ImportError("paramiko library not available for SFTP.")

            sftp_file_to_upload = output_path  # Use the final path after potential encryption
            print(f"SFTP Destination: Preparing to upload local file: {sftp_file_to_upload}")

            # Determine target directory on SFTP server
            sftp_target_directory_final = SFTP_TARGET_DIR
            if KEEP_ORIGINAL_FOLDER_STRUCTURE:
                original_path_dirs = os.path.dirname(key)
                if original_path_dirs: sftp_target_directory_final = os.path.join(SFTP_TARGET_DIR, original_path_dirs)
                print(f"SFTP Target Directory (Keeping Structure): {sftp_target_directory_final}")
            else:
                print(f"SFTP Target Directory (NOT Keeping Structure): {sftp_target_directory_final}")

            # Perform SFTP upload
            upload_to_sftp(sftp_file_to_upload, sftp_target_directory_final, KEEP_ORIGINAL_FOLDER_STRUCTURE)


        # --- Azure Destination ---
        elif DESTINATION == 'Azure':
            print("Preparing upload to Azure Blob Storage...")
            if not all([ACCOUNT_NAME, CONTAINER_NAME, SAS_TOKEN]): raise ValueError("Azure config missing.")

            # Determine Azure Blob Name (uses final output_path's basename)
            final_filename_for_azure = os.path.basename(output_path)  # Includes .aes if encrypted
            blob_name = ""

            if KEEP_ORIGINAL_FOLDER_STRUCTURE:
                key_parts = key.split('/')
                first_folder = key_parts[0]
                modified_first_folder = first_folder
                if SUFFIX_MODE == 'remove' and ORIGINAL_SUFFIX:
                    modified_first_folder = first_folder.replace(f'-{ORIGINAL_SUFFIX}', '')
                elif SUFFIX_MODE == 'add' and NEW_SUFFIX:
                    modified_first_folder = f'{first_folder}-{NEW_SUFFIX}'

                if len(key_parts) > 1:
                    original_dirs_only = os.path.dirname(os.path.join(*key_parts[1:]))
                    modified_directory_structure = os.path.join(modified_first_folder,
                                                                original_dirs_only) if original_dirs_only else modified_first_folder
                else:
                    modified_directory_structure = modified_first_folder

                blob_name = os.path.join(modified_directory_structure, final_filename_for_azure)
                print(f"Azure Blob Name (Keeping Structure): {blob_name}")
            else:
                blob_name = os.path.join(DESTINATION_FOLDER,
                                         final_filename_for_azure) if DESTINATION_FOLDER else final_filename_for_azure
                print(f"Azure Blob Name (NOT Keeping Structure): {blob_name}")

            # Normalize path, URL encode, and construct URL
            blob_name = blob_name.replace("\\", "/")
            if blob_name.startswith('/'): blob_name = blob_name[1:]
            sas_token_corrected = SAS_TOKEN if SAS_TOKEN.startswith('?') else '?' + SAS_TOKEN
            url = f"https://{ACCOUNT_NAME}.blob.core.windows.net/{CONTAINER_NAME}/{urllib.parse.quote(blob_name)}{sas_token_corrected}"

            # Set headers based on FINAL output file (could be .aes)
            content_type = 'application/octet-stream'  # Default, suitable for encrypted binary
            headers = {'x-ms-blob-type': 'BlockBlob'}
            # Determine content type based on the file *before* potential encryption if needed
            # For simplicity, using octet-stream for potentially encrypted data is safe.
            # If you needed specific content-types for non-encrypted data:
            # base_file_for_content_type = encrypted_path[:-len(ENCRYPTED_FILE_SUFFIX)] if ENCRYPT_OUTPUT else output_path
            # if base_file_for_content_type.endswith(".ndjson"): content_type = '...' etc.
            headers['Content-Type'] = content_type
            print(f"Azure Upload Headers: {headers}")

            print(f"Uploading '{output_path}' to Azure Blob: {blob_name}")
            print(f"Target URL (SAS hidden): https://{ACCOUNT_NAME}.blob.core.windows.net/{CONTAINER_NAME}/{blob_name}")

            with open(output_path, 'rb') as f:
                upload_content = f.read()

            http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=certifi.where())
            response = http.request('PUT', url, body=upload_content, headers=headers)
            if response.status != 201:
                error_message = f"Failed to upload blob to Azure. Status: {response.status}, Reason: {response.data.decode('utf-8', errors='ignore')}"
                print(f"ERROR: {error_message}")
                raise Exception(error_message)
            else:
                print("Upload to Azure Blob Storage successful.")

        else:
            print(f"Warning: Destination '{DESTINATION}' is not recognized or configured for upload.")
            # raise ValueError(f"Unsupported DESTINATION configured: {DESTINATION}")

        # --- Original File Deletion (if enabled) ---
        if DELETE_ORIGINAL:
            try:
                print(f"Attempting to delete original S3 object: s3://{bucket}/{key}")
                s3_client.delete_object(Bucket=bucket, Key=key)
                print("Original S3 object deleted successfully.")
            except Exception as e:
                print(f"Warning: Failed to delete original S3 object s3://{bucket}/{key}. Error: {e}")

        print("Lambda execution completed successfully.")
        return {
            'statusCode': 200,
            'body': json.dumps(f'File s3://{bucket}/{key} processed successfully and sent to {DESTINATION}.')
        }

    except Exception as e:
        # Catch-all for errors during main processing (transform, encrypt, upload)
        print(f"FATAL ERROR during Lambda execution for s3://{bucket}/{key}. Error: {e}")
        import traceback
        traceback.print_exc()
        return {
            'statusCode': 500,
            'body': json.dumps(f'Failed to process file s3://{bucket}/{key}. Error: {e}')
        }

    finally:
        # --- Final Cleanup of Temporary Files ---
        print("Initiating final cleanup of temporary files in /tmp...")
        # List all potential files created during execution
        files_to_clean = {download_path, transformed_path, encrypted_path, output_path}  # Use set to handle duplicates

        for file_path in files_to_clean:
            # Check if path is valid and exists
            if file_path and isinstance(file_path, str) and os.path.exists(file_path):
                try:
                    # Double check it's a file before removing
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                        print(f"Deleted temporary file: {file_path}")
                    # Optional: could handle deleting temp directories if needed
                except Exception as e:
                    print(f"Warning: Could not delete temporary file {file_path}. Reason: {e}")
            # Silently ignore None paths or non-existent paths

        print("Temporary file cleanup finished.")