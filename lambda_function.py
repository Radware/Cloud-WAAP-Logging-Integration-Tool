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
import zipfile # For password-protected zip files
import traceback # For better error printing

# Assuming this utility file exists in your Lambda deployment package
try:
    from cloudwaap_log_utils import CloudWAAPProcessor
except ImportError:
    # Provide a dummy class if the utility is not found, allowing basic operation
    print("WARNING: cloudwaap_log_utils not found. Enrichment features will be disabled.")
    class CloudWAAPProcessor:
        @staticmethod
        def identify_log_type(key): return "Unknown"
        @staticmethod
        def parse_application_name(key): return "Unknown"
        @staticmethod
        def parse_tenant_name(key): return "Unknown"

s3_client = boto3.client('s3')

# Radware Cloud WAAP Logging Integration Tool
# Lambda function - Version 2.1.2 

# ======================================================================
# General Script Options
# ======================================================================
DELETE_ORIGINAL = True  # Whether to delete the original file after successful processing and upload.
# Destination type: "Internal S3", "External S3", "Custom S3", "SFTP" or "Azure".
DESTINATION = "Internal" 
OUTPUT_FORMAT = "json.gz"  # Output file format: "ndjson", "json", "json.gz". (Determines if transformation happens before zipping)
KEEP_ORIGINAL_FOLDER_STRUCTURE = False  # Whether to retain the original folder structure in the destination.
DESTINATION_FOLDER = ""  # Destination folder when not retaining structure (empty for root). Use forward slashes.
ENRICH_LOGS = False  # Enrich logs with additional metadata. Only works if transformation occurs.

# ======================================================================
# Password-Protected Zip Options
# ======================================================================
PASSWORD_PROTECT_ZIP = True # Use this flag to enable/disable zip protection
ZIP_PASSWORD_ENV_VAR = 'ZIP_PASSWORD' # Environment variable for the zip password
PROTECTED_ZIP_SUFFIX = ".zip" # Output file will have this suffix if protected

# ======================================================================
# S3 Destination Options
# ======================================================================
SUFFIX_MODE = "remove"
ORIGINAL_SUFFIX = "unprocessed"
NEW_SUFFIX = ""
INTERNAL_DESTINATION_BUCKET = None

# ======================================================================
# External & Custom S3 Options (Includes S3-Compatible Storage like Synology, MinIO, etc.)
# ======================================================================

# ---------------------------------------
# External/Custom S3 General Options (Used by both AWS External and Custom S3)
# ---------------------------------------
EXTERNAL_ACCESS_KEY_ID = ''  # Access Key for External AWS S3 or Custom S3 storage
EXTERNAL_SECRET_ACCESS_KEY = ''  # Secret Key for External AWS S3 or Custom S3 storage
EXTERNAL_DESTINATION_BUCKET = ''  # Bucket Name for External AWS S3 or Custom S3 storage
EXTERNAL_PREFIX = ''  # Optional prefix (folder path) within the external bucket (end with "/").

# ---------------------------------------
# External AWS S3 Specific Options
# ---------------------------------------
EXTERNAL_BUCKET_REGION = ''  # AWS region for the external S3 bucket (Only used if DESTINATION is 'External S3').

# ---------------------------------------
# Custom S3 Specific Options (e.g., Synology, MinIO, Dell ECS, other S3-compatible)
# ---------------------------------------
EXTERNAL_ENDPOINT_URL = ''  # Endpoint URL for the Custom S3-compatible storage. REQUIRED for Custom S3.
EXTERNAL_ENDPOINT_SSL_VERIFY = True  # Whether to verify SSL for Custom S3 access.
EXTERNAL_ENDPOINT_SIGNATURE_VERSION = "s3v4"  # S3 signature version for Custom S3 ("s3", "s3v2", "s3v4").

# ======================================================================
# Azure Destination Options
# ======================================================================
ACCOUNT_NAME = ''
CONTAINER_NAME = ''
SAS_TOKEN = ''

# ======================================================================
# SFTP Destination Options
# ======================================================================
SFTP_SERVER = ''
SFTP_PORT = 21
SFTP_USERNAME = ''
SFTP_PASSWORD = ''
SFTP_USE_KEY_AUTH = True
SFTP_PRIVATE_KEY_FILE_NAME = ''
SFTP_TARGET_DIR = ''

# --- Conditional Imports ---

# Paramiko for SFTP
paramiko_present = False
paramiko = None
if 'SFTP' in DESTINATION:
    try:
        import paramiko
        from paramiko import RSAKey, DSSKey, ECDSAKey, Ed25519Key
        paramiko_present = True
        print("Paramiko library loaded successfully for SFTP.")
    except ImportError as e:
        print("WARNING: paramiko module is not available but DESTINATION is SFTP. SFTP functionality will FAIL.")

# --- Initialize S3 Clients (Conditionally) ---
internal_s3_client = s3_client # For source bucket and potentially internal destination
external_s3_client = None
custom_s3_client = None #

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

# --- Condition and variable name ---
elif DESTINATION == "Custom S3":
    if not all(
            [EXTERNAL_ENDPOINT_URL, EXTERNAL_ACCESS_KEY_ID, EXTERNAL_SECRET_ACCESS_KEY, EXTERNAL_DESTINATION_BUCKET]):
        print("WARNING: DESTINATION is Custom S3, but one or more required configurations are missing (Endpoint URL, Access Key, Secret Key, Bucket Name).")
    else:
        try:
            custom_s3_client = boto3.client( 
                's3',
                endpoint_url=EXTERNAL_ENDPOINT_URL,
                aws_access_key_id=EXTERNAL_ACCESS_KEY_ID,
                aws_secret_access_key=EXTERNAL_SECRET_ACCESS_KEY,
                verify=EXTERNAL_ENDPOINT_SSL_VERIFY,
                config=Config(signature_version=EXTERNAL_ENDPOINT_SIGNATURE_VERSION),
            )
            print("Custom S3 client initialized.") 
        except Exception as e:
            print(f"Error initializing Custom S3 client: {e}") 

# --- Helper Functions ---

def enrich_log_data(logs, log_type, application_name, tenant_name):
    """Enrich log data."""
    if not isinstance(logs, list):
        print("Warning: Data passed to enrich_log_data is not a list. Skipping enrichment.")
        return logs
    for log in logs:
        if isinstance(log, dict):
            log['logType'] = log_type
            if log_type == 'WebDDoS':
                if 'applicationName' not in log: log['applicationName'] = application_name
            if log_type != "Access" and 'tenantName' not in log: log['tenantName'] = tenant_name
        else:
            print(f"Warning: Found non-dictionary item in logs during enrichment: {type(log)}. Skipping item.")
    return logs

def load_private_key():
    """Loads SFTP private key."""
    if not paramiko_present: raise ImportError("paramiko library not loaded, cannot load private key.")
    key_path = f'./{SFTP_PRIVATE_KEY_FILE_NAME}'
    print(f"Attempting to load SFTP private key from {key_path}.")
    if not os.path.exists(key_path): raise FileNotFoundError(f"SFTP Private key file '{key_path}' not found.")
    try:
        with open(key_path, 'r') as key_file: private_key_data = key_file.read()
        if not private_key_data: raise ValueError(f"The private key file '{key_path}' is empty.")
        print(f"Read {len(private_key_data)} characters from key file.")
        private_key_stream = io.StringIO(private_key_data)
        key_loaded = False; private_key = None
        supported_key_types = [paramiko.RSAKey, paramiko.DSSKey, paramiko.ECDSAKey, paramiko.Ed25519Key]
        for pkey_class in supported_key_types:
            try:
                private_key_stream.seek(0); print(f"Attempting to load private key as {pkey_class.__name__}...")
                pkey = pkey_class.from_private_key(private_key_stream); print(f"Private key loaded successfully as {pkey_class.__name__}.")
                private_key = pkey; key_loaded = True; break
            except paramiko.SSHException: print(f"Key is not {pkey_class.__name__} type or format invalid, trying next..."); continue
            except Exception as e: print(f"Unexpected error loading key as {pkey_class.__name__}: {e}"); continue
        if not key_loaded: raise paramiko.SSHException("Could not load private key using any supported format.")
        return private_key
    except FileNotFoundError: print(f"ERROR: Private key file not found at path: {key_path}"); raise
    except Exception as e: print(f"ERROR: Failed to load private key. Reason: {e}"); raise

def upload_to_sftp(file_path, target_dir, keep_original_folder_structure=True):
    """Uploads file to SFTP server."""
    if not paramiko_present: raise ImportError("paramiko library not loaded, cannot perform SFTP upload.")
    transport = None; sftp = None
    try:
        if not os.path.exists(file_path): raise FileNotFoundError(f"Local file {file_path} not found for SFTP upload.")
        local_file_size = os.path.getsize(file_path)
        if local_file_size == 0: print(f"Warning: Local file {file_path} is empty (0 bytes). Uploading empty file.")
        print(f"Local file {file_path} found (Size: {local_file_size} bytes). Proceeding with SFTP connection.")
        print(f"Connecting to SFTP server {SFTP_SERVER}:{SFTP_PORT}...")
        transport = paramiko.Transport((SFTP_SERVER, SFTP_PORT))
        transport.connect(hostkey=None, username=SFTP_USERNAME, password=SFTP_PASSWORD if not SFTP_USE_KEY_AUTH else None, pkey=load_private_key() if SFTP_USE_KEY_AUTH else None)
        print("SFTP transport connection established.")
        sftp = paramiko.SFTPClient.from_transport(transport)
        print("SFTP client initialized.")
        target_dir = target_dir.replace("\\", "/")
        if target_dir != '/' and target_dir.endswith('/'): target_dir = target_dir[:-1]
        final_target_path = ""; final_target_dir = target_dir
        if keep_original_folder_structure:
            print(f"Ensuring SFTP directory structure exists for target base: {target_dir}")
            current_remote_dir = ''; path_parts = target_dir.strip('/').split('/'); base_dir = '/' if target_dir.startswith('/') else ''
            for dir_part in path_parts:
                if not dir_part: continue
                current_remote_dir = os.path.join(base_dir, current_remote_dir.strip('/'), dir_part).replace("\\", "/")
                try: sftp.stat(current_remote_dir)
                except IOError:
                    print(f"SFTP directory '{current_remote_dir}' not found, creating...")
                    try: sftp.mkdir(current_remote_dir); print(f"SFTP directory '{current_remote_dir}' created.")
                    except IOError as mkdir_err:
                        try: sftp.stat(current_remote_dir); print(f"SFTP directory '{current_remote_dir}' exists after mkdir attempt (race condition?).")
                        except IOError: print(f"ERROR: Failed to create SFTP directory '{current_remote_dir}'. Error: {mkdir_err}"); raise
            final_target_dir = target_dir
            final_target_path = os.path.join(final_target_dir, os.path.basename(file_path)).replace("\\", "/")
            print(f"Target SFTP path (keeping structure): {final_target_path}")
        else:
            try: sftp.stat(target_dir)
            except IOError: print(f"Base SFTP target directory '{target_dir}' not found, creating..."); sftp.mkdir(target_dir); print(f"Base SFTP target directory '{target_dir}' created.")
            final_target_dir = target_dir
            final_target_path = os.path.join(final_target_dir, os.path.basename(file_path)).replace("\\", "/")
            print(f"Target SFTP path (NOT keeping structure): {final_target_path}")
        print(f"Starting SFTP upload of '{file_path}' to '{final_target_path}'...")
        with open(file_path, 'rb') as local_file: sftp_attr = sftp.putfo(local_file, final_target_path, callback=None)
        print(f"SFTP putfo completed. Attributes: {sftp_attr}")
        try:
            remote_file_stat = sftp.stat(final_target_path); print(f"Verification: Remote file size: {remote_file_stat.st_size} bytes.")
            if local_file_size != remote_file_stat.st_size: print(f"Warning: Uploaded file size ({remote_file_stat.st_size}) != local size ({local_file_size}).")
        except Exception as stat_err: print(f"Warning: Could not verify remote file size after upload. Error: {stat_err}")
        print(f"SFTP upload completed successfully: {final_target_path}")
    except Exception as e: print(f"ERROR during SFTP operation: {e}"); traceback.print_exc(); raise
    finally:
        if sftp: print("Closing SFTP client connection."); sftp.close()
        if transport and transport.is_active(): print("Closing SFTP transport connection."); transport.close()

# --- Main Lambda Handler ---

def lambda_handler(event, context):
    print(f"Lambda invoked. Destination: {DESTINATION}, Output Format: {OUTPUT_FORMAT}, Keep Structure: {KEEP_ORIGINAL_FOLDER_STRUCTURE}")
    print(f"Password Protect Zip Enabled: {PASSWORD_PROTECT_ZIP}")
    print(f"SFTP Key Auth Enabled: {SFTP_USE_KEY_AUTH}")

    download_path = None; output_path = None; transformed_path = None
    zip_protected_path = None; zip_password = None
    bucket = None; key = None

    # --- Cleanup /tmp at start ---
    tmp_dir = '/tmp'
    try:
        print("Checking /tmp directory for initial cleanup...")
        items = os.listdir(tmp_dir)
        if items:
            print(f"Found {len(items)} items in /tmp, proceeding with cleanup.")
            for item_name in items:
                item_path = os.path.join(tmp_dir, item_name)
                try:
                    if os.path.isfile(item_path) or os.path.islink(item_path): os.unlink(item_path)
                    elif os.path.isdir(item_path): shutil.rmtree(item_path)
                except Exception as e: print(f'Warning: Failed to delete {item_path} during initial cleanup. Reason: {e}')
            print("/tmp initial cleanup finished.")
        else: print("/tmp directory is already empty.")
    except Exception as e: print(f"Warning: Error during /tmp initial cleanup phase: {e}")

    try:
        # --- Process Event and Download File ---
        try:
            record = event['Records'][0]
            bucket = record['s3']['bucket']['name']
            key = urllib.parse.unquote_plus(record['s3']['object']['key'], encoding='utf-8')
            print(f"Processing event for s3://{bucket}/{key}")
        except (KeyError, IndexError, TypeError) as e:
            print(f"Error: Could not parse S3 event structure. Event: {json.dumps(event)}")
            raise ValueError(f"Invalid S3 event structure: {e}") # Treat as non-retryable config error

        file_extension = os.path.splitext(key)[1].lower()
        base_filename = os.path.basename(key)
        download_path = os.path.join(tmp_dir, base_filename)
        print(f"Attempting download: s3://{bucket}/{key} -> {download_path}")
        s3_client.download_file(bucket, key, download_path)
        print(f"S3 object downloaded successfully to {download_path}.")
        output_path = download_path

    except ValueError as e: # Catch bad event structure
        print(f"Configuration or Event Error: {e}")
        # Return success as this is likely not fixable by retry
        return {'statusCode': 400, 'body': json.dumps(f'Configuration/Event Error: {e}')}
    except ImportError as e: # Catch missing critical libraries
        print(f"Dependency Error: {e}"); raise # Let Lambda handle retries/DLQ
    except Exception as e: # Catch errors during S3 download or initial setup
        print(f"Error during initial processing or S3 download: {e}"); traceback.print_exc()
        if download_path and os.path.exists(download_path):
            try: os.remove(download_path); print(f"Cleaned up downloaded file: {download_path}")
            except OSError: pass
        raise # Let Lambda handle retries/DLQ

    # --- Main Processing Block (Transform, Zip, Upload) ---
    try:
        # --- Transformation Logic (Optional) ---
        target_output_extension = f".{OUTPUT_FORMAT}"
        if file_extension == ".txt": target_output_extension = ".txt"
        needs_transformation = (target_output_extension != file_extension and file_extension != ".txt")

        if needs_transformation:
            print(f"Starting transformation from '{file_extension}' to '{target_output_extension}'...")
            transformed_filename_base = os.path.splitext(base_filename)[0]
            transformed_path = os.path.join(tmp_dir, transformed_filename_base + target_output_extension)
            if file_extension != ".json.gz": print(f"Warning: Transformation assumes input is gzipped JSON, but source is '{file_extension}'.")
            try:
                with gzip.open(output_path, 'rt', encoding='utf-8') as f_in: data = json.load(f_in)
                if ENRICH_LOGS:
                    if isinstance(data, list):
                        log_type = CloudWAAPProcessor.identify_log_type(key)
                        application_name = CloudWAAPProcessor.parse_application_name(key)
                        tenant_name = CloudWAAPProcessor.parse_tenant_name(key)
                        print(f"Enriching logs. Type: {log_type}, App: {application_name}, Tenant: {tenant_name}")
                        data = enrich_log_data(data, log_type, application_name, tenant_name)
                    else: print("Warning: ENRICH_LOGS is True, but loaded data is not a list. Skipping enrichment.")
                if OUTPUT_FORMAT == "ndjson":
                    print(f"Writing transformed NDJSON content to {transformed_path}")
                    with open(transformed_path, 'w', encoding='utf-8') as f_out:
                        if isinstance(data, list):
                            for item in data: json.dump(item, f_out); f_out.write('\n')
                        else: json.dump(data, f_out); f_out.write('\n')
                elif OUTPUT_FORMAT == "json":
                    print(f"Writing transformed JSON content to {transformed_path}")
                    with open(transformed_path, 'w', encoding='utf-8') as f_out: json.dump(data, f_out, indent=None)
                else: print(f"Warning: Unsupported OUTPUT_FORMAT '{OUTPUT_FORMAT}'."); transformed_path = output_path
                output_path = transformed_path
                print(f"Transformation complete. Current output file: {output_path}")
            except (gzip.BadGzipFile, json.JSONDecodeError, UnicodeDecodeError) as e: print(f"ERROR during file transformation: {e}"); raise RuntimeError(f"Failed during file transformation: {e}")
            except Exception as e: print(f"ERROR during file transformation: {e}"); raise RuntimeError(f"Unexpected transformation error: {e}")
        else:
            print(f"No transformation needed. Using file as is: {output_path}")

        # --- Password Protect Zip Step (Optional) ---
        if PASSWORD_PROTECT_ZIP:
            print(f"Zip protection step: PASSWORD_PROTECT_ZIP is True.")
            try:
                zip_password = os.environ.get(ZIP_PASSWORD_ENV_VAR)
                if not zip_password: raise ValueError(f"Missing zip password env var: {ZIP_PASSWORD_ENV_VAR}")
                print("Zip password retrieved.")
            except Exception as e: print(f"ERROR retrieving zip password: {e}"); raise
            zip_protected_path = output_path + PROTECTED_ZIP_SUFFIX
            file_to_zip = output_path; filename_inside_zip = os.path.basename(file_to_zip)
            print(f"Creating password-protected zip '{zip_protected_path}' containing '{filename_inside_zip}'...")
            try:
                with zipfile.ZipFile(zip_protected_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
                    zf.setpassword(zip_password.encode('utf-8'))
                    zf.write(file_to_zip, arcname=filename_inside_zip)
                print(f"Password-protected zip created successfully.")
                output_path = zip_protected_path
                print(f"Updated output_path to zip file: {output_path}")
            except zipfile.BadZipFile as e: print(f"ERROR creating zip file: {e}"); raise RuntimeError(f"Failed zip creation: {e}")
            except Exception as e: print(f"ERROR during zip creation: {e}"); traceback.print_exc(); raise RuntimeError(f"Failed zipping: {e}")
        else:
            print("Zip protection step: PASSWORD_PROTECT_ZIP is False. Skipping.")

        # --- Destination Upload Logic ---
        print(f"Preparing upload for destination: {DESTINATION}")
        print(f"Final file to upload: {output_path}")

        # --- S3 Destinations (Internal, External AWS, Custom S3) ---
        # --- condition and variable usage ---
        if DESTINATION in ["Internal S3", "External S3", "Custom S3"]:
            s3_upload_client = None; destination_bucket = None; destination_prefix = ""
            if DESTINATION == 'Internal S3':
                 s3_upload_client = internal_s3_client; destination_bucket = INTERNAL_DESTINATION_BUCKET or bucket; print(f"Configured for Internal S3. Target Bucket: {destination_bucket}")
            elif DESTINATION == 'External S3':
                 s3_upload_client = external_s3_client; destination_bucket = EXTERNAL_DESTINATION_BUCKET; destination_prefix = EXTERNAL_PREFIX; print(f"Configured for External AWS S3. Target Bucket: {destination_bucket}, Prefix: {destination_prefix}")
            elif DESTINATION == 'Custom S3':
                 s3_upload_client = custom_s3_client; destination_bucket = EXTERNAL_DESTINATION_BUCKET; destination_prefix = EXTERNAL_PREFIX; print(f"Configured for Custom S3. Target Bucket: {destination_bucket}, Prefix: {destination_prefix}") # Updated print

            if not s3_upload_client: raise ValueError(f"S3 Upload client not initialized or invalid config for {DESTINATION}.")
            if not destination_bucket: raise ValueError(f"Destination bucket not configured for {DESTINATION}.")

            final_filename = os.path.basename(output_path)
            output_key_unprefixed = ""
            if KEEP_ORIGINAL_FOLDER_STRUCTURE:
                key_parts = key.split('/'); first_folder = key_parts[0]; modified_first_folder = first_folder
                if SUFFIX_MODE == 'remove' and ORIGINAL_SUFFIX: modified_first_folder = first_folder.replace(f'-{ORIGINAL_SUFFIX}', '')
                elif SUFFIX_MODE == 'add' and NEW_SUFFIX: modified_first_folder = f'{first_folder}-{NEW_SUFFIX}'
                if len(key_parts) > 1: original_dirs_part = os.path.dirname(os.path.join(*key_parts[1:])); key_structure_base = os.path.join(modified_first_folder, original_dirs_part) if original_dirs_part else modified_first_folder
                else: key_structure_base = modified_first_folder
                output_key_unprefixed = os.path.join(key_structure_base, final_filename)
                print(f"Keeping folder structure. Base S3 key structure: {output_key_unprefixed}")
            else:
                output_key_unprefixed = os.path.join(DESTINATION_FOLDER, final_filename) if DESTINATION_FOLDER else final_filename
                print(f"Not keeping folder structure. Base S3 key: {output_key_unprefixed}")

            destination_key = os.path.join(destination_prefix, output_key_unprefixed).replace("\\", "/")
            if destination_key.startswith('/'): destination_key = destination_key[1:]

            print(f"Starting upload to {DESTINATION}:"); print(f"  Source File: '{output_path}'"); print(f"  Destination Bucket: '{destination_bucket}'"); print(f"  Destination Key: '{destination_key}'")
            s3_upload_client.upload_file(output_path, destination_bucket, destination_key) # Raises exceptions on failure
            print(f"Upload to {DESTINATION} completed successfully.")

        # --- SFTP Destination ---
        elif DESTINATION == "SFTP":
            if not paramiko_present: raise ImportError("paramiko library not available for SFTP.")
            sftp_file_to_upload = output_path
            print(f"SFTP Destination: Preparing to upload local file: {sftp_file_to_upload}")
            sftp_target_directory_final = SFTP_TARGET_DIR
            if KEEP_ORIGINAL_FOLDER_STRUCTURE:
                original_path_dirs = os.path.dirname(key)
                if original_path_dirs: sftp_target_directory_final = os.path.join(SFTP_TARGET_DIR, original_path_dirs).replace("\\", "/")
                print(f"SFTP Target Directory (Keeping Structure): {sftp_target_directory_final}")
            else: print(f"SFTP Target Directory (NOT Keeping Structure): {sftp_target_directory_final}")
            upload_to_sftp(sftp_file_to_upload, sftp_target_directory_final, KEEP_ORIGINAL_FOLDER_STRUCTURE) # Raises exceptions on failure

        # --- Azure Destination ---
        elif DESTINATION == 'Azure':
            print("Preparing upload to Azure Blob Storage...")
            if not all([ACCOUNT_NAME, CONTAINER_NAME, SAS_TOKEN]): raise ValueError("Azure config missing.")
            final_filename_for_azure = os.path.basename(output_path)
            blob_name = ""
            if KEEP_ORIGINAL_FOLDER_STRUCTURE:
                key_parts = key.split('/'); first_folder = key_parts[0]; modified_first_folder = first_folder
                if SUFFIX_MODE == 'remove' and ORIGINAL_SUFFIX: modified_first_folder = first_folder.replace(f'-{ORIGINAL_SUFFIX}', '')
                elif SUFFIX_MODE == 'add' and NEW_SUFFIX: modified_first_folder = f'{first_folder}-{NEW_SUFFIX}'
                if len(key_parts) > 1: original_dirs_only = os.path.dirname(os.path.join(*key_parts[1:])); modified_directory_structure = os.path.join(modified_first_folder, original_dirs_only) if original_dirs_only else modified_first_folder
                else: modified_directory_structure = modified_first_folder
                blob_name = os.path.join(modified_directory_structure, final_filename_for_azure)
                print(f"Azure Blob Name (Keeping Structure): {blob_name}")
            else:
                blob_name = os.path.join(DESTINATION_FOLDER, final_filename_for_azure) if DESTINATION_FOLDER else final_filename_for_azure
                print(f"Azure Blob Name (NOT Keeping Structure): {blob_name}")

            blob_name = blob_name.replace("\\", "/")
            if blob_name.startswith('/'): blob_name = blob_name[1:]
            sas_token_corrected = SAS_TOKEN if SAS_TOKEN.startswith('?') else '?' + SAS_TOKEN
            url = f"https://{ACCOUNT_NAME}.blob.core.windows.net/{CONTAINER_NAME}/{urllib.parse.quote(blob_name)}{sas_token_corrected}"
            content_type = 'application/zip' if output_path.endswith('.zip') else 'application/octet-stream'
            headers = {'x-ms-blob-type': 'BlockBlob', 'Content-Type': content_type}
            print(f"Azure Upload Headers: {headers}"); print(f"Uploading '{output_path}' to Azure Blob: {blob_name}")
            print(f"Target URL (SAS hidden): https://{ACCOUNT_NAME}.blob.core.windows.net/{CONTAINER_NAME}/{blob_name}")

            with open(output_path, 'rb') as f: upload_content = f.read()
            http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=certifi.where())
            response = http.request('PUT', url, body=upload_content, headers=headers)
            if not (200 <= response.status < 300):
                error_message = f"Failed to upload to Azure. Status: {response.status}, Reason: {response.data.decode('utf-8', errors='ignore')}"
                print(f"ERROR: {error_message}"); raise Exception(error_message) # Raise exception on failure
            else: print("Upload to Azure Blob Storage successful.")
        else:
            print(f"ERROR: Destination '{DESTINATION}' is not recognized or configured.")
            raise ValueError(f"Unsupported DESTINATION configured: {DESTINATION}") # Treat as config error

        if DELETE_ORIGINAL:
            try:
                print(f"Attempting to delete original S3 object: s3://{bucket}/{key}")
                s3_client.delete_object(Bucket=bucket, Key=key)
                print("Original S3 object deleted successfully.")
            except Exception as e:
                # Log warning but don't fail lambda if only deletion fails
                print(f"Warning: Failed to delete original S3 object s3://{bucket}/{key}. Error: {e}")
                traceback.print_exc()

        print("Lambda execution completed successfully.")
        return { # Return success status
            'statusCode': 200,
            'body': json.dumps(f'File s3://{bucket}/{key} processed successfully and sent to {DESTINATION}.')
        }

    except Exception as e:
        # Catch any exception from the main processing block (transform, zip, upload)
        print(f"FATAL ERROR during Lambda processing for s3://{bucket}/{key}. Error type: {type(e).__name__}, Message: {e}")
        traceback.print_exc()
        # raise the exception to trigger Lambda retries/DLQ.
        raise 

    finally:
        # --- Final Cleanup of Temporary Files ---
        print("Initiating final cleanup of temporary files in /tmp...")
        files_to_clean = {download_path, transformed_path, zip_protected_path, output_path}
        for file_path in files_to_clean:
            if file_path and isinstance(file_path, str) and os.path.exists(file_path) and os.path.isfile(file_path):
                try: os.remove(file_path); print(f"Deleted temporary file: {file_path}")
                except Exception as e: print(f"Warning: Could not delete temporary file {file_path}. Reason: {e}")
        print("Temporary file cleanup finished.")