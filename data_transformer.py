import json
import gzip
from cloudwaap_log_utils import CloudWAAPProcessor

def decompress_gzip(file_path):
    """Decompress a gzip file and return the content as a string."""
    with gzip.open(file_path, 'rt') as file:
        return file.read()

def convert_to_json(data):
    """Convert string data to JSON."""
    return json.loads(data)

def convert_to_ndjson(json_data):
    """Convert a list of JSON objects to NDJSON format."""
    return '\n'.join(json.dumps(record) for record in json_data)

def enrich_log_data(json_data, log_type, application_name, tenant_name):
    """Enrich each log entry with additional metadata."""
    for entry in json_data:
        entry['logType'] = log_type
        if 'applicationName' not in entry:
            entry['applicationName'] = application_name
        if 'tenantName' not in entry:
            entry['tenantName'] = tenant_name
    return json_data

def process_file(file_path, output_format, enrich=False):
    """Process the file based on the specified format and whether to enrich."""
    data = decompress_gzip(file_path)
    json_data = convert_to_json(data)

    if enrich:
        log_type = CloudWAAPProcessor.identify_log_type(file_path)
        application_name = CloudWAAPProcessor.parse_application_name(file_path)
        tenant_name = CloudWAAPProcessor.parse_tenant_name(file_path)
        json_data = enrich_log_data(json_data, log_type, application_name, tenant_name)

    if output_format == 'ndjson':
        return convert_to_ndjson(json_data)
    elif output_format == 'json':
        return json.dumps(json_data)

    return data  # return decompressed data without further processing if no specific format is requested
