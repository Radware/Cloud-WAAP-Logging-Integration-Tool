import re

def identify_log_type(key):
    if key.split("/")[-1].startswith("rdwr_log"):
        return "Access"
    else:
        return key.split("/")[-2]

def parse_tenant_name(key):
    return key.split("/")[-4]

def parse_application_name(key):
    tenant_name = parse_tenant_name(key)
    pattern = r"rdwr_event_{}_([^_]+)_(\d{{8}}H\d{{6}})".format(tenant_name)
    match = re.search(pattern, key)
    if match:
        return match.group(1)
    return None

def parse_access_request(request, protocol, host):
    parts = request.split(' ')
    if len(parts) != 3:
        return request, "", ""  # Return the original request if it doesn't match the expected format

    method, uri, http_version = parts
    full_url = "{}://{}{}".format(protocol, host, uri)
    return method, full_url, http_version

def parse_waf_request(request, protocol, host):
    """Parse the WAF request to extract the method, full URL, HTTP version, and specified headers."""

    # Extract method, uri, and HTTP version
    parts = request.split(' ')
    if len(parts) < 3:
        return None, None, None  # Return None if the request doesn't match the expected format

    method, uri, _ = parts[0], parts[1], parts[2]
    full_url = "{}://{}{}".format(protocol, host, uri.split(" ")[0])

    # Extract headers
    headers = {}

    cookie_match = re.search(r'^Cookie:\s(.+)?\r\n', request, re.MULTILINE)
    if cookie_match:
        headers['Cookie'] = cookie_match.group(1)

    user_agent_match = re.search(r'^User-Agent:\s(.+)?\r\n', request, re.MULTILINE)
    if user_agent_match:
        headers['User-Agent'] = user_agent_match.group(1)

    referer_match = re.search(r'^Referer:\s(.+)?\r\n', request, re.MULTILINE)
    if referer_match:
        headers['Referer'] = referer_match.group(1)

    return method, full_url, headers

def determine_severity(action, log_type, severity=None):
    if log_type == "Access":
        if action == "Blocked":
            return "3"  # High severity
        else:
            return "2"  # Low severity
    elif log_type == "WAF":
        # Map WAF severity levels to CEF severity levels
        waf_severity_mapping = {
            "Critical": "10",  # Most severe
            "High": "8",
            "Warning": "5",
            "Low": "3",
            "Info": "1"  # Least severe
        }
        return waf_severity_mapping.get(severity, "0")  # Default to 0 if severity is not recognized
    elif log_type == "Bot":
        return "3"
    elif log_type == "DDoS":
        return "3"
    elif log_type == "WebDDoS":
        return "3"

def sanitize_string(value):
    """Sanitize strings for CEF format by replacing problematic characters."""
    return  value.replace("\r\n\r\n", "").replace("\r\n", " ; ").replace("\n", " ").replace("\r", " ").replace("=", " ").replace("\\", "/")

def flatten_log(log, type=None):
    """
    Flattens the log by extracting the nested enrichmentContainer fields.
    """
    flattened = dict(log)
    enrichment = log.get('enrichmentContainer', {})

    for key, value in enrichment.items():
        new_key = 'enrichmentContainer.' + key
        flattened[new_key] = value

    flattened.pop('enrichmentContainer', None)

    if type == "WebDDoS":
        flattened = flatten_log_further(flattened, type)
        if "latestRealTimeSignature" in log and "Pattern" in log["latestRealTimeSignature"]:
            flattened["latestRealTimeSignature.Pattern"] = flatten_pattern(log["latestRealTimeSignature"]["Pattern"])
        return flatten_headers_list(flattened)
    else:
        return flattened

def flatten_pattern(pattern_list):
    """
    Flattens the latestRealTimeSignature.Pattern list into a formatted string.
    """
    if not isinstance(pattern_list, list):
        return ""  # Return an empty string or some default value if pattern_list is not a list

    pattern_strs = []
    for pattern in pattern_list:
        name = pattern.get("Name", "")
        values = ", ".join(pattern.get("Values", []))
        pattern_strs.append(f"{name}: {values}")
    return "; ".join(pattern_strs)

def flatten_log_further(log, type=None):
    """
    Flattens the log by extracting the nested enrichmentContainer, latestRealTimeSignature, detection, and rps fields.
    Also handles further nested elements within the detection field.
    """
    flattened = dict(log)
    latest_real_time_signature = log.get('latestRealTimeSignature', {})
    for key, value in latest_real_time_signature.items():
        new_key = 'latestRealTimeSignature.' + key
        flattened[new_key] = value
    flattened.pop('latestRealTimeSignature', None)

    # Flatten detection with further nested elements
    detection = log.get('detection', {})
    for key, sub_value in detection.items():
        if isinstance(sub_value, dict):  # Check if the value is a dictionary to further flatten
            for sub_key, sub_sub_value in sub_value.items():
                new_key = 'detection.' + key + '.' + sub_key
                flattened[new_key] = sub_sub_value
        else:
            new_key = 'detection.' + key
            flattened[new_key] = sub_value
    flattened.pop('detection', None)
    print("here")
    # Flatten rps
    rps = log.get('rps', {})
    for key, value in rps.items():
        new_key = 'rps.' + key
        flattened[new_key] = value
    flattened.pop('rps', None)

    return flattened

def flatten_headers_list(flattened_log):
    """
    Flattens the header lists in the latestRealTimeSignature to a single string delimited by a comma.
    """
    header_keys = [
        "latestRealTimeSignature.EligibleHeaders",
        "latestRealTimeSignature.IgnoreHeaders",
        "latestRealTimeSignature.KnownHeaders"
    ]

    for key in header_keys:
        header_list = flattened_log.get(key)
        if isinstance(header_list, list):
            flattened_log[key] = ", ".join(header_list)

    return flattened_log

def flatten_log_headers(log, type=None):
    """
    Flattens the log and then further modifies the header lists in the latestRealTimeSignature.
    """
    flattened = flatten_log_further(log, type)
    pattern = log.get("latestRealTimeSignature", {}).get("Pattern")
    if isinstance(pattern, list):
        flattened["latestRealTimeSignature.Pattern"] = flatten_pattern(pattern)
    return flatten_headers_list(flattened)
