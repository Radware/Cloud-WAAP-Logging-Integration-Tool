import json
from datetime import datetime
import time
import re
from cwaf_log_tools import *

def convert_to_cef(log, log_type, application_name=None, tenant_name=None):
    # Basic CEF header
    if log_type == "Access":
        cef_header = "CEF:0|Radware|CloudWAF|1.0|1|AccessLog|{}|".format(
            determine_severity(log['action'], "Access")  # Severity (example function to determine severity)
        )

        # Convert the time format to epoch time
        log_time = datetime.strptime(log['time'], '%d/%b/%Y:%H:%M:%S %z')
        epoch_time = int(log_time.timestamp() * 1000)  # Convert to milliseconds

        # Parse the request field
        method, full_url, http_version = parse_access_request(log['request'], log['protocol'], log['host'])

        # Extension fields
        fields_mapping = {
            "act": log.get('action', ''),
            "dpt": log.get('destination_port', ''),
            "dst": log.get('destination_ip', ''),
            "dhost": log.get('host', ''),
            "app": log.get('protocol', ''),
            "request": full_url,
            "requestMethod": method,
            "rt": epoch_time,
            "spt": log.get('source_port', ''),
            "src": log.get('source_ip', ''),
            "in": log.get('http_bytes_in', ''),
            "out": log.get('http_bytes_out', ''),
            "requestClientApplication": log.get('user_agent', ''),
            "requestContext": log.get('referrer', ''),
            "requestCookies": log.get('cookie', ''),
            "rdwrCldResponseCode": log.get('response_code', ''),
            "rdwrCldCountryCode": log.get('country_code', ''),
            "rdwrCldTenantName": log.get('tenant_name', ''),
            "rdwrCldAppName": log.get('application_name', ''),
            "rdwrCldAppId": log.get('application_id', ''),
            "rdwrCldRequestTime": log.get('request_time', ''),
            "rdwrCldDirectory": log.get('directory', ''),
            "rdwrCldAcceptLanguage": log.get('accept_language', ''),
            "rdwrCldXff": log.get('x-forwarded-for', ''),
            "rdwrCldHttpVersion": http_version
        }

        cef_extensions = []
        for cef_key, value in fields_mapping.items():
            if value != "-" and value:  # Skip if the value is exactly "-" or is empty
                sanitized_value = sanitize_string(str(value))
                cef_extensions.append("{}={}".format(cef_key, sanitized_value))

        return cef_header + ' '.join(cef_extensions)

    elif log_type == "WAF":
        cef_header = "CEF:0|Radware|CloudWAF|1.0|2|WAFLog|{}|".format(
            determine_severity(log['severity'], "WAF")
        )
        full_url = None  # Initialize the variable with None
        if 'request' in log:
            method, full_url, headers = parse_waf_request(log['request'], log['protocol'], log['host'])

        # Base extension fields specific to WAF logs
        cef_extensions = []

        flattened_log = flatten_log(log)
        flattened_log["application_name"] = application_name
        flattened_log["tenant_name"] = tenant_name
        # Define a mapping of CEF extension keys to log keys
        fields_mapping = {
            "act": "action",
            "dpt": "destinationPort",
            "dst": "externalIp",
            "dhost": "host",
            "app": "protocol",
            "request": full_url,
            "requestMethod": "method",
            "rt": "receivedTimeStamp",
            "spt": "sourcePort",
            "src": "sourceIp",
            "reason": "title",
            "requestContext": headers.get('referrer', ''),
            "requestCookies": headers.get('cookie', ''),
            "requestClientApplication": headers.get('user_agent', ''),
            "rdwrCldCountryCode": "enrichmentContainer.geoLocation.countryCode",
            "rdwrCldTenantName": "tenant_name",
            "rdwrCldAppName": "application_name",
            "rdwrCldAppId": "enrichmentContainer.applicationId",
            "rdwrCldContractId": "enrichmentContainer.contractId",
            "rdwrCldTenantId": "enrichmentContainer.tenant",
            "rdwrCldModule": "targetModule",
            "rdwrCldWafTransId": "transId",
            "rdwrCldPath": "URI",
            "rdwrCldViolationCategory": "violationCategory",
            "rdwrCldViolationDetails": "violationDetails",
            "rdwrCldViolationType": "violationType",
            "rdwrCldThreatCategory": "enrichmentContainer.owaspCategory2021",
            "rdwrCldParamName": "paramName",
            "rdwrCldParamType": "paramType",
            "rdwrCldParamValue": "paramValue",
            "rdwrCldRuleId": "RuleID"
        }

        for cef_key, log_key in fields_mapping.items():
            value = flattened_log.get(log_key, None)
            if value is None:
                continue
            sanitized_value = sanitize_string(str(value))
            cef_extensions.append("{}={}".format(cef_key, sanitized_value))

        return cef_header + ' '.join(cef_extensions)


    elif log_type == "Bot":

        # Convert the time to epoch format
        epoch_time = str(int(log['time']))

        # CEF header
        cef_header = "CEF:0|Radware|CloudWAF|1.0|3|BotLog|{}|".format(
            determine_severity(log['action'], "Bot")  # Assuming you have a severity function for bot logs
        )

        log["application_name"] = application_name
        log["tenant_name"] = tenant_name
        # Define a mapping of CEF extension keys to log keys
        fields_mapping = {
            "act": "action",
            "dhost": "site",
            "request": "url",
            "rt": epoch_time,
            "src": "ip",
            "reason": "violation_reason",
            "requestContext": "referrer",
            "requestClientApplication": "ua",
            "rdwrCldCountryCode": "country_code",
            "rdwrCldTenantName": "tenant_name",  # Assuming you have a way to get tenant_name
            "rdwrCldAppName": "application_name",  # Assuming you have a way to get application_name
            "rdwrCldTid": "tid",
            "rdwrCldStatus": "status",
            "rdwrCldBotCategory": "bot_category",
            "rdwrCldSessionCookie": "session_cookie",
            "rdwrCldHeaders": "headers",
            "rdwrCldPolicyId": "policy_id",
            "rdwrCldSignaturePattern": "signature_pattern"
        }

        cef_extensions = []
        for cef_key, log_key in fields_mapping.items():
            value = log.get(log_key, None)
            if not value:
                continue
            sanitized_value = sanitize_string(str(value))
            cef_extensions.append("{}={}".format(cef_key, sanitized_value))

        return cef_header + ' '.join(cef_extensions)

    elif log_type == "DDoS":
        # Generate the CEF format
        cef_header = "CEF:0|Radware|CloudWAF|1.0|4|DDoSLog|{}|".format("3")
        cef_extensions = []
        # Convert the time to epoch
        epoch_time = int(time.mktime(time.strptime(log['time'], "%d-%m-%Y %H:%M:%S")))

        # Flatten the log
        flattened_log = flatten_log(log)
        flattened_log["application_name"] = application_name
        flattened_log["tenant_name"] = tenant_name
        # Define the mapping
        fields_mapping = {
            "act": "action",
            "dst": "destinationIP",
            "dpt": "destinationPort",
            "app": "protocol",
            "rt": epoch_time,
            "src": "sourceIP",
            "spt": "sourcePort",
            "reason": "name",
            "rdwrCldCountryCode": "enrichmentContainer.geoLocation.countryCode",
            "rdwrCldTenantName": "tenant_name",
            "rdwrCldAppName": "application_name",
            "rdwrCldAppId": "enrichmentContainer.applicationId",
            "rdwrCldContractId": "enrichmentContainer.contractId",
            "rdwrCldTenantId": "enrichmentContainer.tenant",
            "rdwrCldCategory": "category",
            "rdwrCldTotalVolume": "totalVolume",
            "rdwrCldTotalPackets": "totalPackets",
            "rdwrCldID": "ID"
        }



        for cef_key, log_key in fields_mapping.items():
            sanitized_value = sanitize_string(str(flattened_log.get(log_key, '')))
            cef_extensions.append("{}={}".format(cef_key, sanitized_value))

        return cef_header + ' '.join(cef_extensions)

    elif log_type == "WebDDoS":
        # Convert the time to epoch
        #epoch_time = int(time.mktime(time.strptime(log['time'], "%d-%m-%Y %H:%M:%S")))

        # Generate the CEF format
        cef_header = "CEF:0|Radware|CloudWAF|1.0|5|WebDDoSLog|{}|".format("10")
        cef_extensions = []

        # Flatten the log
        flattened_log = flatten_log(log, "WebDDoS")
        flattened_log["application_name"] = application_name
        flattened_log["tenant_name"] = tenant_name
        # Define the mapping
        fields_mapping = {
            "act": "action",
            "dhost": "host",
            "rdwrCldAppName": "applicationName", # Should add conditional that if applicationName field does not exist then use application_name
            "rdwrCldCountryCode": "enrichmentContainer.geoLocation.countryCode",
            "rdwrCldContractId": "enrichmentContainer.contractId",
            "rdwrCldApplicationId": "enrichmentContainer.applicationId",
            "rdwrCldTenantId": "enrichmentContainer.tenant",
            "rdwrCldTenantName": "tenant_name",
            "rdwrCldAttackId": "attackID",
            "rdwrCldStartTime": "startTime",
            "rdwrCldEndTime": "endTime",
            "rdwrCldDuration": "Duration",
            "rdwrCldAttackVector": "attackVector",
            "rdwrCldStatus": "status",
            "rdwrCldLrtsAllowedTopOfBufferMisses": "latestRealTimeSignature.AllowedTopOfBufferMisses",
            "rdwrCldLrtsEligibleHeaders": "latestRealTimeSignature.EligibleHeaders",
            "rdwrCldLrtsIgnoreHeaders": "latestRealTimeSignature.IgnoreHeaders",
            "rdwrCldLrtsIsCharacterProb": "latestRealTimeSignature.IsCharacterizationProbability",
            "rdwrCldLrtsKnownHeaders": "latestRealTimeSignature.KnownHeaders",
            "rdwrCldLrtsPattern": "latestRealTimeSignature.Pattern",
            "rdwrCldDetAppBehavAttackThresh": "rdwrCldDetAppBehavAttackThresh",
            "rdwrCldRpsInbound": "Rps.Inbound",
            "rdwrCldRpsBlocked": "latestRealTimeSignature.Pattern",
            "rdwrCldRpsClean": "Rps.clean",
            "rdwrCldRpsAttackThresh": "Rps.attackThreshold"
        }

        for cef_key, log_key in fields_mapping.items():

            sanitized_value = sanitize_string(str(flattened_log.get(log_key, '')))
            cef_extensions.append("{}={}".format(cef_key, sanitized_value))

        return cef_header + ' '.join(cef_extensions)


