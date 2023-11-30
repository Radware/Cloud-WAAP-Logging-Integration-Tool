import json
from datetime import datetime
import time
import re
from cwaf_log_tools import *



def convert_to_leef(log, log_type, application_name=None, tenant_name=None):
    if log_type == "Access":
        # LEEF Header
        leef_header = "LEEF:2.0|Radware|CloudWAF|1.0|AccessLog|"

        # Convert the time format to epoch time
        log_time = datetime.strptime(log['time'], '%d/%b/%Y:%H:%M:%S %z')
        epoch_time = int(log_time.timestamp() * 1000)  # Convert to milliseconds

        method, full_url, http_version = parse_access_request(log['request'], log['protocol'], log['host'])

        # Map the fields from your log to LEEF fields
        fields_mapping = {
            "action": log.get('action', ''),  # Action taken
            "dstPort": log.get('destination_port', ''),
            "dst": log.get('destination_ip', ''),
            "dhost": log.get('host', ''),
            "proto": log.get('protocol', ''),
            "url": full_url,  # Assuming 'full_url' field contains the complete URL
            "method": method,  # Assuming 'method' field exists for HTTP method
            "devTime": str(epoch_time),  # Device time, assuming it's the request time
            "srcPort": log.get('source_port', ''),
            "src": log.get('source_ip', ''),
            "bytesIn": log.get('http_bytes_in', ''),
            "bytesOut": log.get('http_bytes_out', ''),
            "userAgent": log.get('user_agent', ''),
            "referrer": log.get('referrer', ''),
            "cookie": log.get('cookie', ''),
            "responseCode": log.get('response_code', ''),
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

        # Construct the LEEF log string
        leef_log = leef_header + str(epoch_time)
        for key, value in fields_mapping.items():
            if value and value != "-":
                leef_log += "\\t{}={}".format(key, value)

    if log_type == "WAF":
        # LEEF Header for WAF Logs
        leef_header = "LEEF:2.0|Radware|CloudWAF|1.0|WAFLog|"

        full_url = None  # Initialize the variable with None
        if 'request' in log:
            method, full_url, headers = parse_waf_request(log['request'], log['protocol'], log['host'])

        flattened_log = flatten_log(log)
        flattened_log["application_name"] = application_name
        flattened_log["tenant_name"] = tenant_name
        # Map the fields from your log to LEEF fields
        fields_mapping = {
            "act": log.get('action', ''),
            "dstPort": log.get('destination_port', ''),
            "dst": log.get('destination_ip', ''),
            "dhost": log.get('host', ''),
            "proto": log.get('protocol', ''),
            "request": full_url,
            "method": log.get('method', ''),
            "devTime": log.get('Time', ''),
            "srcPort": log.get('source_port', ''),
            "src": log.get('externalIp', ''),
            "reason": log.get('title', ''),
            "referer": log.get('referrer', ''),
            "cookie": log.get('Cookie', ''),
            "userAgent": log.get('User_agent', ''),
            "sev": log.get('severity', ''),
            "rdwrCldCountryCode": log.get("enrichmentContainer.geoLocation.countryCode", ''),
            "rdwrCldTenantName": log.get('tenant_name', ''),
            "rdwrCldAppName": log.get('application_name', ''),
            "rdwrCldAppId": log.get("enrichmentContainer.applicationId", ''),
            "rdwrCldContractId": log.get("enrichmentContainer.contractId", ''),
            "rdwrCldTenantId": log.get("enrichmentContainer.tenant", ''),
            "rdwrCldModule": log.get('targetModule', ''),
            "rdwrCldWafTransId": log.get('transId', ''),
            "rdwrCldPath": log.get('appPath', ''),
            "rdwrCldViolationCategory": log.get('violationCategory', ''),
            "rdwrCldViolationDetails": log.get('violationDetails', ''),
            "rdwrCldViolationType": log.get('violationType', ''),
            "rdwrCldThreatCategory": log.get('enrichmentContainer.owaspCategory2021', ''),
            "rdwrCldParamName": log.get('paramName', ''),
            "rdwrCldParamType": log.get('paramType', ''),
            "rdwrCldParamValue": log.get('paramValue', ''),
            "rdwrCldRuleId": log.get('RuleID', '')
        }

        # Construct the LEEF log string
        leef_log = leef_header + log['Time']
        for key, value in fields_mapping.items():
            if value and value != "-":
                leef_log += "\\t{}={}".format(key, value)

        return leef_log


    elif log_type == "Bot":

        leef_header = "LEEF:2.0|Radware|CloudWAF|1.0|BotLog|"

        # Convert the time to epoch format
        epoch_time = str(int(log['time']))
        log["application_name"] = application_name
        log["tenant_name"] = tenant_name

        # Map the fields from your log to LEEF fields
        fields_mapping = {
            "act": log.get('action', ''),
            "dhost": log.get('site', ''),
            "request": log.get('url', ''),
            "devTime": str(epoch_time),
            "src": log.get('ip', ''),
            "cat": log.get('violation_reason', ''),
            "referer": log.get('referrer', ''),
            "userAgent": log.get('ua', ''),
            "rdwrCldCountryCode": log.get('enrichmentContainer.geoLocation.countryCode', ''),
            "rdwrCldTenantName": tenant_name or log.get('tenant_name', ''),
            "rdwrCldAppName": application_name or log.get('application_name', ''),
            "rdwrCldTid": log.get('tid', ''),
            "rdwrCldStatus": log.get('status', ''),
            "rdwrCldBotCategory": log.get('bot_category', ''),
            "rdwrCldSessionCookie": log.get('session_cookie', ''),
            "rdwrCldHeaders": log.get('headers', ''),
            "rdwrCldPolicyId": log.get('policy_id', ''),
            "rdwrCldSignaturePattern": log.get('signature_pattern', '')
        }

        # Construct the LEEF log string
        leef_log = leef_header + str(epoch_time)
        for key, value in fields_mapping.items():
            if value and value != "-":
                leef_log += "\\t{}={}".format(key, value)

        return leef_log

    elif log_type == "DDoS":
        # LEEF Header for DDoS Logs
        leef_header = "LEEF:2.0|Radware|CloudWAF|1.0|DDoSLog|"

        # Convert the time to epoch
        epoch_time = int(time.mktime(time.strptime(log['time'], "%d-%m-%Y %H:%M:%S")))

        # Flatten the log
        flattened_log = flatten_log(log)
        flattened_log["application_name"] = application_name
        flattened_log["tenant_name"] = tenant_name
        # Map the fields from your log to LEEF fields
        fields_mapping = {
            "act": log.get('action', ''),
            "dst": log.get('destinationIP', ''),
            "dstPort": log.get('destinationPort', ''),
            "proto": log.get('protocol', ''),
            "devTime": str(epoch_time),
            "src": log.get('sourceIP', ''),
            "srcPort": log.get('sourcePort', ''),
            "reason": log.get('name', ''),
            "cat": log.get('category', ''),
            "rdwrCldCountryCode": log.get('enrichmentContainer.geoLocation.countryCode', ''),
            "rdwrCldTenantName": tenant_name or log.get('tenant_name', ''),
            "rdwrCldAppName": application_name or log.get('application_name', ''),
            "rdwrCldAppId": log.get('enrichmentContainer.applicationId', ''),
            "rdwrCldContractId": log.get('enrichmentContainer.contractId', ''),
            "rdwrCldTenantId": log.get('enrichmentContainer.tenant', ''),
            "rdwrCldTotalVolume": log.get('totalVolume', ''),
            "rdwrCldTotalPackets": log.get('totalPackets', ''),
            "rdwrCldID": log.get('ID', '')
        }

        # Construct the LEEF log string
        leef_log = leef_header + str(epoch_time)
        for key, value in fields_mapping.items():
            if value and value != "-":
                leef_log += "\\t{}={}".format(key, value)

        return leef_log

    elif log_type == "WebDDoS":
        # LEEF Header for WebDDoS Logs
        leef_header = "LEEF:2.0|Radware|CloudWAF|1.0|WebDDoSLog|"

        # Flatten the log if necessary and handle missing fields
        flattened_log = flatten_log(log, "WebDDoS")
        flattened_log["application_name"] = application_name
        flattened_log["tenant_name"] = tenant_name
        # Map the fields from your log to LEEF fields
        fields_mapping = {
            "act": flattened_log.get('action', ''),
            "dhost": flattened_log.get('host', ''),
            "rdwrCldAppName": flattened_log.get('applicationName', '') or application_name ,
            "rdwrCldCountryCode": flattened_log.get('enrichmentContainer.geoLocation.countryCode', ''),
            "rdwrCldContractId": flattened_log.get('enrichmentContainer.contractId', ''),
            "rdwrCldApplicationId": flattened_log.get('enrichmentContainer.applicationId', ''),
            "rdwrCldTenantId": flattened_log.get('enrichmentContainer.tenant', ''),
            "rdwrCldTenantName": tenant_name or flattened_log.get('tenant_name', ''),
            "rdwrCldAttackId": flattened_log.get('attackID', ''),
            "rdwrCldStartTime": flattened_log.get('startTime', ''),
            "rdwrCldEndTime": flattened_log.get('endTime', ''),
            "rdwrCldDuration": flattened_log.get('Duration', ''),
            "rdwrCldAttackVector": flattened_log.get('attackVector', ''),
            "rdwrCldStatus": flattened_log.get('status', ''),
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

        # Construct the LEEF log string
        leef_log = leef_header
        for key, value in fields_mapping.items():
            if value and value != "-":
                leef_log += "\\t{}={}".format(key, value)

        return leef_log
