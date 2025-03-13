import requests
import json
import os
import logging
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient

# Configuration
SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")
RESOURCE_GROUP_NAME = os.getenv("AZURE_RESOURCE_GROUP")
WAF_POLICY_NAME = os.getenv("AZURE_WAF_POLICY_NAME")
FRAUDGUARD_USERNAME = os.getenv("FRAUDGUARD_USERNAME")
FRAUDGUARD_PASSWORD = os.getenv("FRAUDGUARD_PASSWORD")
FRAUDGUARD_RISK_LEVEL = os.getenv("FRAUDGUARD_RISK_LEVEL", "5")  # Default risk level
LOG_FILE = os.getenv("AZURE_WAF_LOG_FILE", "azure_waf_integration.log")

# API Request Parameters
OFFSET = 0
LIMIT = 10000  # Max IPs per request
CIDR = "false"
IPV4 = "true"
IPV6 = "false"

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# FraudGuard API Endpoint
FRAUDGUARD_API_URL = (
    f"https://api.fraudguard.io/raw-lists-by-risk/{FRAUDGUARD_RISK_LEVEL}"
    f"?offset={OFFSET}&limit={LIMIT}&cidr={CIDR}&ipv4={IPV4}&ipv6={IPV6}"
)

# Authenticate with Azure
credential = DefaultAzureCredential()
network_client = NetworkManagementClient(credential, SUBSCRIPTION_ID)

def get_fraudguard_blacklist():
    """Fetches blacklisted IPs from FraudGuard.io API with pagination support."""
    auth = (FRAUDGUARD_USERNAME, FRAUDGUARD_PASSWORD)
    
    ip_list = []
    offset = 0
    while True:
        url = (
            f"https://api.fraudguard.io/raw-lists-by-risk/{FRAUDGUARD_RISK_LEVEL}"
            f"?offset={offset}&limit={LIMIT}&cidr={CIDR}&ipv4={IPV4}&ipv6={IPV6}"
        )
        response = requests.get(url, auth=auth)
        
        if response.status_code == 200:
            data = response.text.splitlines()
            if not data:
                break  # No more IPs to fetch
            ip_list.extend(data)
            offset += LIMIT
        else:
            logging.error(f"Error fetching blacklist: {response.status_code} - {response.text}")
            break
    
    logging.info(f"Fetched {len(ip_list)} IPs from FraudGuard.io.")
    return ip_list

def update_azure_waf_rules(ip_list):
    """Updates Azure WAF Custom Rules with the new IP blacklist."""
    try:
        waf_policy = network_client.web_application_firewall_policies.get(
            RESOURCE_GROUP_NAME, WAF_POLICY_NAME
        )
        
        waf_policy.custom_rules = [
            {
                "name": "FraudGuardBlacklist",
                "priority": 1,
                "ruleType": "MatchRule",
                "action": "Block",
                "matchConditions": [
                    {
                        "matchVariables": [{"variableName": "RemoteAddr"}],
                        "operator": "IPMatch",
                        "matchValues": ip_list[:10000]  # Max 10,000 IPs
                    }
                ]
            }
        ]
        
        network_client.web_application_firewall_policies.begin_create_or_update(
            RESOURCE_GROUP_NAME, WAF_POLICY_NAME, waf_policy
        ).result()
        logging.info("Azure WAF rules updated successfully!")
    except Exception as e:
        logging.error(f"Error updating Azure WAF rules: {str(e)}")

if __name__ == "__main__":
    logging.info("Starting Azure WAF FraudGuard.io integration script.")
    ip_blacklist = get_fraudguard_blacklist()
    if ip_blacklist:
        update_azure_waf_rules(ip_blacklist)
    logging.info("Azure WAF integration script execution completed.")
