import logging
import time
import requests
import google.auth
from google.auth.transport.requests import AuthorizedSession
from google.cloud import compute_v1

# Configuration
FRAUDGUARD_RISK_LEVEL = 5  # Change risk level as needed
FRAUDGUARD_API_URL = "https://api.fraudguard.io/raw-lists-by-risk/{}".format(FRAUDGUARD_RISK_LEVEL)
FRAUDGUARD_USERNAME = "your_API_username"
FRAUDGUARD_PASSWORD = "your_API_password"
GCP_PROJECT_ID = "your-gcp-project-id"
SECURITY_POLICY_NAME = "your-security-policy-name"
LOG_FILE = "gcp_waf_integration.log"

# Limits for testing
MAX_IPS = 1000  # Set to None to ingest all IPs
PAGE_LIMIT = 1000  # FraudGuard API max limit

# Logging setup
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def get_authenticated_session():
    """Authenticate with Google Cloud API."""
    credentials, _ = google.auth.default()
    return AuthorizedSession(credentials)

def fetch_fraudguard_ips():
    """Fetch IPs from FraudGuard.io API with pagination support."""
    offset = 0
    all_ips = []
    while True:
        try:
            params = {
                "offset": offset,
                "limit": PAGE_LIMIT,
                "cidr": "false",
                "ipv4": "true",
                "ipv6": "false",
            }
            response = requests.get(
                FRAUDGUARD_API_URL,
                auth=(FRAUDGUARD_USERNAME, FRAUDGUARD_PASSWORD),
                params=params,
            )
            response.raise_for_status()
            ip_list = response.text.splitlines()
            if not ip_list:
                break

            all_ips.extend(ip_list)
            offset += PAGE_LIMIT

            if MAX_IPS and len(all_ips) >= MAX_IPS:
                all_ips = all_ips[:MAX_IPS]
                break

            logging.info(f"Fetched {len(ip_list)} IPs (offset={offset}).")
            time.sleep(5)
        except requests.RequestException as e:
            logging.error(f"Error fetching IPs from FraudGuard.io: {e}")
            break
    return all_ips

def update_gcp_waf_rules(ip_list):
    """Update GCP Security Policy with FraudGuard.io IP list."""
    try:
        client = compute_v1.SecurityPoliciesClient()
        security_policy = client.get(project=GCP_PROJECT_ID, security_policy=SECURITY_POLICY_NAME)

        existing_rules = security_policy.rules or []
        new_rule = compute_v1.SecurityPolicyRule(
            priority=1000,
            action="deny(403)",
            match=compute_v1.SecurityPolicyRuleMatcher(
                config=compute_v1.SecurityPolicyRuleMatcherConfig(
                    src_ip_ranges=ip_list[:MAX_IPS]  # Limit IPs
                )
            )
        )
        
        existing_rules.append(new_rule)
        security_policy.rules = existing_rules
        client.patch(project=GCP_PROJECT_ID, security_policy=SECURITY_POLICY_NAME, security_policy_resource=security_policy)
        logging.info("GCP WAF rules updated successfully!")
    except Exception as e:
        logging.error(f"Error updating GCP WAF rules: {e}")

if __name__ == "__main__":
    logging.info("Starting GCP WAF FraudGuard.io integration script.")
    fraudguard_ips = fetch_fraudguard_ips()
    if fraudguard_ips:
        update_gcp_waf_rules(fraudguard_ips)
    logging.info("GCP WAF integration script execution completed.")