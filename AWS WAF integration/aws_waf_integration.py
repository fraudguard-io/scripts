import logging
import time
import requests
import boto3
import ipaddress
from botocore.exceptions import BotoCoreError, ClientError

# Configuration (ensure these are securely managed)
FRAUDGUARD_RISK_LEVEL = 5  # Change risk level as needed
# Reference: https://blog.fraudguard.io/misc/2024/04/06/use-cases-article.html
FRAUDGUARD_API_URL = f"https://api.fraudguard.io/raw-lists-by-risk/{FRAUDGUARD_RISK_LEVEL}"
FRAUDGUARD_USERNAME = "your_API_username"
FRAUDGUARD_PASSWORD = "your_API_password"
AWS_REGION = "us-east-1"
IP_SET_SCOPE = "REGIONAL"  # Use "CLOUDFRONT" for global IP sets
IPV4_SET_NAME = "YourIPv4SetName"
IPV6_SET_NAME = "YourIPv6SetName"
LOG_FILE = "aws_waf_integration.log"

# Limits for testing
MAX_IPS = 100  # Set to None to ingest all IPs
PAGE_LIMIT = 1000  # FraudGuard API max limit

# Logging setup
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# AWS WAF client
waf_client = boto3.client("wafv2", region_name=AWS_REGION)

def fetch_fraudguard_ips(max_ips=10000):
    """Fetch IPv4 and IPv6 addresses separately from FraudGuard.io, enforcing MAX_IPS limit."""
    def fetch_ips(ipv4, ipv6, max_ips):
        offset = 0
        all_ips = []
        total_count = None

        while total_count is None or offset < total_count:
            try:
                params = {
                    "offset": offset,
                    "limit": PAGE_LIMIT,
                    "cidr": "true",
                    "ipv6": str(ipv6).lower(),
                    "ipv4": str(ipv4).lower(),
                }
                response = requests.get(
                    FRAUDGUARD_API_URL,
                    auth=(FRAUDGUARD_USERNAME, FRAUDGUARD_PASSWORD),
                    params=params,
                )
                response.raise_for_status()

                ip_list = response.json()
                if not ip_list:
                    break

                if total_count is None:
                    total_count = int(response.headers.get("X-Total-Count", 0))
                    logging.info(f"Total {('IPv6' if ipv6 else 'IPv4')} IPs available: {total_count}")

                all_ips.extend(ip_list)
                offset += PAGE_LIMIT

                # Stop if MAX_IPS is reached
                if max_ips and len(all_ips) >= max_ips:
                    logging.warning(f"Reached MAX_IPS limit ({max_ips} IPs), stopping additional fetches.")
                    all_ips = all_ips[:max_ips]  # Trim extra IPs
                    break

                logging.info(f"Fetched {len(ip_list)} {('IPv6' if ipv6 else 'IPv4')} IPs (offset={offset}/{total_count}).")

                time.sleep(5)

            except requests.RequestException as e:
                logging.error(f"Error fetching {('IPv6' if ipv6 else 'IPv4')} IPs from FraudGuard.io: {e}")
                raise

        return all_ips

    # Fetch separately to ensure both IPv4 and IPv6 are retrieved correctly
    ipv4_ips = fetch_ips(ipv4=True, ipv6=False, max_ips=max_ips)
    ipv6_ips = fetch_ips(ipv4=False, ipv6=True, max_ips=max_ips)

    return ipv4_ips + ipv6_ips  # Merge both lists

def format_ips(ip_list):
    """Ensure all IPs are correctly categorized into IPv4 and IPv6 lists with required CIDR notation."""
    ipv4_list = []
    ipv6_list = []

    for ip in ip_list:
        try:
            ip_obj = ipaddress.ip_network(ip, strict=False)  # Handle CIDR if present

            if ip_obj.version == 4:
                formatted_ip = f"{ip_obj.network_address}/32"
                ipv4_list.append(formatted_ip)
            else:
                formatted_ip = f"{ip_obj.network_address}/64"
                ipv6_list.append(formatted_ip)

        except ValueError:
            logging.warning(f"Invalid IP detected and skipped: {ip}")

    logging.info(f"IPv4 Count: {len(ipv4_list)}, IPv6 Count: {len(ipv6_list)}")  # Debugging

    return ipv4_list, ipv6_list

def get_ip_set(name):
    """Retrieve the IP set information and lock token."""
    try:
        response = waf_client.list_ip_sets(Scope=IP_SET_SCOPE)
        for ip_set in response.get("IPSets", []):
            if ip_set["Name"] == name:
                ip_set_details = waf_client.get_ip_set(
                    Name=name,
                    Scope=IP_SET_SCOPE,
                    Id=ip_set["Id"]
                )
                logging.info(f"Retrieved IP set {name} with ID: {ip_set['Id']} and LockToken: {ip_set_details['LockToken']}")
                return {
                    "Id": ip_set["Id"],
                    "LockToken": ip_set_details["LockToken"]
                }
        return None
    except (BotoCoreError, ClientError) as e:
        logging.error(f"Error retrieving IP set: {e}")
        raise

def validate_ip_set(name):
    """Validate that the IP set exists in AWS WAF."""
    try:
        ip_set = get_ip_set(name)
        if not ip_set:
            logging.error(f"IP set {name} does not exist. Please create it in AWS WAF.")
            raise Exception(f"IP set {name} not found.")
        logging.info(f"IP set {name} found with ID: {ip_set['Id']}")
        return ip_set
    except Exception as e:
        logging.error(f"Validation failed for IP set {name}: {e}")
        raise

def update_ip_set(ip_set_name, ip_set_id, lock_token, new_ips, max_ips=10000):
    """Update the IP set with the provided IPs, enforcing AWS WAF limits."""
    try:
        # Trim the list if it exceeds AWS WAF's max capacity
        if len(new_ips) > max_ips:
            logging.warning(f"Trimming IP list for {ip_set_name} from {len(new_ips)} to {max_ips} (AWS WAF limit).")
            new_ips = new_ips[:max_ips]

        logging.info(f"Updating {ip_set_name} with {len(new_ips)} IPs.")
        waf_client.update_ip_set(
            Name=ip_set_name,
            Scope=IP_SET_SCOPE,
            Id=ip_set_id,
            LockToken=lock_token,
            Addresses=new_ips,
        )
        logging.info(f"Successfully updated {ip_set_name} with {len(new_ips)} IPs.")

    except (BotoCoreError, ClientError) as e:
        logging.error(f"Error updating IP set {ip_set_name}: {e}")
        raise

def main():
    logging.info("Starting AWS WAF integration script.")

    try:
        # Determine the max allowed IPs for AWS WAF (or testing MAX_IPS override)
        max_ips = MAX_IPS if MAX_IPS else (100000 if IP_SET_SCOPE == "CLOUDFRONT" else 10000)

        # Fetch only what AWS WAF allows
        fraudguard_ips = fetch_fraudguard_ips(max_ips=max_ips)

        # Separate IPv4 and IPv6
        ipv4_ips, ipv6_ips = format_ips(fraudguard_ips)

        # Validate and update IPv4 IP Set
        ipv4_set = validate_ip_set(IPV4_SET_NAME)
        update_ip_set(IPV4_SET_NAME, ipv4_set["Id"], ipv4_set["LockToken"], ipv4_ips, max_ips)

        # Validate and update IPv6 IP Set
        ipv6_set = validate_ip_set(IPV6_SET_NAME)
        update_ip_set(IPV6_SET_NAME, ipv6_set["Id"], ipv6_set["LockToken"], ipv6_ips, max_ips)

    except Exception as e:
        logging.error(f"Script terminated with error: {e}")
    else:
        logging.info("AWS WAF integration script completed successfully.")

if __name__ == "__main__":
    main()