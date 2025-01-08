import argparse
import requests
import json
import os
import re

# Load configuration
CONFIG_FILE = os.path.expanduser("~/.fraudguard-cli-config")
if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE) as f:
        config = dict(line.strip().split('=') for line in f if '=' in line)
else:
    print("Error: Configuration file not found. Please create ~/.fraudguard-cli-config with your API credentials.")
    exit(1)

USERNAME = config.get('USERNAME')
PASSWORD = config.get('PASSWORD')

API_URL = "https://api.fraudguard.io"
PAGE_LIMIT = 1000  # Number of IPs per page

# Helper functions
def is_valid_ip(ip):
    """Validate IPv4 and IPv6 addresses."""
    ipv4_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    ipv6_pattern = re.compile(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
    return ipv4_pattern.match(ip) or ipv6_pattern.match(ip)

def validate_ips(ip_list):
    """Validate a list of IPs."""
    valid_ips = [ip for ip in ip_list if is_valid_ip(ip)]
    invalid_ips = [ip for ip in ip_list if not is_valid_ip(ip)]
    if invalid_ips:
        print(f"Warning: The following IPs are invalid and will be skipped: {', '.join(invalid_ips)}")
    return valid_ips

def make_request(method, endpoint, payload=None, verbose=False):
    """Make a request to the FraudGuard API."""
    url = f"{API_URL}/{endpoint}"
    headers = {"Content-Type": "application/json"}
    try:
        if method == "GET":
            response = requests.get(url, auth=(USERNAME, PASSWORD))
        elif method in ["POST", "DELETE"]:
            response = requests.request(method, url, auth=(USERNAME, PASSWORD), json=payload, headers=headers)
        else:
            raise ValueError("Invalid HTTP method")
        
        response.raise_for_status()
        if verbose:
            print(f"Request to {url} succeeded with status code {response.status_code}")
        return response.json() if response.text else []
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        exit(1)

def fetch_existing_ips(list_type):
    """Fetch all existing IPs from a specified list, supporting pagination."""
    all_ips = []
    offset = 0

    while True:
        endpoint = f"{list_type}/{offset}"
        ips = make_request("GET", endpoint)
        if not ips:
            break
        all_ips.extend(ips)
        offset += PAGE_LIMIT

    return all_ips

# Command functions
def add_ips(ip_list, list_type, verbose):
    valid_ips = validate_ips(ip_list)
    if not valid_ips:
        return
    
    existing_ips = fetch_existing_ips(list_type)
    ips_to_add = [ip for ip in valid_ips if ip not in existing_ips]
    
    if not ips_to_add:
        print("All IPs are already in the list. No changes made.")
        return

    print(f"Adding IPs to {list_type}: {ips_to_add}")
    make_request("POST", list_type, ips_to_add, verbose)

def remove_ips(ip_list, list_type, verbose):
    valid_ips = validate_ips(ip_list)
    if not valid_ips:
        return

    existing_ips = fetch_existing_ips(list_type)
    ips_to_remove = [ip for ip in valid_ips if ip in existing_ips]
    non_existent_ips = [ip for ip in valid_ips if ip not in existing_ips]

    if non_existent_ips:
        print(f"Warning: The following IPs do not exist in the {list_type} and will be skipped: {', '.join(non_existent_ips)}")
    
    if not ips_to_remove:
        print("No IPs to remove. No changes made.")
        return

    print(f"Removing IPs from {list_type}: {ips_to_remove}")
    make_request("DELETE", list_type, ips_to_remove, verbose)

def list_ips(list_type, verbose):
    print(f"Fetching IPs from {list_type}...")
    ips = fetch_existing_ips(list_type)
    for ip in ips:
        print(ip)

# Main CLI
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FraudGuard.io CLI Tool")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Add IPs
    add_parser = subparsers.add_parser("add")
    add_parser.add_argument("--list", choices=["blacklist", "whitelist"], required=True, help="Specify blacklist or whitelist")
    add_parser.add_argument("--ips", nargs="+", required=True, help="IP addresses to add")

    # Remove IPs
    remove_parser = subparsers.add_parser("remove")
    remove_parser.add_argument("--list", choices=["blacklist", "whitelist"], required=True, help="Specify blacklist or whitelist")
    remove_parser.add_argument("--ips", nargs="+", required=True, help="IP addresses to remove")

    # List IPs
    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--list", choices=["blacklist", "whitelist"], required=True, help="Specify blacklist or whitelist")

    args = parser.parse_args()

    if args.command == "add":
        add_ips(args.ips, args.list, args.verbose)
    elif args.command == "remove":
        remove_ips(args.ips, args.list, args.verbose)
    elif args.command == "list":
        list_ips(args.list, args.verbose)