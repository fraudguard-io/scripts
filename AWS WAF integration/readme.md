# AWS WAF Integration Script for FraudGuard.io

## Overview
This Python script automates the process of fetching high-risk IPs from FraudGuard.io and updating AWS WAF IP sets to enhance security. It supports both IPv4 and IPv6, ensures compliance with AWS WAF limits, and prevents excessive API requests with built-in rate limiting.

## Features
- Automatically retrieves IPv4 and IPv6 addresses from FraudGuard.io
- Respects AWS WAF limits (10,000 for Regional WAF, 100,000 for CloudFront WAF)
- Ensures correct CIDR formatting
- Implements rate-limiting
- Logs all actions for easy debugging

## Requirements
- Python 3 (Run using `python3` on macOS)
- AWS CLI configured with appropriate WAF permissions and creation of both AWS WAF IP Sets defined below
- FraudGuard.io API credentials
- Boto3 (AWS SDK for Python)
- Requests library
- Must be a valid FraudGuard.io customer with access to the (Raw List by Risk API)[https://docs.fraudguard.io/#raw-ip-lists-by-risk]

### Install Dependencies
Run the following command to install dependencies:
```bash
pip3 install boto3 requests
```

## Configuration
Modify the script's configuration variables before running:

```python
# FraudGuard.io API Settings
FRAUDGUARD_RISK_LEVEL = 5  # Change risk level as needed
FRAUDGUARD_USERNAME = "your_API_username"
FRAUDGUARD_PASSWORD = "your_API_password"

# AWS WAF Settings
AWS_REGION = "your_aws_region"
IPV4_SET_NAME = "YourIPv4SetName"
IPV6_SET_NAME = "YourIPv6SetName"
IP_SET_SCOPE = "REGIONAL"  # Use "CLOUDFRONT" for global WAF
```

## Running the Script
To execute the script, run:
```bash
python3 aws_waf_integration.py
```

## How It Works
1. Fetches IPs from FraudGuard.io (both IPv4 and IPv6 separately)
2. Ensures correct CIDR notation
3. Stops fetching once AWS WAF limits are reached
4. Updates AWS WAF IP sets with the retrieved IPs
5. Logs progress and potential errors

## Logging
Logs are stored in `aws_waf_integration.log`. To view logs in real time:
```bash
tail -f aws_waf_integration.log
```

---
🚀 **This script ensures real-time protection against high-risk IPs using AWS WAF.** Modify as needed to fit your security policies!

