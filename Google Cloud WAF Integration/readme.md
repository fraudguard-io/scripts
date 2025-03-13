# Google Cloud WAF Integration with FraudGuard.io

## Overview
This script integrates Google Cloud WAF (Security Policies) with FraudGuard.io by dynamically fetching blacklisted IPs and updating Google Cloud Security Policy rules to block malicious traffic. The script can be automated using cron jobs or Cloud Functions.

## Features
- Fetches blacklisted IPs from FraudGuard.io.
- Updates Google Cloud Security Policies to block high-risk IPs.
- Uses Basic Authentication for FraudGuard.io API access.
- Supports pagination to fetch all IPs.
- Provides logging for monitoring and debugging.
- Automatable with cron jobs or Cloud Functions.

## Prerequisites
Before running this script, ensure you have the following:
- FraudGuard.io Enterprise Subscription ([Sign up here](https://fraudguard.io)).
- Google Cloud account ([Sign up here](https://cloud.google.com/free)).
- Google Cloud Security Policy already created.
- Python 3.x installed on your system.
- Required Python modules: `google-auth`, `google-cloud-compute`, `requests`.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/fraudguard-io/scripts.git
   ```

2. Install dependencies:
   ```bash
   pip install google-auth google-cloud-compute requests
   ```

## Configuration
Set the following environment variables before running the script:
```bash
export GCP_PROJECT_ID="your-gcp-project-id"
export SECURITY_POLICY_NAME="your-security-policy-name"
export FRAUDGUARD_USERNAME="your-fraudguard-username"
export FRAUDGUARD_PASSWORD="your-fraudguard-password"
export FRAUDGUARD_RISK_LEVEL="5"  # Change risk level if needed
export GCP_WAF_LOG_FILE="gcp_waf_integration.log"
```

## Usage
Run the script manually:
```bash
python gcp_waf_integration.py
```

### Automating with Cron Job
To schedule the script to run every 6 hours:
```bash
crontab -e
```
Add the following line:
```bash
0 */6 * * * /usr/bin/python3 /path/to/gcp_waf_integration.py >> /path/to/gcp_waf.log 2>&1
```

## Logging
The script logs execution details in `gcp_waf_integration.log`. You can change the log file path using:
```bash
export GCP_WAF_LOG_FILE="/var/log/gcp_waf_integration.log"
```

## Troubleshooting
### ModuleNotFoundError: No module named 'google.cloud.compute'
Run:
```bash
pip install google-cloud-compute google-auth requests
```

### Invalid Credentials for FraudGuard.io
Ensure that your `FRAUDGUARD_USERNAME` and `FRAUDGUARD_PASSWORD` are correct.

### Security Policy Not Found
Ensure the `GCP_PROJECT_ID` and `SECURITY_POLICY_NAME` are set correctly.
Check your security policies with:
```bash
gcloud compute security-policies list --project your-gcp-project-id
```

## Support
For any issues, reach out to [FraudGuard.io Support](mailto:hello@fraudguard.io) or visit [FraudGuard.io](https://fraudguard.io) for more details.

