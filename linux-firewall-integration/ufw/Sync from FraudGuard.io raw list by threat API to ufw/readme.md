# UFW Threat-Based Blocking Script

This script integrates with the **FraudGuard.io Raw IP Lists by Threat API** to block IPs classified under a specific threat type using **UFW (Uncomplicated Firewall)**. It automates the process of adding high-risk IPs to your firewall rules based on their threat classification.

## Features

- Threat-Based Blocking: Blocks IPs identified by a specific threat classification, such as `honeypot_tracker`.
- Pagination Support: Automatically fetches IPs in batches for large lists.
- Total Count Awareness: Utilizes the `X-Total-Count` header to determine the total number of IPs available.
- Hard Limit for Testing: Configurable maximum number of IPs to process (optional).
- Rate Limiting: Includes a sleep interval to avoid overloading the API.
- Avoids Duplicate Rules: Skips IPs already blocked by UFW.
- Detailed Logs: Actions and errors are logged to `ufw_block_by_threat.log`.

## Prerequisites

1. Dependencies:
   - curl for API requests.
   - jq for parsing JSON responses.

   Install jq if it’s not already installed:
   sudo apt-get update
   sudo apt-get install jq

2. FraudGuard.io Credentials:
   - Obtain your FraudGuard.io API key username and password, which are different from your web application credentials.

3. UFW:
   - Ensure UFW is installed and active on your server:
     sudo apt-get update
     sudo apt-get install ufw
     sudo ufw enable

## Usage

1. Setup:
   - Download or copy the `block_by_threat.sh` script to your server.
   - Make the script executable:
     chmod +x block_by_threat.sh

2. Configure:
   - Open the script in a text editor and update the following variables:
     - USERNAME and PASSWORD: Your FraudGuard.io API key credentials.
     - THREAT_TYPE: The type of threat to block (e.g., honeypot_tracker).
     - LIMIT: The number of IPs to fetch per request (default: 100).
     - MAX_RESULTS: A hard limit for the total number of IPs to process (set to 0 to disable).
     - SLEEP_INTERVAL: Time (in seconds) to wait between API requests.

3. Run the Script:
   - Execute the script with root privileges:
     sudo ./block_by_threat.sh

4. Logs:
   - The script logs all actions and errors to ufw_block_by_threat.log.
   - View the log file:
     cat ufw_block_by_threat.log

## Notes

- The X-Total-Count header ensures the script stops when all available IPs have been processed.
- For more information about risk levels and their use cases, check out our [blog post](https://blog.fraudguard.io/misc/2024/04/06/use-cases-article.html).

## Example Log Output

Fetching IPs classified as honeypot_tracker from FraudGuard.io...  
Fetching from offset 0...  
Blocking 100 IPs with UFW...  
Blocked: 5.188.210.93  
Blocked: 199.167.138.22  
Already blocked: 5.188.210.21  
Sleeping for 2 seconds to prevent API overload...  
Fetching from offset 100...  
No more IPs to process. Sync complete!  
Reloading UFW...  
UFW threat-based blocking complete!  

## Support

For questions or assistance, contact **FraudGuard.io** at [hello@fraudguard.io](mailto:hello@fraudguard.io). For more information, refer to the official documentation for the [`Raw IP Lists by Threat` API](https://docs.fraudguard.io/#raw-ip-lists-by-threat).

---

- Sign up for a **14-day free trial** and explore FraudGuard.io's features at [FraudGuard.io](https://fraudguard.io).