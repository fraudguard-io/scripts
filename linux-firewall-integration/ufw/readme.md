# UFW Blacklist Sync Script

This script syncs the custom blacklist from **FraudGuard.io** with **UFW (Uncomplicated Firewall)** on your server. It ensures that all IPs or subnets in your FraudGuard.io blacklist are blocked at the firewall level, providing an extra layer of protection for your infrastructure.

## Features

- Fetches the latest custom blacklist from FraudGuard.io using the `Get Custom Blacklist` API.
- Handles pagination for large blacklists with more than 1000 entries.
- Logs errors, such as failed API requests or HTTP issues, for debugging.
- Avoids duplicate rules by checking if an IP or subnet is already blocked.
- Logs all actions, including blocked IPs and errors, in `ufw_sync_blacklist.log`.

## Prerequisites

1. **Dependencies**:
   - `curl` for API requests.
   - `jq` for parsing JSON responses.

   Install `jq` if it’s not installed on your system.

2. **FraudGuard.io Credentials**:
   - Obtain your FraudGuard.io username and password from the [FraudGuard.io website](https://fraudguard.io).

3. **UFW**:
   - Ensure UFW is installed and active on your server.

## Usage

1. Save the script to your server and make it executable.
2. Open the script in a text editor and replace the placeholders for username and password with your FraudGuard.io credentials.
3. Run the script with root privileges to sync the blacklist with UFW.

## Workflow

1. The script fetches the blacklist from FraudGuard.io using `curl`.
2. It handles pagination to process all entries if the blacklist exceeds 1000 IPs or subnets.
3. Each IP or subnet is applied to UFW with the `ufw deny from` command.
4. The script reloads UFW to apply changes.

## Example Log Output

Fetching custom blacklist from FraudGuard.io...  
Fetching blacklist from offset 0...  
Applying 500 IPs to UFW...  
Blocked: 52.36.72.37  
Blocked: 144.24.162.232  
Already blocked: 166.13.138.114  
Reloading UFW...  
UFW blacklist sync complete!  

## Troubleshooting

1. **Failed to fetch blacklist**:
   - Verify your FraudGuard.io username and password.
   - Check your network connection and ensure the API URL is correct.

2. **Duplicate rules**:
   - The script skips already-blocked IPs. Verify UFW rules if duplicates persist.

3. **Large blacklists**:
   - The script handles pagination automatically. Ensure there is enough disk space for temporary files.

## Support

For questions or assistance, contact **FraudGuard.io** at [hello@fraudguard.io](mailto:hello@fraudguard.io). For more information, refer to the official documentation for the [`Get Custom Blacklist` API](https://docs.fraudguard.io/#get-custom-blacklist).

- Sign up for a **14-day free trial** and explore FraudGuard.io's features at [FraudGuard.io](https://fraudguard.io).