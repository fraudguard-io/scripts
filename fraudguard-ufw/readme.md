# FraudGuard UFW Blacklist Script

A Python script that fetches the FraudGuard.io blacklist feed and applies it to your server using UFW. All rules are tagged with `# fraudguard` for easy identification and safe refresh.

## Features
- Fetches IPs and CIDRs from the FraudGuard.io API
- Deduplicates and normalizes entries (IPv4 + IPv6)
- Inserts deny rules at the top of the UFW list (before broad allows)
- Tags each rule with `comment "fraudguard"`

## Requirements
- Python 3.7+
- `requests` Python package
- UFW installed and enabled (`sudo ufw enable`)

## Setup
1. Clone this repo:
   ```bash
   git clone https://github.com/fraudguard-io/scripts.git
   cd fraudguard-ufw
   ```

2. Install Python deps:
   ```bash
   pip install requests
   ```

3. Export your FraudGuard API credentials:
   ```bash
   export FRAUDGUARD_USER="your-username"
   export FRAUDGUARD_PASS="your-password"
   ```

## Usage
Preview the rules (no changes made):
```bash
python ufw_blacklist.py
```

Apply rules via UFW:
```bash
sudo -E python ufw_blacklist.py --apply
```

Refresh mode - keeps the rules always in sync with FraudGuard API (remove old FraudGuard rules, then re-add clean):
```bash
sudo -E python ufw_blacklist.py --apply --refresh
```

## Example
After applying, your UFW rules will look like:
```
[ 1] Anywhere                   DENY IN     144.91.118.26      # fraudguard
[ 2] Anywhere                   DENY IN     27.79.220.146      # fraudguard
[ 4] 80/tcp                     ALLOW IN    Anywhere
[ 5] 443/tcp                    ALLOW IN    Anywhere
```

## Notes
- Do not hardcode credentials in the script; best to use environment variables.
- Only FraudGuard-tagged rules are modified on refresh; other UFW rules remain untouched.
- Set this Python script on a cron job or systemd timer to keep your blacklist updated automatically; this way it can act as a global IP blacklist across all your servers.

## License
MIT License © FraudGuard