# AWS to FraudGuard.io ThreatWatch Sync

Syncs **all public IPv4 addresses** discovered in AWS to **FraudGuard ThreatWatch**, keeping your watchlist aligned with your cloud footprint.

Supports two modes:

- **Single-account mode**: scans the specified profile AWS account across **all regions**
- **Organization mode**: scans **all ACTIVE accounts** in an AWS Organization by assuming a role in each member account

The sync is idempotent:
- Adds IPs found in AWS but missing from ThreatWatch
- Optionally deletes ThreatWatch IPs that no longer exist in AWS

## What AWS resources are included

The script inventories “owned” public IPv4s that are reliably enumerable via AWS APIs:

- **Elastic IPs (EIPs)** (`ec2:DescribeAddresses`)
- **EC2 public IPv4s** (`ec2:DescribeInstances` → `PublicIpAddress`)
- **NAT Gateway public IPv4s** (`ec2:DescribeNatGateways` → `NatGatewayAddresses[].PublicIp`)

Notes:
- **ALB public IPs are not stable** and cannot be treated as persistent assets (they can change).
- Services like **CloudFront** and **API Gateway** do not map cleanly to stable, customer-owned public IPs. This script intentionally focuses on owned IP assets.

## Prerequisites

- Python 3.9+ recommended
- AWS credentials configured (AWS CLI profile, environment variables, or instance role)
- Python dependencies:

  ```bash
  pip install boto3 requests
  ```

## FraudGuard ThreatWatch endpoints used

The script calls these endpoints (Basic Auth):

- `GET  https://api.fraudguard.io/api/threatwatch/list`
- `POST https://api.fraudguard.io/api/threatwatch/add` (JSON body: `{"ip":"x.x.x.x"}`)
- `DELETE https://api.fraudguard.io/api/threatwatch/delete` (JSON body: `{"ip":"x.x.x.x"}`)

## Authentication

### AWS

You can use an AWS profile:

```bash
aws configure --profile myaws
```

And run:

```bash
python3 aws_org_threatwatch_sync.py --profile myaws
```

### FraudGuard

Provide credentials via environment variables:

```bash
export FG_USERNAME="username"
export FG_PASSWORD="password"
```

Or via flags:

```bash
python3 aws_org_threatwatch_sync.py --fg-username username --fg-password password
```

## Usage

### 1) Inventory-only (no FraudGuard calls)

Prints discovered AWS public IPv4s and exits (useful for validation):

```bash
python3 aws_org_threatwatch_sync.py --profile myaws --inventory-only
```

### 2) Single-account sync (default)

Scans the current account across all regions and syncs to ThreatWatch:

```bash
python3 aws_org_threatwatch_sync.py --profile myaws
```

Dry-run (shows planned adds/deletes without making changes):

```bash
python3 aws_org_threatwatch_sync.py --profile myaws --dry-run
```

### 3) Organization-wide sync (assume-role in every account)

Provide a role name that exists in each member account (example: `FraudGuardInventoryRole`):

```bash
python3 aws_org_threatwatch_sync.py --profile myaws --role-name FraudGuardInventoryRole
```

Dry-run:

```bash
python3 aws_org_threatwatch_sync.py --profile myaws --role-name FraudGuardInventoryRole --dry-run
```

Include or exclude specific accounts:

```bash
python3 aws_org_threatwatch_sync.py \
  --profile myaws \
  --role-name FraudGuardInventoryRole \
  --include-accounts "111111111111,222222222222"
```

```bash
python3 aws_org_threatwatch_sync.py \
  --profile myaws \
  --role-name FraudGuardInventoryRole \
  --exclude-accounts "333333333333"
```

### Deleting missing IPs

By default, the script only adds missing IPs. To also remove ThreatWatch entries that no longer exist in AWS:

```bash
python3 aws_org_threatwatch_sync.py --profile myaws --delete-missing
```

**Recommendation:** run with `--dry-run` before enabling deletes.

## Debugging and tracing

- `--verbose` prints high-level progress (accounts, regions)
- `--trace-aws` prints each AWS API call before it executes (service + operation + region)

Example:

```bash
python3 aws_org_threatwatch_sync.py --profile myaws --trace-aws --dry-run
```

Example output:

```
[trace-aws] sts.get_caller_identity
[trace-aws] ec2.describe_regions AllRegions=False
[trace-aws] ec2.describe_addresses region=us-east-1
[trace-aws] ec2.describe_instances region=us-east-1
[trace-aws] ec2.describe_nat_gateways region=us-east-1
```

## IAM requirements (Organization mode)

In Organization mode, the credentials used by `--profile` must be able to:

- `organizations:ListAccounts`
- `sts:AssumeRole` into each member account role (`--role-name`)

Each member account must contain a role (example: `FraudGuardInventoryRole`) with these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRegions",
        "ec2:DescribeAddresses",
        "ec2:DescribeInstances",
        "ec2:DescribeNatGateways"
      ],
      "Resource": "*"
    }
  ]
}
```

The role trust policy must allow the management/tooling account to assume it. Example trust policy (replace `111111111111` with your management account ID):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::111111111111:root" },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

If you require `ExternalId` for AssumeRole, pass `--external-id`.

## Exit codes

- `0` success
- `1` completed with one or more add/delete failures
- `2` missing required FraudGuard credentials (not in `--inventory-only` mode)

## Security notes

- Keep FraudGuard credentials in environment variables (recommended) rather than shell history.
- Consider running `--dry-run` in CI before enabling `--delete-missing`.

