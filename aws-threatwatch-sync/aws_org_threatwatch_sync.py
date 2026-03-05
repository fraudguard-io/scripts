#!/usr/bin/env python3
"""
AWS → FraudGuard ThreatWatch sync (single-account or AWS Organizations).
See readme.md for usage, IAM requirements, and examples.
"""

import argparse
import base64
import ipaddress
import os
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

import boto3
import botocore
import requests


# ----------------------------
# Utils
# ----------------------------

def is_public_ipv4(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.version == 4 and a.is_global
    except ValueError:
        return False


def basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("utf-8")
    return f"Basic {token}"


def sleep_ms(ms: int) -> None:
    if ms > 0:
        time.sleep(ms / 1000.0)


def req_with_retries(
    method: str,
    url: str,
    headers: Dict[str, str],
    json_body: Optional[dict],
    timeout_s: int,
    retries: int,
    backoff_ms: int,
) -> requests.Response:
    last_exc: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            return requests.request(method, url, headers=headers, json=json_body, timeout=timeout_s)
        except Exception as e:
            last_exc = e
            if attempt == retries:
                raise
            sleep_ms(backoff_ms * (attempt + 1))
    raise RuntimeError(f"request failed unexpectedly: {last_exc}")


def parse_csv_set(v: str) -> Optional[Set[str]]:
    v = (v or "").strip()
    if not v:
        return None
    return {x.strip() for x in v.split(",") if x.strip()}


# ----------------------------
# FraudGuard ThreatWatch client
# ----------------------------

@dataclass
class FraudGuardThreatWatch:
    base_url: str
    username: str
    password: str
    timeout_s: int = 12
    retries: int = 2
    backoff_ms: int = 500
    rate_limit_ms: int = 150

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": basic_auth_header(self.username, self.password),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _url(self, path: str) -> str:
        return self.base_url.rstrip("/") + path

    def list_ips(self) -> Set[str]:
        url = self._url("/api/threatwatch/list")
        resp = req_with_retries("GET", url, self._headers(), None, self.timeout_s, self.retries, self.backoff_ms)
        if resp.status_code // 100 != 2:
            raise RuntimeError(f"ThreatWatch list failed status={resp.status_code} body={resp.text[:500]}")

        data = resp.json()
        if not isinstance(data, dict) or data.get("status") != "success":
            raise RuntimeError(f"Unexpected list response: {data}")

        ips: Set[str] = set()
        for row in data.get("monitored_ips", []) or []:
            if isinstance(row, dict):
                ip = row.get("ip")
                if isinstance(ip, str) and is_public_ipv4(ip):
                    ips.add(ip)
        return ips

    def add_ip(self, ip: str) -> None:
        url = self._url("/api/threatwatch/add")
        payload = {"ip": ip}
        resp = req_with_retries("POST", url, self._headers(), payload, self.timeout_s, self.retries, self.backoff_ms)
        if resp.status_code // 100 != 2:
            raise RuntimeError(f"ThreatWatch add failed ip={ip} status={resp.status_code} body={resp.text[:500]}")

        data = resp.json()
        if not isinstance(data, dict) or data.get("status") != "success":
            raise RuntimeError(f"Unexpected add response ip={ip}: {data}")

        sleep_ms(self.rate_limit_ms)

    def delete_ip(self, ip: str) -> None:
        url = self._url("/api/threatwatch/delete")
        payload = {"ip": ip}
        resp = req_with_retries("DELETE", url, self._headers(), payload, self.timeout_s, self.retries, self.backoff_ms)
        if resp.status_code // 100 != 2:
            raise RuntimeError(f"ThreatWatch delete failed ip={ip} status={resp.status_code} body={resp.text[:500]}")

        data = resp.json()
        if not isinstance(data, dict) or data.get("status") != "success":
            raise RuntimeError(f"Unexpected delete response ip={ip}: {data}")

        sleep_ms(self.rate_limit_ms)


# ----------------------------
# AWS Org inventory
# ----------------------------

def org_list_active_accounts(org_client, trace: bool=False) -> List[Tuple[str, str]]:
    accounts: List[Tuple[str, str]] = []
    if trace:
        print("[trace-aws] organizations.list_accounts", file=sys.stderr)
    paginator = org_client.get_paginator("list_accounts")
    for page in paginator.paginate():
        for acct in page.get("Accounts", []):
            if acct.get("Status") == "ACTIVE":
                accounts.append((acct["Id"], acct.get("Name", "")))
    return accounts


def assume_role_session(account_id: str, role_name: str, external_id: Optional[str], profile_name: Optional[str], trace: bool=False) -> boto3.Session:
    sts = boto3.Session(profile_name=profile_name).client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    params = {
        "RoleArn": role_arn,
        "RoleSessionName": f"fg-tw-sync-{account_id}-{int(time.time())}",
        "DurationSeconds": 3600,
    }
    if external_id:
        params["ExternalId"] = external_id

    if trace:
        print(f"[trace-aws] sts.assume_role RoleArn={role_arn} ExternalId={external_id}", file=sys.stderr)
    resp = sts.assume_role(**params)
    c = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=c["AccessKeyId"],
        aws_secret_access_key=c["SecretAccessKey"],
        aws_session_token=c["SessionToken"],
    )


def discover_regions(session: boto3.Session, trace: bool=False) -> List[str]:
    ec2 = session.client("ec2", region_name="us-east-1")
    if trace:
        print("[trace-aws] ec2.describe_regions AllRegions=False", file=sys.stderr)
    resp = ec2.describe_regions(AllRegions=False)
    return sorted([r["RegionName"] for r in resp["Regions"]])


def collect_ips_in_region(session: boto3.Session, region: str, trace: bool=False) -> Set[str]:
    ips: Set[str] = set()
    ec2 = session.client("ec2", region_name=region)

    # EIPs
    try:
        if trace:
            print(f"[trace-aws] ec2.describe_addresses region={region}", file=sys.stderr)
        resp = ec2.describe_addresses()
        for addr in resp.get("Addresses", []):
            ip = addr.get("PublicIp")
            if isinstance(ip, str) and is_public_ipv4(ip):
                ips.add(ip)
    except botocore.exceptions.ClientError:
        pass

    # EC2 instances public IPs
    try:
        if trace:
            print(f"[trace-aws] ec2.describe_instances region={region}", file=sys.stderr)
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    ip = inst.get("PublicIpAddress")
                    if isinstance(ip, str) and is_public_ipv4(ip):
                        ips.add(ip)
    except botocore.exceptions.ClientError:
        pass

    # NAT Gateways public IPs
    try:
        if trace:
            print(f"[trace-aws] ec2.describe_nat_gateways region={region}", file=sys.stderr)
        paginator = ec2.get_paginator("describe_nat_gateways")
        for page in paginator.paginate():
            for ngw in page.get("NatGateways", []):
                for a in ngw.get("NatGatewayAddresses", []):
                    ip = a.get("PublicIp")
                    if isinstance(ip, str) and is_public_ipv4(ip):
                        ips.add(ip)
    except botocore.exceptions.ClientError:
        pass

    return ips


def collect_org_public_ips(
    accounts: List[Tuple[str, str]],
    role_name: str,
    external_id: Optional[str],
    include_accounts: Optional[Set[str]],
    exclude_accounts: Optional[Set[str]],
    profile_name: Optional[str],
    trace_aws: bool,
    verbose: bool,
) -> Set[str]:
    all_ips: Set[str] = set()

    for account_id, account_name in accounts:
        if include_accounts and account_id not in include_accounts:
            continue
        if exclude_accounts and account_id in exclude_accounts:
            continue

        if verbose:
            print(f"[aws] account={account_id} name={account_name}", file=sys.stderr)

        try:
            sess = assume_role_session(account_id, role_name, external_id, profile_name, trace=trace_aws)
        except Exception as e:
            print(f"[aws] WARN assume-role failed account={account_id}: {e}", file=sys.stderr)
            continue

        try:
            regions = discover_regions(sess, trace=trace_aws)
        except Exception as e:
            print(f"[aws] WARN describe_regions failed account={account_id}: {e}", file=sys.stderr)
            continue

        for region in regions:
            if verbose:
                print(f"[aws]   region={region}", file=sys.stderr)
            try:
                ips = collect_ips_in_region(sess, region, trace=trace_aws)
                all_ips.update(ips)
            except Exception as e:
                print(f"[aws] WARN inventory failed account={account_id} region={region}: {e}", file=sys.stderr)
                continue

    return all_ips


# ----------------------------
# Main
# ----------------------------

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--role-name", required=False, help="IAM role name to assume in each member account (if omitted, only the current account will be scanned)")
    p.add_argument("--external-id", default="", help="Optional ExternalId for AssumeRole")
    p.add_argument("--profile", default=None, help="AWS profile to use")

    p.add_argument("--include-accounts", default="", help="Comma-separated account IDs to include (optional)")
    p.add_argument("--exclude-accounts", default="", help="Comma-separated account IDs to exclude (optional)")

    p.add_argument("--fg-base-url", default="https://api.fraudguard.io", help="FraudGuard API base URL")
    p.add_argument("--fg-username", default=os.getenv("FG_USERNAME", ""), help="FG username (or FG_USERNAME env)")
    p.add_argument("--fg-password", default=os.getenv("FG_PASSWORD", ""), help="FG password (or FG_PASSWORD env)")

    p.add_argument("--delete-missing", action="store_true", help="Delete ThreatWatch IPs that are no longer in AWS")
    p.add_argument("--dry-run", action="store_true", help="Show planned changes only")
    p.add_argument("--verbose", action="store_true", help="Verbose progress logging")
    p.add_argument("--trace-aws", action="store_true", help="Print every AWS API call before it is executed")

    p.add_argument("--fg-timeout-s", type=int, default=12)
    p.add_argument("--fg-retries", type=int, default=2)
    p.add_argument("--fg-backoff-ms", type=int, default=500)
    p.add_argument("--fg-rate-limit-ms", type=int, default=150)
    p.add_argument("--inventory-only", action="store_true", help="Only output discovered AWS public IPv4s; do not call FraudGuard")

    args = p.parse_args()

    if not args.inventory_only and (not args.fg_username or not args.fg_password):
        print("ERROR: Missing FraudGuard credentials. Set FG_USERNAME/FG_PASSWORD or pass --fg-username/--fg-password.", file=sys.stderr)
        return 2

    include_accounts = parse_csv_set(args.include_accounts)
    exclude_accounts = parse_csv_set(args.exclude_accounts)
    external_id = args.external_id.strip() or None

    session = boto3.Session(profile_name=args.profile)

    # 1) Determine account scope
    if args.role_name:
        # Organization-wide mode
        org = session.client("organizations")
        accounts = org_list_active_accounts(org, trace=args.trace_aws)
        if args.verbose:
            print(f"[aws] active accounts={len(accounts)}", file=sys.stderr)
    else:
        # Single-account mode (no AssumeRole)
        sts = session.client("sts")
        if args.trace_aws:
            print("[trace-aws] sts.get_caller_identity", file=sys.stderr)
        ident = sts.get_caller_identity()
        accounts = [(ident["Account"], "current-account")]
        if args.verbose:
            print(f"[aws] single-account mode account={ident['Account']}", file=sys.stderr)

    # 2) AWS org-wide IP inventory
    if args.role_name:
        aws_ips = collect_org_public_ips(
            accounts=accounts,
            role_name=args.role_name,
            external_id=external_id,
            include_accounts=include_accounts,
            exclude_accounts=exclude_accounts,
            profile_name=args.profile,
            trace_aws=args.trace_aws,
            verbose=args.verbose,
        )
    else:
        # Single-account discovery (no AssumeRole)
        aws_ips = set()
        regions = discover_regions(session, trace=args.trace_aws)
        for region in regions:
            if args.verbose:
                print(f"[aws] region={region}", file=sys.stderr)
            try:
                ips = collect_ips_in_region(session, region, trace=args.trace_aws)
                aws_ips.update(ips)
            except Exception as e:
                print(f"[aws] WARN inventory failed region={region}: {e}", file=sys.stderr)
    scope_label = "org-wide" if args.role_name else "single-account"
    print(f"Discovered AWS {scope_label} public IPv4s: {len(aws_ips)}")

    if args.inventory_only:
        for ip in sorted(aws_ips):
            print(ip)
        return 0

    # 3) ThreatWatch list
    fg = FraudGuardThreatWatch(
        base_url=args.fg_base_url,
        username=args.fg_username,
        password=args.fg_password,
        timeout_s=args.fg_timeout_s,
        retries=args.fg_retries,
        backoff_ms=args.fg_backoff_ms,
        rate_limit_ms=args.fg_rate_limit_ms,
    )
    tw_ips = fg.list_ips()
    print(f"ThreatWatch monitored IPv4s (current): {len(tw_ips)}")

    # 4) Diff
    to_add = sorted(aws_ips - tw_ips)
    to_del = sorted(tw_ips - aws_ips) if args.delete_missing else []

    print(f"Planned changes: add={len(to_add)} delete={len(to_del)} (delete-missing={'on' if args.delete_missing else 'off'})")

    if args.dry_run:
        if to_add:
            print("\n[DRY RUN] ADD (first 200):")
            for ip in to_add[:200]:
                print(ip)
            if len(to_add) > 200:
                print(f"... ({len(to_add) - 200} more)")
        if to_del:
            print("\n[DRY RUN] DELETE (first 200):")
            for ip in to_del[:200]:
                print(ip)
            if len(to_del) > 200:
                print(f"... ({len(to_del) - 200} more)")
        return 0

    # 5) Apply
    ok_add = 0
    ok_del = 0
    fail = 0

    for ip in to_add:
        try:
            fg.add_ip(ip)
            ok_add += 1
        except Exception as e:
            fail += 1
            print(f"[fg] add failed ip={ip}: {e}", file=sys.stderr)

    for ip in to_del:
        try:
            fg.delete_ip(ip)
            ok_del += 1
        except Exception as e:
            fail += 1
            print(f"[fg] delete failed ip={ip}: {e}", file=sys.stderr)

    print(f"Done. add_ok={ok_add}/{len(to_add)} delete_ok={ok_del}/{len(to_del)} failures={fail}")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())