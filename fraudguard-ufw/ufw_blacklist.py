#!/usr/bin/env python3
import os, sys, time, ipaddress, subprocess, re
from typing import List, Set
import requests
from requests.auth import HTTPBasicAuth

API_BASE = "https://api.fraudguard.io/blacklist"
BATCH_TARGET = 1000
SLEEP_BETWEEN_CALLS = 2.0
TIMEOUT_SECS = 20
TAG = "fraudguard"

def read_creds():
    u, p = os.getenv("FRAUDGUARD_USER"), os.getenv("FRAUDGUARD_PASS")
    if not u or not p:
        sys.stderr.write("Set FRAUDGUARD_USER and FRAUDGUARD_PASS.\n")
        sys.exit(1)
    return u, p

def normalize(entry: str) -> str:
    s = entry.strip().strip('"').strip("'")
    if not s: raise ValueError("empty")
    if "/" in s:
        return str(ipaddress.ip_network(s, strict=False))  # CIDR
    return str(ipaddress.ip_address(s))                    # single IP

def fetch_batch(offset: int, auth: HTTPBasicAuth) -> List[str]:
    url = f"{API_BASE}/{offset}"
    r = requests.get(url, auth=auth, timeout=TIMEOUT_SECS, headers={"Accept":"application/json"})
    r.raise_for_status()
    data = r.json()
    if isinstance(data, list):
        return [str(x) for x in data]
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        return [str(x) for x in data["data"]]
    return []

def pull_blacklist() -> List[str]:
    u, p = read_creds()
    auth = HTTPBasicAuth(u, p)
    all_entries: Set[str] = set()
    offset = 0
    first = True
    while True:
        if not first: time.sleep(SLEEP_BETWEEN_CALLS)
        first = False
        batch = fetch_batch(offset, auth)
        if not batch: break
        for item in batch:
            try: all_entries.add(normalize(item))
            except Exception: pass
        if len(batch) < BATCH_TARGET: break
        offset += len(batch)
    # Sort so IPv4 before IPv6; we’ll insert each at position 1 anyway
    return sorted(all_entries, key=lambda x: (":" in x, x))

# ----- UFW helpers -----

def ufw_ready():
    from shutil import which
    if not which("ufw"): sys.exit("ufw not installed")
    s = subprocess.run(["ufw","status"], capture_output=True, text=True).stdout
    if "Status: inactive" in s: sys.exit("ufw is inactive (sudo ufw enable)")

def ufw_status_numbered() -> str:
    out = subprocess.run(["ufw","status","numbered"], capture_output=True, text=True, check=True)
    return out.stdout

def delete_tagged_rules(tag: str) -> int:
    status = ufw_status_numbered()
    lines = status.splitlines()
    numbered = []
    for line in lines:
        if tag.lower() in line.lower():
            m = re.search(r"\[\s*(\d+)\]", line)
            if m:
                numbered.append(int(m.group(1)))
    # delete highest first so numbering stays valid
    for n in sorted(numbered, reverse=True):
        subprocess.run(["ufw","--force","delete",str(n)], check=False)
    return len(numbered)

def add_rules_top(entries: List[str]) -> None:
    # Insert each rule at position 1 so denies are evaluated before broad ALLOWs
    # Note: inserting N entries at pos 1 results in reverse order;
    # functionally identical for denies, so we keep it simple.
    for e in entries:
        subprocess.run(["ufw","insert","1","deny","from",e,"comment",TAG], check=False)
    subprocess.run(["ufw","status","numbered"], check=False)

def main():
    import argparse
    p = argparse.ArgumentParser(description="Apply FraudGuard blacklist to UFW (insert at top) with comment tagging.")
    p.add_argument("--apply", action="store_true", help="Apply rules via UFW (otherwise just print the commands).")
    p.add_argument("--refresh", action="store_true", help="Remove existing 'fraudguard' rules before adding new ones.")
    args = p.parse_args()

    entries = pull_blacklist()
    if not entries:
        print("No entries returned.")
        return

    if args.apply:
        ufw_ready()
        removed = 0
        if args.refresh:
            removed = delete_tagged_rules(TAG)
        add_rules_top(entries)
        print(f"Removed {removed} old '{TAG}' rules; inserted {len(entries)} denies at top.")
    else:
        # print the exact commands that would be run
        for e in entries:
            print(f"ufw insert 1 deny from {e} comment \"{TAG}\"")
        print("# (Preview only — run with --apply to execute)")

if __name__ == "__main__":
    main()