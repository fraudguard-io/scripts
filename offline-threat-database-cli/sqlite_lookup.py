#!/usr/bin/env python3
"""
FraudGuard Offline Threat DB — SQLite Lookup
============================================
Offline lookups against a local SQLite database that contains **only threat IPs**.

For details see: https://blog.fraudguard.io/misc/2025/08/12/offline-database-article.html

## Expected Schema
  attackers_detailed(
    id INTEGER PRIMARY KEY,
    ip TEXT UNIQUE,
    threat TEXT,
    risk INTEGER,
    asn INTEGER,
    asn_organization TEXT,
    isp TEXT,
    organization TEXT,
    isocode TEXT,
    country TEXT,
    connection_type TEXT,
    updated_at TEXT
  )

## Usage
  python3 sqlite_lookup.py [OPTIONS]

## Arguments
--db <path>                      Path to SQLite DB (read-only). Default: data/current.sqlite

--ip <IP>[,IP,...]               IP address to lookup. May be repeated or comma-separated.
                                 Examples:
                                   --ip 203.0.113.9
                                   --ip 1.1.1.1,8.8.8.8 --ip 9.9.9.9

--cidr <CIDR>                    CIDR to iterate. Use with --limit to cap enumeration.
                                 Example: --cidr 203.0.113.0/27

--limit <int>                    Max IPs to enumerate from --cidr. Default: 65536

--batch-size <int>               Number of IPs per SQL IN() batch. Default: 1000

--min-risk <int>                 Minimum risk to return (1–5). Default: 1

--threat <name>                  Filter by single threat classification
                                 (e.g., anonymous_tracker, abuse_tracker, vpn_tracker, botnet_tracker).

--fields <csv>                   Comma-separated fields to return. Default:
                                 ip,risk,threat,asn,asn_organization,isp,organization,isocode,country,connection_type,updated_at

--output <json|tsv|csv>          Output format. Default: json (JSON Lines).

--include-misses                 If provided, also emit rows for non-matching inputs with:
                                 {"ip": "...", "found": False}

--isocode <CC>                   Filter by ISO country code (e.g., US, DE). Case-insensitive.

--asn <int>                      Filter by ASN number (e.g., 15169).

## Notes
- The database contains only threat IPs, so absence implies "not a known threat" in this snapshot.
- The script opens the database in **read-only** mode and applies light PRAGMA tuning for speed.
- When both --ip and --cidr are provided, results are combined.
- Filters (--min-risk, --threat, --isocode, --asn) are **ANDed** together.

## Exit Codes
- 0: Success
- 2: Invalid usage (e.g., no --ip/--cidr provided)
- 1: Other runtime error

## Examples
# Single IP, default fields as JSON
python3 sqlite_lookup.py --ip 203.0.113.9

# Multiple IPs (mixed styles), filter to risk >= 3, output TSV
python3 sqlite_lookup.py --ip 1.1.1.1,8.8.8.8 --ip 9.9.9.9 --min-risk 3 --output tsv

# Iterate a small block, include misses for auditing
python3 sqlite_lookup.py --cidr 203.0.113.0/28 --include-misses

# Filter by threat and country
python3 sqlite_lookup.py --cidr 198.51.100.0/24 --threat anonymous_tracker --isocode US

# Filter by ASN and custom fields, CSV output
python3 sqlite_lookup.py --cidr 192.0.2.0/20 --asn 15169 --fields ip,risk,threat,asn,organization --output csv

# Large CIDR with a cap and tuned batching
python3 sqlite_lookup.py --cidr 10.0.0.0/8 --limit 50000 --batch-size 2000 --min-risk 4

"""
import argparse, ipaddress, sqlite3, sys, json
from typing import Iterable, List, Dict

DEFAULT_DB = "data/current.sqlite"
DEFAULT_FIELDS = [
    "ip","risk","threat","asn","asn_organization","isp",
    "organization","isocode","country","connection_type","updated_at"
]

def connect_ro(path: str) -> sqlite3.Connection:
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA cache_size = -200000")  # ~200MB if available
    con.execute("PRAGMA temp_store = MEMORY")
    return con

def chunked(seq: List[str], n: int) -> Iterable[List[str]]:
    for i in range(0, len(seq), n):
        yield seq[i:i+n]

def enumerate_cidr(cidr: str, limit: int) -> List[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    # guardrails so nobody expands huge ranges by accident
    max_hosts = limit if limit > 0 else 65536
    ips = []
    it = (net.hosts() if net.version == 4 else net)  # include all for v6
    for i, ip in enumerate(it):
        if i >= max_hosts: break
        ips.append(str(ip))
    return ips

def lookup_block(cur: sqlite3.Cursor, ips: List[str], fields: List[str], min_risk: int, threat: str|None, isocode: str|None, asn: int|None):
    if not ips: return []
    placeholders = ",".join(["?"]*len(ips))
    cols = ", ".join(fields)
    where = [f"ip IN ({placeholders})", "risk >= ?"]
    params = ips + [min_risk]
    if threat:
        where.append("threat = ?")
        params.append(threat)
    if isocode:
        where.append("isocode = ?")
        params.append(isocode.upper())
    if asn:
        where.append("asn = ?")
        params.append(asn)
    q = f"SELECT {cols} FROM attackers_detailed WHERE {' AND '.join(where)}"
    return [dict(r) for r in cur.execute(q, params).fetchall()]

def to_tsv(rows: List[Dict], fields: List[str]) -> str:
    out = ["\t".join(fields)]
    for r in rows:
        out.append("\t".join("" if r.get(k) is None else str(r.get(k)) for k in fields))
    return "\n".join(out)

def parse_args():
    ap = argparse.ArgumentParser(description="Offline SQLite threat IP lookup")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--ip", action="append", help="IP to lookup (repeatable or comma-separated)")
    ap.add_argument("--cidr", help="CIDR to iterate (use --limit to cap)")
    ap.add_argument("--limit", type=int, default=65536, help="Max IPs to enumerate from --cidr")
    ap.add_argument("--batch-size", type=int, default=1000, help="IN() batch size")
    ap.add_argument("--min-risk", type=int, default=1, help="Minimum risk to return")
    ap.add_argument("--threat", help="Filter by threat (e.g., anonymous_tracker, abuse_tracker)")
    ap.add_argument("--fields", default=",".join(DEFAULT_FIELDS), help="Comma-separated fields to return")
    ap.add_argument("--output", choices=["json","tsv","csv"], default="json")
    ap.add_argument("--include-misses", action="store_true",
                    help="Emit non-matching IPs with {'ip':..., 'found': False}")
    ap.add_argument("--isocode", help="Filter by ISO country code (e.g., US, DE)")
    ap.add_argument("--asn", type=int, help="Filter by ASN number")
    return ap.parse_args()

def main():
    args = parse_args()
    fields = [f.strip() for f in args.fields.split(",") if f.strip()]
    ips: List[str] = []

    if args.ip:
        for part in args.ip:
            ips.extend([p.strip() for p in part.split(",") if p.strip()])
    if args.cidr:
        ips.extend(enumerate_cidr(args.cidr, args.limit))

    if not ips:
        print("No IPs provided. Use --ip and/or --cidr.", file=sys.stderr)
        sys.exit(2)

    con = connect_ro(args.db); cur = con.cursor()
    results: List[Dict] = []
    seen: set[str] = set()

    for block in chunked(ips, args.batch_size):
        rows = lookup_block(cur, block, fields, args.min_risk, args.threat, args.isocode, args.asn)
        for r in rows:
            r["found"] = True
            results.append(r)
            seen.add(r["ip"])

        if args.include_misses:
            for ip in block:
                if ip not in seen:
                    results.append({"ip": ip, "found": False})

    if args.output == "json":
        for r in results:
            print(json.dumps(r, ensure_ascii=False))
    elif args.output == "tsv":
        print(to_tsv(results, fields + (["found"] if args.include_misses else [])))
    else:  # csv
        import csv, io
        buf = io.StringIO()
        header = fields + (["found"] if args.include_misses else [])
        w = csv.DictWriter(buf, fieldnames=header)
        w.writeheader()
        for r in results:
            w.writerow({k: r.get(k) for k in header})
        print(buf.getvalue().rstrip("\n"))

if __name__ == "__main__":
    main()