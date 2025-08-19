# Offline Threat DB – Examples (SQLite/CSV)

This folder contains ready‑to‑run Python scripts for using FraudGuard’s Offline Threat Database entirely locally (air‑gapped friendly)

- `download_offline_db.py` — downloads the latest SQLite or CSV snapshot safely (ETag caching, 60‑minute guard, gzip auto‑detect, integrity checks, atomic rotate).
- `sqlite_lookup.py` — fast, read‑only threat lookups against the local SQLite file with flexible filters and multiple output formats.

---

## 1) Installation

```bash
# Python 3.9+
python3 -m venv .venv
source .venv/bin/activate
```

---

## 2) `download_offline_db.py`


### What it does
- Authenticates with FG_USERNAME / FG_PASSWORD (Basic Auth).
- Skips if a download occurred within the last 60 minutes (hard‑coded guard).
- Uses ETag to avoid re‑downloading unchanged files (`304 Not Modified`).
- Auto‑detects gzip responses and transparently decompresses.
- Validates payloads:
  - **SQLite**: `PRAGMA integrity_check == 'ok'`
  - **CSV**: header must match the expected schema
- Writes atomically to `data/current.sqlite` or `data/current.csv`.

### API Documentation

- [Offline Threat Database (SQLite)](https://docs.fraudguard.io/#offline-threat-database-sqlite)
- [Offline Threat Database (CSV)](https://docs.fraudguard.io/#offline-threat-database-csv)
- [Blog Post](https://blog.fraudguard.io/misc/2025/08/12/offline-database-article.html)

### Arguments
The downloader intentionally keeps CLI flags minimal for operational safety. It supports:

```
--format <sqlite|csv>       Which snapshot format to download. Default: sqlite
```

> All other settings use environment variables (below). The script always writes to `./data/`.

### Environment variables (required / optional)
Required:

- `FG_USERNAME` — FraudGuard API username
- `FG_PASSWORD` — FraudGuard API password

### Usage
```bash
export FG_USERNAME="your-api-username"
export FG_PASSWORD="your-api-password"

# SQLite (default)
python3 offline-db-examples/download_offline_db.py --format sqlite

# CSV
python3 offline-db-examples/download_offline_db.py --format csv
```

Output files:
- `data/current.sqlite` or `data/current.csv`
- `data/current.sqlite.etag` / `data/current.csv.etag`
- `data/current.sqlite.stamp` / `data/current.csv.stamp`

### Troubleshooting
- **401/403 or unexpected HTTP** → verify `FG_USERNAME`/`FG_PASSWORD`.
- **Integrity check failed (SQLite)** → download may be partial/corrupt; try again after 60m or remove the `.stamp` to force.
- **CSV header check failed** → ensure you requested the CSV endpoint; gzip is auto‑handled.

---

## 3) `sqlite_lookup.py`

### What it does
Performs fast, read‑only lookups against the local SQLite database of threat IPs only with a snapshot in real-time of current risk levels derived from the FraudGuard.io attack correlation engine. Supports single IPs, CIDRs (with cap), and filtering by risk, threat, ISO code, and ASN. Outputs JSON (default), TSV, or CSV.


### Arguments (complete)
```
--db <path>                 Path to SQLite DB (read‑only). Default: data/current.sqlite
--ip <IP>[,IP,...]          IP to lookup (repeatable or comma‑separated)
--cidr <CIDR>               CIDR to iterate (use --limit to cap)
--limit <int>               Max IPs to enumerate from --cidr (default: 65536)
--batch-size <int>          IN() batch size (default: 1000)
--min-risk <int>            Minimum risk to return (default: 1)
--threat <name>             Filter by threat (e.g., anonymous_tracker, abuse_tracker)
--fields <csv>              Comma‑separated fields to return
--output <json|tsv|csv>     Output format (default: json)
--include-misses            Emit non‑matching rows as {"ip": "...", "found": false}
--isocode <CC>              Filter by ISO country code (e.g., US, DE) [case‑insensitive]
--asn <int>                 Filter by ASN number (e.g., 15169)
```

### Notes
- Database opens read‑only with tuned PRAGMAs for speed.
- Filters (`--min-risk`, `--threat`, `--isocode`, `--asn`) are AND‑ed.
- You may pass multiple `--ip` flags and/or comma‑separated lists; combined with any `--cidr`.
- `--include-misses` helps audit lists by emitting entries not present in the threat DB snapshot.

### Quick examples
```bash
# Single IP → JSON
python3 offline-db-examples/sqlite_lookup.py --ip 203.0.113.9

# Multiple IPs, minimum risk 3 → TSV
python3 offline-db-examples/sqlite_lookup.py \
  --ip 1.1.1.1,8.8.8.8 --ip 9.9.9.9 --min-risk 3 --output tsv

# Iterate a block, include misses for auditing
python3 offline-db-examples/sqlite_lookup.py --cidr 203.0.113.0/28 --include-misses

# Filter by threat and country
python3 offline-db-examples/sqlite_lookup.py --cidr 198.51.100.0/24 --threat anonymous_tracker --isocode US

# Filter by ASN and return custom fields as CSV
python3 offline-db-examples/sqlite_lookup.py \
  --cidr 192.0.2.0/20 --asn 15169 \
  --fields ip,risk,threat,asn,organization --output csv
```
