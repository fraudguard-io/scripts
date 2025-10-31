# FraudGuard Offline DB Log Enricher

Enrich any log or data file locally using your FraudGuard Offline Database (SQLite). 
No API calls. No format lock-in. It auto-detects text, CSV, NDJSON, and JSON arrays and preserves the original structure.

---

## What it does

- Scans each record/line for IPv4/IPv6 addresses
- Looks up each IP in your offline SQLite DB (table: `attackers_detailed`)
- Emits enrichment without breaking your file’s format:
  - Plain text / .log / .txt: prints the original line unchanged followed by an enrichment line:
    ```
    # FG: ip=... risk=... threat=... asn=... asn_org=... isp=... organization=... isocode=... country=... connection_type=...
    ```
  - CSV: appends these columns:
    ```
    fraudguard_risk, fraudguard_threat, fraudguard_asn, fraudguard_asn_organization,
    fraudguard_isp, fraudguard_organization, fraudguard_isocode, fraudguard_country,
    fraudguard_connection_type
    ```
  - NDJSON / JSON array: injects a `"fraudguard": { ... }` object into each matching record

Designed for easy grepping, SIEM ingestion, and downstream parsing.

---

## Requirements

- Python **3.8+**
- Your FraudGuard offline SQLite database (e.g., `fg-database.sqlite`)
- Table **`attackers_detailed`** with at least the following columns:
  ```
  ip, threat, risk, asn, asn_organization, isp, organization,
  isocode, country, connection_type
  ```
  *(Snapshots already include an index on `ip` such as `idx_attackers_detailed_ip`.)*

---

## Quickstart

1) **Prepare the DB**

If your file is gzipped, decompress once:
```bash
gunzip fg-database.sqlite.gz
```
Sanity check:
```bash
sqlite3 fg-database.sqlite "SELECT COUNT(*) FROM attackers_detailed;"
sqlite3 fg-database.sqlite "PRAGMA index_list('attackers_detailed');"
```

2) **Run the enricher**

### Text (stdin → stdout)
```bash
echo "login from 203.0.113.8" | python3 fg_enrich.py --db fg-database.sqlite
```
Output:
```
login from 203.0.113.8
# FG: ip=203.0.113.8 risk=5 threat=abuse_tracker asn=15169 asn_org=Google LLC isp=Google LLC organization=Google LLC isocode=US country=United States connection_type=Datacenter
```

### Text file → file
```bash
python3 fg_enrich.py \
  --db fg-database.sqlite \
  --input /var/log/nginx/access.log \
  --output /tmp/access.enriched.log
```

### CSV
```bash
python3 fg_enrich.py \
  --db fg-database.sqlite \
  --input access.csv \
  --output access.enriched.csv
```
The output CSV will include the `fraudguard_*` columns listed above.

### NDJSON (one JSON per line)
```bash
python3 fg_enrich.py \
  --db fg-database.sqlite \
  --input events.ndjson \
  --output events.enriched.ndjson
```

### JSON array
```bash
python3 fg_enrich.py \
  --db fg-database.sqlite \
  --input events.json \
  --output events.enriched.json
```

---

## Behavior notes

- Text logs: original line is preserved; enrichment appears as a separate `# FG:` line immediately after. Easy to grep or ignore.
- CSV: auto-detects delimiter and IP column; if no obvious IP column, it scans string fields per row for an IP pattern.
- JSON: preserves the input structure; for JSON arrays it parses objects in a streaming manner (no full-file load).
- Multiple IPs per line (text): prints one `# FG:` enrichment line per matched IP.

---

## Helpful SQLite commands

```bash
sqlite3 fg-database.sqlite ".tables"
sqlite3 fg-database.sqlite "PRAGMA table_info('attackers_detailed');"
sqlite3 fg-database.sqlite "SELECT ip, risk, threat FROM attackers_detailed LIMIT 5;"
```

---

## Security & privacy

- All enrichment happens locally. No data is sent to FraudGuard unless you choose to share it.
- The script is read-only with respect to your SQLite DB.

---

## License

MIT License — you’re free to use, modify, and distribute this code however you’d like. Attribution is appreciated but not required.

To explore FraudGuard’s live threat intelligence APIs, dashboards, and commercial offerings, sign up at [https://fraudguard.io](https://fraudguard.io)

---

