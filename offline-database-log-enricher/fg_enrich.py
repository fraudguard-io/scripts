#!/usr/bin/env python3
"""
fg_enrich.py - FraudGuard Offline SQLite Enricher (auto-detect formats)

Usage examples:
  # stdin -> stdout (text)
  cat /var/log/nginx/access.log | python3 fg_enrich.py --db fg-database.sqlite > enriched.log

  # file -> file (CSV/JSON/etc)
  python3 fg_enrich.py --db fg-database.sqlite --input access.csv --output enriched.csv

Notes:
- SQLite must contain table `attackers_detailed` with an indexed `ip` column.
- For CSV, the script will try to auto-detect the IP column name (looks for header containing "ip").
- For JSON lines (NDJSON) or JSON arrays, the script will inject a "fraudguard" field (object) on matched records.
- For plain text lines, the script appends " | <json>" when enrichment exists.
"""

import argparse
import csv
import json
import os
import re
import sqlite3
import sys
from typing import Dict, Optional, Iterable, Tuple

# --- Regexes ---
# IPv4 pattern (robust)
IPv4_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b')
# IPv6 pattern (simple but practical)
IPv6_RE = re.compile(r'\b([A-F0-9]{1,4}:){1,7}[A-F0-9]{1,4}\b', re.I)

# common ip-like header names for CSV/JSON
IP_CANDIDATES = ("ip", "client_ip", "src_ip", "source_ip", "remote_addr", "host_ip", "ip_address")

# --- DB helpers ---
def open_db(path: str) -> sqlite3.Connection:
    if not os.path.isfile(path):
        sys.exit(f"[!] Database not found: {path}")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    # performance pragmas for read-only heavy use
    conn.execute("PRAGMA journal_mode=OFF;")
    conn.execute("PRAGMA synchronous=OFF;")
    return conn

def lookup_ip(conn: sqlite3.Connection, ip: str) -> Optional[Dict]:
    try:
        cur = conn.execute(
            "SELECT risk, threat, asn, asn_organization, isp, organization, isocode, country, connection_type "
            "FROM attackers_detailed WHERE ip = ? LIMIT 1",
            (ip,),
        )
    except sqlite3.OperationalError as e:
        # Table/column mismatch - surface a clear error
        sys.stderr.write(f"[!] SQLite error: {e}\n")
        return None
    row = cur.fetchone()
    if not row:
        return None
    # convert Row to simple dict with non-null fields
    out = {}
    for k in row.keys():
        v = row[k]
        if v is not None:
            out[k] = v
    return out

# --- Format detection ---
def sniff_format(sample_lines: Iterable[str]) -> str:
    """
    Detect format from first few non-empty lines.
    Returns: 'json_array', 'ndjson', 'csv', or 'text'
    """
    sample = []
    for i, line in enumerate(sample_lines):
        if i >= 20: break
        s = line.strip()
        if not s: 
            continue
        sample.append(s)
    if not sample:
        return "text"
    first = sample[0]
    # JSON array?
    if first.startswith('['):
        return "json_array"
    # NDJSON? (each line parseable as JSON)
    ndjson_ok = True
    for s in sample:
        if not (s.startswith('{') or s.startswith('[')):
            ndjson_ok = False
            break
        try:
            json.loads(s)
        except Exception:
            ndjson_ok = False
            break
    if ndjson_ok:
        return "ndjson"
    # CSV sniff using csv.Sniffer
    try:
        sniffer = csv.Sniffer()
        combined = "\n".join(sample)
        dialect = sniffer.sniff(combined)
        # basic sanity: must have comma/tab/pipe delim
        if dialect.delimiter in (',','\t','|',';'):
            return "csv"
    except Exception:
        pass
    # fallback text
    return "text"

# --- Utilities ---
def find_first_ip_in_record(obj: dict) -> Optional[Tuple[str, str]]:
    """Given a dict (JSON/CSV row), try to find a key with IP and return (key, ip)."""
    for k in obj.keys():
        kl = k.lower()
        if any(tok in kl for tok in IP_CANDIDATES) or kl.endswith("_ip"):
            v = obj.get(k)
            if isinstance(v, str):
                # find ip inside the string
                m4 = IPv4_RE.search(v)
                if m4:
                    return (k, m4.group(0))
                m6 = IPv6_RE.search(v)
                if m6:
                    return (k, m6.group(0))
    # fallback: scan all string values for ip pattern
    for k, v in obj.items():
        if isinstance(v, str):
            m4 = IPv4_RE.search(v)
            if m4:
                return (k, m4.group(0))
            m6 = IPv6_RE.search(v)
            if m6:
                return (k, m6.group(0))
    return None

def find_ips_in_line(line: str) -> list:
    """Return list of unique IPs found in the text line (IPv4 and IPv6)."""
    ipv4s = IPv4_RE.findall(line)
    ipv6s = IPv6_RE.findall(line)
    # ipv6 regex may capture groups; normalize
    ipv6s = [m if isinstance(m, str) else m[0] for m in ipv6s]
    ips = []
    for ip in ipv4s + ipv6s:
        if ip not in ips:
            ips.append(ip)
    return ips

# --- JSON array streaming parser (top-level array of objects) ---
def stream_json_array(fd):
    """
    Generator that yields parsed JSON objects from a top-level JSON array in fd.
    This is a lightweight streaming parser that does not require external deps.
    It assumes the file contains a single top-level array: [ {...}, {...}, ... ]
    Works by scanning braces and extracting object substrings.
    """
    buf = ""
    depth = 0
    in_string = False
    escape = False
    reading_obj = False
    # read char-by-char
    while True:
        ch = fd.read(8192)
        if not ch:
            break
        for c in ch:
            if not reading_obj:
                if c.isspace():
                    continue
                if c == '[':
                    reading_obj = True
                    continue
                # skip until array starts
                continue
            # reading objects inside array
            buf += c
            if in_string:
                if escape:
                    escape = False
                elif c == '\\':
                    escape = True
                elif c == '"':
                    in_string = False
                continue
            else:
                if c == '"':
                    in_string = True
                elif c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        # found full object
                        obj_text = buf.strip().rstrip(',')
                        buf = ""
                        # skip possible whitespace and comma handled
                        try:
                            yield json.loads(obj_text)
                        except Exception:
                            # yield raw if parse fails
                            yield None
                elif c == ']':
                    return
    # end

# --- Main processing functions per-format ---
def process_text_stream(conn, infile, outfile, stats):
    for line in infile:
        line = line.rstrip("\n")
        stats['lines'] += 1
        ips = find_ips_in_line(line)
        enrichments = []
        for ip in ips:
            info = lookup_ip(conn, ip)
            if info:
                enrichments.append({"ip": ip, **info})
                stats['matches'] += 1

        # Always write the original line as-is
        outfile.write(line + "\n")

        # For each matched IP, append an enrichment line without changing log structure
        for e in enrichments:
            fg_line = (
                f"# FG: ip={e.get('ip','')} "
                f"risk={e.get('risk','')} "
                f"threat={e.get('threat','')} "
                f"asn={e.get('asn','')} "
                f"asn_org={e.get('asn_organization') or e.get('organization') or e.get('isp','')} "
                f"isp={e.get('isp','')} "
                f"organization={e.get('organization','')} "
                f"isocode={e.get('isocode','')} "
                f"country={e.get('country','')} "
                f"connection_type={e.get('connection_type','')}"
            )
            outfile.write(fg_line.strip() + "\n")

def process_ndjson(conn, infile, outfile, stats):
    for raw in infile:
        raw = raw.strip()
        if not raw:
            continue
        stats['lines'] += 1
        try:
            obj = json.loads(raw)
        except Exception:
            # fallback to text append if unparseable
            ips = find_ips_in_line(raw)
            enrichments = []
            for ip in ips:
                info = lookup_ip(conn, ip)
                if info:
                    enrichments.append({"ip": ip, **info})
                    stats['matches'] += 1
            if enrichments:
                outfile.write(raw + " | " + json.dumps(enrichments, separators=(',', ':')) + "\n")
            else:
                outfile.write(raw + "\n")
            continue
        # try to find ip field
        found = find_first_ip_in_record(obj)
        if found:
            _, ip = found
            info = lookup_ip(conn, ip)
            if info:
                obj['fraudguard'] = info
                stats['matches'] += 1
        outfile.write(json.dumps(obj, ensure_ascii=False) + "\n")

def process_csv(conn, infile, outfile, stats):
    # detect delimiter and header
    sample = infile.read(8192)
    infile.seek(0)
    try:
        sniffer = csv.Sniffer()
        dialect = sniffer.sniff(sample)
    except Exception:
        dialect = csv.get_dialect('excel')
    reader = csv.DictReader(infile, dialect=dialect)
    fieldnames = list(reader.fieldnames or [])
    # find ip column
    ip_col = None
    for col in fieldnames:
        if col and any(tok in col.lower() for tok in IP_CANDIDATES):
            ip_col = col
            break
    # if not found, fallback to first column that looks like IP in first non-empty row
    peek_row = None
    if ip_col is None:
        for r in reader:
            peek_row = r
            break
        if peek_row:
            for k, v in peek_row.items():
                if isinstance(v, str) and (IPv4_RE.search(v) or IPv6_RE.search(v)):
                    ip_col = k
                    break
    # rewind reader: reopen infile
    infile.seek(0)
    reader = csv.DictReader(infile, dialect=dialect)
    # add columns for enrichment
    add_cols = [
        'fraudguard_risk',
        'fraudguard_threat',
        'fraudguard_asn',
        'fraudguard_asn_organization',
        'fraudguard_isp',
        'fraudguard_organization',
        'fraudguard_isocode',
        'fraudguard_country',
        'fraudguard_connection_type'
    ]
    writer_fieldnames = fieldnames + add_cols
    writer = csv.DictWriter(outfile, fieldnames=writer_fieldnames, extrasaction='ignore', dialect=dialect)
    writer.writeheader()
    for r in reader:
        stats['lines'] += 1
        ip = None
        if ip_col:
            ip_val = r.get(ip_col, "") or ""
            # may include full text; extract ip if present
            m4 = IPv4_RE.search(ip_val)
            if m4:
                ip = m4.group(0)
            else:
                m6 = IPv6_RE.search(ip_val)
                if m6:
                    ip = m6.group(0)
        if not ip:
            # try scanning all string fields
            for v in r.values():
                if isinstance(v, str):
                    m4 = IPv4_RE.search(v)
                    if m4:
                        ip = m4.group(0)
                        break
                    m6 = IPv6_RE.search(v)
                    if m6:
                        ip = m6.group(0)
                        break
        if ip:
            info = lookup_ip(conn, ip)
            if info:
                r['fraudguard_risk'] = info.get('risk')
                r['fraudguard_threat'] = info.get('threat')
                r['fraudguard_asn'] = info.get('asn')
                r['fraudguard_asn_organization'] = info.get('asn_organization') or info.get('organization') or info.get('isp')
                r['fraudguard_isp'] = info.get('isp')
                r['fraudguard_organization'] = info.get('organization')
                r['fraudguard_isocode'] = info.get('isocode')
                r['fraudguard_country'] = info.get('country')
                r['fraudguard_connection_type'] = info.get('connection_type')
                stats['matches'] += 1
            else:
                r['fraudguard_risk'] = ""
                r['fraudguard_threat'] = ""
                r['fraudguard_asn'] = ""
                r['fraudguard_asn_organization'] = ""
                r['fraudguard_isp'] = ""
                r['fraudguard_organization'] = ""
                r['fraudguard_isocode'] = ""
                r['fraudguard_country'] = ""
                r['fraudguard_connection_type'] = ""
        else:
            r['fraudguard_risk'] = ""
            r['fraudguard_threat'] = ""
            r['fraudguard_asn'] = ""
            r['fraudguard_asn_organization'] = ""
            r['fraudguard_isp'] = ""
            r['fraudguard_organization'] = ""
            r['fraudguard_isocode'] = ""
            r['fraudguard_country'] = ""
            r['fraudguard_connection_type'] = ""
        writer.writerow(r)

def process_json_array(conn, infile, outfile, stats):
    # write opening '['
    outfile.write("[\n")
    first = True
    for obj in stream_json_array(infile):
        if obj is None:
            # skip or write raw?
            continue
        stats['lines'] += 1
        found = find_first_ip_in_record(obj)
        if found:
            _, ip = found
            info = lookup_ip(conn, ip)
            if info:
                obj['fraudguard'] = info
                stats['matches'] += 1
        # write with indentation
        if not first:
            outfile.write(",\n")
        outfile.write(json.dumps(obj, ensure_ascii=False))
        first = False
    outfile.write("\n]\n")

# --- Main ---
def main():
    ap = argparse.ArgumentParser(description="FraudGuard Offline SQLite Enricher (auto format detect)")
    ap.add_argument("--db", required=True, help="Path to offline SQLite (fg-database.sqlite)")
    ap.add_argument("--input", help="Input file (defaults to stdin)")
    ap.add_argument("--output", help="Output file (defaults to stdout)")
    ap.add_argument("--min-risk", type=int, default=0, help="Only attach enrichment when risk >= N (default: 0)")
    args = ap.parse_args()

    conn = open_db(args.db)
    infile = open(args.input, "r", encoding="utf-8", errors="ignore") if args.input else sys.stdin
    outfile = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout

    # peek sample for sniffing
    sample_lines = []
    # read up to 64KB for sniffing (line-oriented)
    for _ in range(100):
        line = infile.readline()
        if not line:
            break
        sample_lines.append(line)
    # reset to beginning for file input, or for stdin we use what we buffered
    if args.input:
        infile.seek(0)
    else:
        # for stdin, create an iterator that yields buffered lines first then remainder
        def stdin_iter():
            for l in sample_lines:
                yield l
            for l in sys.stdin:
                yield l
        # wrap as iterable for processing functions that accept file-like
        # but we need a file-like object for some functions (CSV reader expects .read), so
        # fallback: create a temporary in-memory buffer if small; otherwise write to a temp file.
        # Simpler: join sample_lines + rest from stdin into an iterator; functions read line-by-line.
        pass

    fmt = sniff_format(iter(sample_lines))
    stats = {'lines': 0, 'matches': 0}

    # If stdin and no args.input, handle differently for JSON array (stream_json_array expects file-like)
    # For simplicity, if input is stdin, we already have `infile` as sys.stdin and we can't seek;
    # we handled sample_lines above but still keep `infile` as sys.stdin for streaming functions.
    # For CSV which uses csv.DictReader (which needs .read), stdin may not support seek; but reading streaming CSV is okay.
    try:
        if fmt == "text":
            # if we are using sample_lines + stdin, need to wrap iteration
            if args.input:
                process_text_stream(conn, infile, outfile, stats)
            else:
                # stdin case: first yield buffered sample_lines then iterate sys.stdin
                for line in sample_lines:
                    process_text_stream(conn, iter([line]), outfile, stats)  # small hack: process single line
                # now continue with remaining stdin
                for line in sys.stdin:
                    process_text_stream(conn, iter([line]), outfile, stats)
        elif fmt == "ndjson":
            # If input is a file, the reader functions accept file-like; for stdin we need to combine sample_lines + sys.stdin
            if args.input:
                process_ndjson(conn, infile, outfile, stats)
            else:
                # process buffered lines first, then sys.stdin
                for line in sample_lines:
                    process_ndjson(conn, iter([line]), outfile, stats)
                for line in sys.stdin:
                    process_ndjson(conn, iter([line]), outfile, stats)
        elif fmt == "csv":
            # CSV requires file-like object; for stdin we have to create a stream combining sample and rest
            if args.input:
                process_csv(conn, infile, outfile, stats)
            else:
                # create a simple wrapper iterator that provides .read() for csv
                all_text = "".join(sample_lines) + sys.stdin.read()
                from io import StringIO
                s = StringIO(all_text)
                process_csv(conn, s, outfile, stats)
        elif fmt == "json_array":
            if args.input:
                process_json_array(conn, infile, outfile, stats)
            else:
                # combine buffered + stdin into a StringIO for streaming parser
                all_text = "".join(sample_lines) + sys.stdin.read()
                from io import StringIO
                s = StringIO(all_text)
                process_json_array(conn, s, outfile, stats)
        else:
            # fallback to text mode
            process_text_stream(conn, infile, outfile, stats)
    finally:
        if args.input:
            infile.close()
        if args.output:
            outfile.close()
        conn.close()

if __name__ == "__main__":
    main()
