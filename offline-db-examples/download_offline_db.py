#!/usr/bin/env python3
"""
FraudGuard.io Offline Threat DB downloader (SQLite or CSV)

For details see: https://blog.fraudguard.io/misc/2025/08/12/offline-database-article.html

- Basic Auth (FG_USERNAME / FG_PASSWORD env vars)
- Skips if already downloaded within last 60 minutes
- ETag caching (skips if upstream not modified)
- Payload validation:
    - SQLite: PRAGMA integrity_check
    - CSV: header check
- Atomic rotate
"""

import os, sys, time, sqlite3, tempfile, shutil, base64, urllib.request, urllib.error
import argparse
from pathlib import Path
import gzip, io

SQLITE_URL = "https://api.fraudguard.io/v1/offline-db/sqlite"
CSV_URL    = "https://api.fraudguard.io/v1/offline-db/csv"

EXPECTED_CSV_HEADER = "id,ip,threat,risk,asn,asn_organization,isp,organization,isocode,country,connection_type,updated_at"
SKIP_MINUTES = 60   # don't bother changing we already run a rate limit server-side

def http_get(url, username, password, etag=None, timeout=60):
    req = urllib.request.Request(url)
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    if etag:
        req.add_header("If-None-Match", etag)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read(), resp.headers.get("ETag"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return 304, b"", e.headers.get("ETag"), dict(e.headers or {})
        raise

def validate_sqlite(path: Path) -> bool:
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        res = con.execute("PRAGMA integrity_check;").fetchone()
        con.close()
        return res and res[0] == "ok"
    except Exception:
        return False

def validate_csv(path: Path) -> bool:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            header = f.readline().strip()
            return header.startswith(EXPECTED_CSV_HEADER)
    except Exception:
        return False

def main():
    parser = argparse.ArgumentParser(description="Download FraudGuard Offline Threat DB")
    parser.add_argument(
        "--format",
        choices=["sqlite", "csv"],
        default=os.getenv("FORMAT", "sqlite").lower(),
        help="Which format to download (sqlite or csv)"
    )
    args = parser.parse_args()
    fmt = args.format

    username = os.getenv("FG_USERNAME")
    password = os.getenv("FG_PASSWORD")
    if not username or not password:
        print("FG_USERNAME and FG_PASSWORD env vars must be set.", file=sys.stderr)
        sys.exit(2)

    data_dir = Path("data"); data_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = data_dir / ".tmp"; tmp_dir.mkdir(parents=True, exist_ok=True)

    out_file = data_dir / ("current.sqlite" if fmt == "sqlite" else "current.csv")
    etag_file = Path(str(out_file) + ".etag")
    stamp_file = Path(str(out_file) + ".stamp")

    # Hard-coded skip: 60 minutes
    if stamp_file.exists() and (time.time() - stamp_file.stat().st_mtime) < SKIP_MINUTES * 60:
        print(f"Last download < {SKIP_MINUTES} minutes ago; skipping.")
        sys.exit(0)

    url = SQLITE_URL if fmt == "sqlite" else CSV_URL
    etag = etag_file.read_text().strip() if etag_file.exists() else None

    fd, tmp_str = tempfile.mkstemp(dir=tmp_dir)
    os.close(fd)
    tmp_path = Path(tmp_str)

    try:
        code, body, new_etag, headers = http_get(url, username, password, etag)
        # Detect gzip (either via header or magic bytes) and transparently decompress
        is_gzip = False
        try:
            enc = (headers.get("Content-Encoding") or headers.get("content-encoding") or "").lower()
            ctype = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
            is_gzip = "gzip" in enc or "application/gzip" in ctype or (len(body) >= 2 and body[:2] == b"\x1f\x8b")
        except Exception:
            pass
        if is_gzip and code == 200 and body:
            try:
                body = gzip.decompress(body)
                # Optional: adjust EXPECTED_CSV_HEADER check will work post-decompression
            except Exception as _e:
                print(f"Detected gzip but failed to decompress: {_e}", file=sys.stderr)
                sys.exit(1)

        if code == 304:
            print("Not modified (ETag).")
            stamp_file.touch()
            tmp_path.unlink(missing_ok=True)
            sys.exit(0)
        if code != 200:
            print(f"Unexpected HTTP status {code}", file=sys.stderr)
            tmp_path.unlink(missing_ok=True)
            sys.exit(1)

        tmp_path.write_bytes(body)

        # Validate payload
        if fmt == "sqlite":
            if not validate_sqlite(tmp_path):
                print("SQLite integrity check failed.", file=sys.stderr)
                tmp_path.unlink(missing_ok=True)
                sys.exit(1)
        else:
            if not validate_csv(tmp_path):
                print("CSV header check failed.", file=sys.stderr)
                tmp_path.unlink(missing_ok=True)
                sys.exit(1)

        tmp_path.replace(out_file)  # atomic rotate
        if new_etag:
            etag_file.write_text(new_etag)
        stamp_file.touch()
        print(f"Wrote {out_file}")

    except Exception as e:
        tmp_path.unlink(missing_ok=True)
        print(f"Download failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()