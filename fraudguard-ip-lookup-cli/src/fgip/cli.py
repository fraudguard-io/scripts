import argparse
import ipaddress
import sys
import time
from typing import Iterable

from fgip.client import lookup_ip_v2, lookup_hostname_v2, FraudGuardAuthError, FraudGuardError
from fgip.formatters import normalize_record, to_human, to_ndjson, csv_header, to_csv_line


def iter_input_targets(arg: str | None, file_path: str | None) -> Iterable[str]:
    # Priority: arg > file > stdin
    if arg:
        yield arg.strip()
        return

    if file_path:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    else:
        if sys.stdin.isatty():
            return
        lines = sys.stdin.read().splitlines()

    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        yield s


def is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def looks_like_hostname(s: str) -> bool:
    # Allow simple hostnames/FQDNs; reject URLs and obvious garbage.
    if not s or len(s) > 253:
        return False
    if "://" in s or "/" in s or " " in s:
        return False
    host = s.strip().rstrip(".")
    labels = host.split(".")
    if len(labels) < 2:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
    for lab in labels:
        if not (1 <= len(lab) <= 63):
            return False
        if lab[0] == "-" or lab[-1] == "-":
            return False
        if any(ch not in allowed for ch in lab):
            return False
    return True


def main() -> None:
    p = argparse.ArgumentParser(
        prog="fgip",
        description="FraudGuard IP/Hostname Reputation Lookup (V2)",
    )

    p.add_argument("target", nargs="?", help="IPv4, IPv6, or hostname (e.g. fraudguard.io)")
    p.add_argument("-f", "--file", help="File with IPs/hostnames (one per line)")
    p.add_argument("--json", action="store_true", help="NDJSON output (one JSON per line)")
    p.add_argument("--csv", action="store_true", help="CSV output")
    p.add_argument(
        "--only",
        default=None,
        help="Output only selected field(s) per record (comma-separated, e.g. --only asn or --only asn,asn_organization).",
    )
    p.add_argument("--min-risk", type=int, default=None, help="Only output results with risk_level >= N (1-5)")
    p.add_argument("--threat", default=None, help="Only output results with threat == VALUE")
    p.add_argument("--username", default=None, help="FraudGuard username (overrides env)")
    p.add_argument("--password", default=None, help="FraudGuard password (overrides env)")
    p.add_argument("--timeout", type=int, default=15, help="HTTP timeout seconds")

    args = p.parse_args()

    if args.csv and args.json:
        print("Choose only one of --csv or --json.", file=sys.stderr)
        raise SystemExit(2)

    only_fields: list[str] = []
    if args.only:
        if not isinstance(args.only, str):
            print("--only requires a field name.", file=sys.stderr)
            raise SystemExit(2)
        only_fields = [f.strip() for f in args.only.split(",") if f.strip()]
        if not only_fields:
            print("--only requires at least one field name.", file=sys.stderr)
            raise SystemExit(2)

    # Field selection
    fields = None
    csv_rows: list[dict] = []
    csv_all_fields = bool(args.csv and not only_fields)

    # Hardcoded rate limit: 1 lookup every 2 seconds
    delay = 2.0

    # Prepare targets
    targets = list(iter_input_targets(args.target, args.file))

    # CSV header
    if args.csv and only_fields:
        print(csv_header(only_fields))

    any_output = False
    last_ts = 0.0

    for raw in targets:
        target = raw.strip()

        is_ip = is_valid_ip(target)
        is_host = looks_like_hostname(target)

        if not is_ip and not is_host:
            print(f"Invalid IP/hostname: {target}", file=sys.stderr)
            continue

        # pacing
        now = time.time()
        if last_ts and delay:
            sleep_for = (last_ts + delay) - now
            if sleep_for > 0:
                time.sleep(sleep_for)

        try:
            if is_ip:
                data = lookup_ip_v2(target, username=args.username, password=args.password, timeout=args.timeout)
            else:
                data = lookup_hostname_v2(target, username=args.username, password=args.password, timeout=args.timeout)

            rec = normalize_record(target, data)
        except FraudGuardAuthError as e:
            print(str(e), file=sys.stderr)
            raise SystemExit(3)
        except FraudGuardError as e:
            print(f"{target}: {e}", file=sys.stderr)
            continue
        except Exception as e:
            print(f"{target}: unexpected error: {e}", file=sys.stderr)
            continue
        finally:
            last_ts = time.time()

        # filters
        if args.min_risk is not None:
            try:
                r = int(rec.get("risk_level") or 0)
            except Exception:
                r = 0
            if r < args.min_risk:
                continue

        if args.threat is not None and (rec.get("threat") != args.threat):
            continue

        any_output = True

        if only_fields:
            # Build an output object with selected fields in a stable order.
            out_obj: dict = {}
            for k in only_fields:
                v = rec.get(k, "")
                if v is None:
                    v = ""
                out_obj[k] = v

            if args.json:
                print(to_ndjson(out_obj))
            elif args.csv:
                print(to_csv_line(out_obj, only_fields))
            else:
                vals = [str(out_obj.get(k, "")) for k in only_fields]
                print("\t".join(vals))
        else:
            if args.json:
                print(to_ndjson(rec))
            elif args.csv:
                if csv_all_fields:
                    csv_rows.append(rec)
                else:
                    # (Should not happen now) kept for safety
                    csv_rows.append(rec)
            else:
                print(to_human(rec))
                print("")

    if args.csv and csv_all_fields:
        if csv_rows:
            keys = set()
            for r in csv_rows:
                keys.update(r.keys())
            ordered_fields = ["ip"] + sorted([k for k in keys if k != "ip"])
            print(csv_header(ordered_fields))
            for r in csv_rows:
                print(to_csv_line(r, ordered_fields))

    raise SystemExit(0 if any_output else 1)


if __name__ == "__main__":
    main()