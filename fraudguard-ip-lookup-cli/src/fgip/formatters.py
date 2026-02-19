import csv
import json
from io import StringIO

DEFAULT_FIELDS = [
    "ip",
    "risk_level",
    "threat",
    "country",
    "state",
    "city",
    "isp",
    "organization",
    "asn",
    "asn_organization",
    "connection_type",
    "discover_date",
]

def normalize_record(ip: str, data: dict) -> dict:
    out = {"ip": ip}
    if isinstance(data, dict):
        out.update(data)
    return out

def to_human(rec: dict) -> str:
    keys = ["ip"] + sorted([k for k in rec.keys() if k != "ip"])
    return "\n".join([f"{k}: {rec.get(k, '')}" for k in keys])

def to_ndjson(rec: dict) -> str:
    return json.dumps(rec, ensure_ascii=False)

def csv_header(fields: list[str]) -> str:
    return ",".join(fields)

def to_csv_line(rec: dict, fields: list[str]) -> str:
    sio = StringIO()
    w = csv.writer(sio)
    w.writerow([rec.get(f, "") for f in fields])
    return sio.getvalue().rstrip("\r\n")