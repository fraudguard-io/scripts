import os

import requests
from requests.auth import HTTPBasicAuth

API_BASE = "https://api.fraudguard.io"
DEFAULT_TIMEOUT = 15


class FraudGuardAuthError(RuntimeError):
    pass


class FraudGuardError(RuntimeError):
    pass


def get_creds(username: str | None, password: str | None) -> tuple[str, str]:
    u = username or os.getenv("FRAUDGUARD_USERNAME")
    p = password or os.getenv("FRAUDGUARD_PASSWORD")
    if not u or not p:
        raise FraudGuardAuthError(
            "Missing credentials. Set FRAUDGUARD_USERNAME and FRAUDGUARD_PASSWORD "
            "or pass --username/--password."
        )
    return u, p


def _do_get(url: str, username: str | None, password: str | None, timeout: int) -> dict:
    u, p = get_creds(username, password)
    resp = requests.get(url, auth=HTTPBasicAuth(u, p), timeout=timeout)

    if resp.status_code == 401:
        raise FraudGuardAuthError("Auth failed (401). Check username/password.")
    if resp.status_code >= 400:
        body = (resp.text or "").strip()
        raise FraudGuardError(f"HTTP {resp.status_code}: {body[:300]}")

    return resp.json()


def lookup_ip_v2(ip: str, username: str | None = None, password: str | None = None, timeout: int = DEFAULT_TIMEOUT) -> dict:
    return _do_get(f"{API_BASE}/v2/ip/{ip}", username=username, password=password, timeout=timeout)


def lookup_hostname_v2(hostname: str, username: str | None = None, password: str | None = None, timeout: int = DEFAULT_TIMEOUT) -> dict:
    return _do_get(f"{API_BASE}/v2/hostname/{hostname}", username=username, password=password, timeout=timeout)