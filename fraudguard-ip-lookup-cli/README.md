# fraudguard-ip-lookup-cli

A tiny CLI for FraudGuard's **Get Specific IP Reputation V2** endpoint.

## Install (recommended: pipx)

```bash
pipx install fraudguard-ip-lookup-cli
# fraudguard-ip-lookup-cli

A tiny, script-friendly CLI for FraudGuard's **Get Specific IP Reputation V2** and **Hostname V2** endpoints.

- ✅ Accepts **IPv4**, **IPv6**, and **hostnames**
- ✅ Works great in pipes (`stdin`) and with files
- ✅ Output as **human**, **NDJSON** (`--json`), or **CSV** (`--csv`)
- ✅ Filter results with `--min-risk` and `--threat`
- ✅ Select fields with `--only` (perfect for shell scripting)
- ✅ Hardcoded rate limit: **1 lookup every 2 seconds**

---

## Install

```bash
pipx install "git+https://github.com/fraudguard-io/scripts.git#egg=fraudguard-ip-lookup-cli&subdirectory=fraudguard-ip-lookup-cli"
```

---

## Authentication

The CLI uses HTTP Basic Auth. Set credentials via environment variables:

```bash
export FRAUDGUARD_USERNAME="your_username"
export FRAUDGUARD_PASSWORD="your_password"
```

Or pass them per command:

```bash
fgip 8.8.8.8 --username "your_username" --password "your_password"
```

---

## Basic usage

### Single lookup

```bash
fgip 8.8.8.8
fgip 2001:4860:4860::8888
fgip fraudguard.io
```

### From stdin (pipes)

```bash
echo -e "8.8.8.8\n1.1.1.1\nfraudguard.io" | fgip
```

### From a file

```bash
fgip --file ips.txt
```

Input files should contain one value per line (IPv4/IPv6/hostname). Blank lines and comments (`# ...`) are ignored.

---

## Output modes

### Human (default)

Default output prints **all fields** returned by the FraudGuard API in a stable key order.

```bash
fgip 8.8.8.8
```

### NDJSON (`--json`)

Prints one JSON object per line (great for `jq`, log pipelines, and ingestion).

```bash
echo -e "8.8.8.8\n1.1.1.1" | fgip --json
```

Example with `jq`:

```bash
echo -e "8.8.8.8\n1.1.1.1" | fgip --json | jq -r '.ip + "\t" + (.asn|tostring)'
```

### CSV (`--csv`)

Prints CSV. When used without `--only`, CSV output includes **all fields** returned (a header row is computed from the results).

```bash
echo -e "8.8.8.8\n1.1.1.1" | fgip --csv > out.csv
```

---

## Select fields (`--only`)

Use `--only` to print **only the fields you specify**, in the order you specify (comma-separated).

### Text (tab-separated)

```bash
# Only ASN (one value per line)
echo -e "8.8.8.8\n1.1.1.1" | fgip --only asn

# IP + ASN (two columns)
echo -e "8.8.8.8\n1.1.1.1" | fgip --only ip,asn

# Common enrichment columns
echo -e "8.8.8.8\n1.1.1.1" | fgip --only ip,asn,asn_organization,connection_type,risk_level,threat
```

### JSON with only selected fields

```bash
echo -e "8.8.8.8\n1.1.1.1" | fgip --json --only ip,asn,risk_level,threat
```

### CSV with only selected fields

```bash
echo -e "8.8.8.8\n1.1.1.1" | fgip --csv --only ip,asn,asn_organization
```

---

## Filters

### `--min-risk`

Only output results where `risk_level >= N`.

```bash
cat ips.txt | fgip --json --min-risk 3
```

### `--threat`

Only output results where `threat == VALUE` (exact match).

```bash
cat ips.txt | fgip --json --threat anonymous_tracker
```

### Combine filters

```bash
cat ips.txt | fgip --only ip,risk_level,threat --min-risk 4 --threat anonymous_tracker
```

---

## Rate limiting

This CLI is intentionally rate-limited to protect your FraudGuard account and the API:

- **1 lookup every 2 seconds**

---

## Exit codes

- `0` success (at least one record printed)
- `1` no output produced (everything filtered out / invalid)
- `2` usage error (bad flags / missing input)
- `3` authentication error

---

## Development

```bash
git clone https://github.com/fraudguard-io/fraudguard-ip-lookup-cli.git
cd fraudguard-ip-lookup-cli
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

fgip 8.8.8.8
```

---

## License

MIT