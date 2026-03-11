# aap-detect-direct-component-access

Detect direct API access to Ansible Automation Platform (AAP) components
by analyzing nginx access logs.

AAP 2.7 requires all API traffic to flow through the AAP Gateway. This
tool scans nginx access logs from Controller, Hub, and EDA components to
identify requests that bypass the gateway — i.e. requests that arrive
without the `X-Trusted-Proxy` header and without a DAB JWT token.

## Requirements

- Python 3.6+ (no third-party dependencies)

## Installation

### With uvx (recommended, no install needed)

```bash
uvx --from "git+https://github.com/ansible/aap-detect-direct-component-access" aap-detect-direct-component-access /path/to/sosreport
```

### With pip

```bash
pip install "git+https://github.com/ansible/aap-detect-direct-component-access"
aap-detect-direct-component-access /path/to/sosreport
```

### Without installing

```bash
python -m aap_detect_direct_component_access /path/to/sosreport
```

Or run the script directly:

```bash
python src/aap_detect_direct_component_access/detect.py /path/to/sosreport
```

## Usage

```
aap-detect-direct-component-access [-h] [-o OUTPUT_DIR] [--include-filtered] [-V] input
```

### Arguments

| Argument | Description |
|----------|-------------|
| `input` | Path to a SOSReport directory, must-gather directory, or individual nginx access log file |
| `-o`, `--output-dir` | Directory to write report files (default: `.`) |
| `--include-filtered` | Include health checks and probe requests in the report |
| `-V`, `--version` | Show version and exit |

### Input formats

The tool auto-detects the input format:

- **SOSReport** — detected by `var/log/containers/` or `var/log/pods/` directory structure
- **must-gather** — detected by `namespaces/` directory structure (OpenShift)
- **Log file** — any individual nginx access log file (plain text or gzipped)

### Expected nginx log format

The tool requires nginx logs with the ANSTRAT-1840 marker fields appended:

```
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
"$http_referer" "$http_user_agent" "$http_x_forwarded_for"
$trusted_proxy_present $dab_jwt_present
```

If logs use the legacy format (without the trailing marker fields), the tool
will report them as "legacy format" and exit with code 3.

### Output

1. **stdout** — summary with total requests, direct access count per component
2. **`<input-name>.report.txt`** — detailed breakdown by path and source IP
3. **`<input-name>.raw.log`** — raw nginx log lines flagged as direct access

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No direct access detected |
| 1 | Error (bad input path, no logs found) |
| 2 | Direct access detected |
| 3 | Legacy log format (cannot determine) |

## Filtered requests

By default, the following are excluded from the direct-access report since
they represent expected internal traffic:

- Health check endpoints (`/api/v2/ping`, `/healthz`, `/readyz`, etc.)
- Static assets (`/static/`, `/favicon.ico`)
- Kubernetes probes (identified by `kube-probe` user-agent)
- Internal monitoring (`/nginx_status`, `/_debug/`)

Use `--include-filtered` to include these in the report.

## Running tests

```bash
python -m pytest tests/
```

Or without pytest:

```bash
python -m unittest discover -s tests
```

## License

Apache-2.0
