#!/usr/bin/env python
"""Detect direct API access to AAP platform components.

Parses nginx access logs (from SOSReport, must-gather, or raw log files)
and identifies requests that bypass the AAP Gateway — i.e. requests that
have NEITHER the X-Trusted-Proxy header NOR a DAB JWT token.

Nginx log format expected (ANSTRAT-1840):

    $remote_addr - $remote_user [$time_local] "$request" $status
    $body_bytes_sent "$http_referer" "$http_user_agent"
    "$http_x_forwarded_for" $trusted_proxy_present $dab_jwt_present

The last two fields are mapped via nginx ``map`` directives:
  - ``trusted_proxy_present``: "trusted-proxy" or "-"
  - ``dab_jwt_present``: "dab-jwt" or "-"

A request with BOTH fields set to "-" is considered direct access.
"""

from __future__ import print_function

import argparse
import collections
import glob
import gzip
import io
import os
import re
import sys

__version__ = "0.1.0"

# ── Nginx log parsing ──────────────────────────────────────────────────

# Matches the combined log format with the two trailing marker fields.
# Groups: remote_addr, remote_user, time_local, request, status,
#         body_bytes_sent, http_referer, http_user_agent,
#         http_x_forwarded_for, trusted_proxy, dab_jwt
_LOG_RE = re.compile(
    r'^(\S+)'                          # remote_addr
    r' - '
    r'(\S+)'                           # remote_user
    r' \[([^\]]+)\]'                   # time_local
    r' "([^"]*)"'                      # request
    r' (\d{3})'                        # status
    r' (\d+|-)'                        # body_bytes_sent
    r' "([^"]*)"'                      # http_referer
    r' "([^"]*)"'                      # http_user_agent
    r' "([^"]*)"'                      # http_x_forwarded_for
    r' (\S+)'                          # trusted_proxy_present
    r' (\S+)'                          # dab_jwt_present
    r'\s*$'
)

# Legacy format (without the two trailing fields) — used to detect logs
# that have NOT been updated to the ANSTRAT-1840 format.
_LEGACY_LOG_RE = re.compile(
    r'^(\S+)'                          # remote_addr
    r' - '
    r'(\S+)'                           # remote_user
    r' \[([^\]]+)\]'                   # time_local
    r' "([^"]*)"'                      # request
    r' (\d{3})'                        # status
    r' (\d+|-)'                        # body_bytes_sent
    r' "([^"]*)"'                      # http_referer
    r' "([^"]*)"'                      # http_user_agent
    r' "([^"]*)"'                      # http_x_forwarded_for
    r'\s*$'
)

# OCP format: Kubernetes timestamp prefix + combined log format with
# extra fields (rid=..., req_len=...) before the two trailing markers.
# Example:
#   2026-03-11T06:54:11.972Z 172.19.0.29 - - [11/Mar/2026:06:54:11 +0000]
#   "GET /api/v2/jobs/ HTTP/1.1" 200 1802 "-" "python-requests/2.32.3"
#   "172.19.0.29" rid=abc123 trusted-proxy dab-jwt
_OCP_LOG_RE = re.compile(
    r'^\S+'                            # k8s timestamp (e.g. 2026-03-11T06:54:11.972Z)
    r' (\S+)'                          # remote_addr
    r' - '
    r'(\S+)'                           # remote_user
    r' \[([^\]]+)\]'                   # time_local
    r' "([^"]*)"'                      # request
    r' (\d{3})'                        # status
    r' (\d+|-)'                        # body_bytes_sent
    r' "([^"]*)"'                      # http_referer
    r' "([^"]*)"'                      # http_user_agent
    r' "([^"]*)"'                      # http_x_forwarded_for
    r'(?: \S+=\S+)*'                   # extra k=v fields (rid=..., req_len=...)
    r' (\S+)'                          # trusted_proxy_present
    r' (\S+)'                          # dab_jwt_present
    r'\s*$'
)

# Key=value format used by AAP containerized nginx (sosreport from
# ``sos report -k aap_containerized``).  Example line:
#   "11/Mar/2026:10:35:20 +0000" client=3.83.224.83 x_forwarded_for=-
#   ... request="GET /api/v2/jobs/ HTTP/1.1" ... status=200 ...
#   user_agent="python-requests/2.32.3" ... trusted_proxy=- dab_jwt=-
_KV_LOG_RE = re.compile(
    r'^"([^"]+)"'                      # time_local (quoted)
    r' client=(\S+)'                   # remote_addr (client)
    r' x_forwarded_for=(\S+)'         # http_x_forwarded_for
    r'.*?'
    r' request="([^"]*)"'             # request
    r'.*?'
    r' status=(\d{3})'                # status
    r'.*?'
    r' body_bytes_sent=(\d+)'         # body_bytes_sent
    r'.*?'
    r' referer=(\S+|"[^"]*")'         # http_referer
    r'.*?'
    r' user_agent="([^"]*)"'          # http_user_agent
    r'.*?'
    r' trusted_proxy=(\S+)'           # trusted_proxy_present
    r' dab_jwt=(\S+)'                 # dab_jwt_present
    r'\s*$'
)

# ── Paths that are "expected" direct access ─────────────────────────

# Health / readiness / startup probes and internal Kubernetes traffic.
_FILTERED_PATH_PREFIXES = (
    "/api/v2/ping",
    "/api/v2/config",
    "/api/gateway/v1/health",
    "/healthz",
    "/readyz",
    "/livez",
    "/_debug/",
    "/nginx_status",
    "/static/",
    "/favicon.ico",
)

# User-agent substrings that indicate internal probes (case-insensitive).
_FILTERED_UA_SUBSTRINGS = (
    "kube-probe",
    "kubernetes",
    "haproxy",
    "envoy/hc",
    "ansible-httpget",
)


# ── Input auto-detection ────────────────────────────────────────────

class InputType(object):
    SOSREPORT = "sosreport"
    MUST_GATHER = "must-gather"
    LOG_FILE = "logfile"


def _detect_input_type(path):
    """Return (InputType, component_log_map) for the given path.

    ``component_log_map`` is a dict mapping component name to a list of
    log file paths found within the input.
    """
    if os.path.isfile(path):
        return InputType.LOG_FILE, {"unknown": [path]}

    if not os.path.isdir(path):
        return None, {}

    # SOSReport (OCP): look for var/log/containers/ or var/log/pods/
    sos_container_logs = os.path.join(path, "var", "log", "containers")
    sos_pod_logs = os.path.join(path, "var", "log", "pods")
    if os.path.isdir(sos_container_logs) or os.path.isdir(sos_pod_logs):
        return InputType.SOSREPORT, _find_sos_logs(path)

    # SOSReport (containerized): look for sos_commands/aap_containerized/
    containerized_logs = _find_containerized_sos_logs(path)
    if containerized_logs:
        return InputType.SOSREPORT, containerized_logs

    # must-gather: look for namespaces/ directory (OpenShift style)
    namespaces_dir = _find_namespaces_dir(path)
    if namespaces_dir is not None:
        return InputType.MUST_GATHER, _find_must_gather_logs(namespaces_dir)

    # Fallback: try to find any nginx log files recursively
    logs = _find_nginx_logs_recursive(path)
    if logs:
        return InputType.LOG_FILE, {"unknown": logs}

    return None, {}


def _find_namespaces_dir(base):
    """Walk up to two levels looking for a 'namespaces' directory."""
    # Direct child
    candidate = os.path.join(base, "namespaces")
    if os.path.isdir(candidate):
        return candidate
    # One level deeper (must-gather typically has a random-named subdir)
    for entry in os.listdir(base):
        candidate = os.path.join(base, entry, "namespaces")
        if os.path.isdir(candidate):
            return candidate
    return None


def _component_from_pod_name(pod_name):
    """Infer component name from a Kubernetes pod name."""
    pod_lower = pod_name.lower()
    if "controller" in pod_lower or "awx" in pod_lower or "tower" in pod_lower:
        return "controller"
    if "hub" in pod_lower or "galaxy" in pod_lower or "pulp" in pod_lower:
        return "hub"
    if "eda" in pod_lower:
        return "eda"
    if "gateway" in pod_lower:
        return "gateway"
    if "lightspeed" in pod_lower:
        return "lightspeed"
    return "unknown"


def _component_from_container_log_name(filename):
    """Infer component name from a containerized AAP log filename.

    Handles names like ``automation-controller-web.log`` or
    ``automationcontroller-0-automation-controller-web.log``.
    """
    lower = filename.lower()
    if "controller" in lower:
        return "controller"
    if "hub" in lower:
        return "hub"
    if "eda" in lower:
        return "eda"
    if "gateway" in lower:
        return "gateway"
    if "lightspeed" in lower:
        return "lightspeed"
    return "unknown"


def _find_sos_logs(base):
    """Find nginx access logs in a SOSReport directory tree."""
    component_logs = collections.defaultdict(list)
    for log_dir in ("var/log/containers", "var/log/pods"):
        search_base = os.path.join(base, log_dir)
        if not os.path.isdir(search_base):
            continue
        for root, _dirs, files in os.walk(search_base):
            for fname in files:
                if "nginx" in fname.lower() and "error" not in fname.lower():
                    full = os.path.join(root, fname)
                    comp = _component_from_pod_name(
                        os.path.basename(root) if log_dir.endswith("pods") else fname
                    )
                    component_logs[comp].append(full)
    return dict(component_logs)


def _find_containerized_sos_logs(base):
    """Find nginx access logs in a containerized AAP SOSReport.

    Containerized sosreports place container logs under
    ``sos_commands/aap_containerized/aap_container_logs/``.  The web
    logs (which contain nginx access entries) are named like
    ``automation-controller-web.log``.
    """
    component_logs = collections.defaultdict(list)

    # Walk to find sos_commands/aap_containerized/aap_container_logs/
    for root, dirs, files in os.walk(base):
        if os.path.basename(root) == "aap_container_logs":
            parent = os.path.dirname(root)
            if os.path.basename(parent) == "aap_containerized":
                for fname in files:
                    if fname.endswith("-web.log") or fname.endswith("-web.log.gz"):
                        full = os.path.join(root, fname)
                        comp = _component_from_container_log_name(fname)
                        component_logs[comp].append(full)

    return dict(component_logs)


def _find_must_gather_logs(namespaces_dir):
    """Find nginx access logs in an OpenShift must-gather."""
    component_logs = collections.defaultdict(list)
    for ns_entry in os.listdir(namespaces_dir):
        ns_path = os.path.join(namespaces_dir, ns_entry)
        pods_dir = os.path.join(ns_path, "pods")
        if not os.path.isdir(pods_dir):
            continue
        for pod_name in os.listdir(pods_dir):
            pod_path = os.path.join(pods_dir, pod_name)
            if not os.path.isdir(pod_path):
                continue
            # Look for nginx container logs
            nginx_dir = os.path.join(pod_path, "nginx", "nginx", "logs")
            if not os.path.isdir(nginx_dir):
                # Also check flat structure
                nginx_dir = os.path.join(pod_path, "nginx")
                if not os.path.isdir(nginx_dir):
                    continue
            for root, _dirs, files in os.walk(nginx_dir):
                for fname in files:
                    if fname.endswith(".log") or fname.endswith(".log.gz"):
                        full = os.path.join(root, fname)
                        comp = _component_from_pod_name(pod_name)
                        component_logs[comp].append(full)
    return dict(component_logs)


def _find_nginx_logs_recursive(base):
    """Fallback: find any file that looks like an nginx access log."""
    results = []
    for root, _dirs, files in os.walk(base):
        for fname in files:
            lower = fname.lower()
            if ("access" in lower or "nginx" in lower) and "error" not in lower:
                if lower.endswith(".log") or lower.endswith(".log.gz"):
                    results.append(os.path.join(root, fname))
    return results


# ── Log parsing ─────────────────────────────────────────────────────

LogEntry = collections.namedtuple(
    "LogEntry",
    [
        "remote_addr",
        "remote_user",
        "time_local",
        "request",
        "status",
        "body_bytes_sent",
        "http_referer",
        "http_user_agent",
        "http_x_forwarded_for",
        "trusted_proxy",
        "dab_jwt",
        "raw_line",
    ],
)


def _open_log_file(path):
    """Open a log file, handling gzip transparently."""
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return io.open(path, "r", errors="replace")


def _is_filtered(entry):
    """Return True if this request should be excluded from direct-access reports."""
    # Parse method and path from the request field
    parts = entry.request.split()
    if len(parts) >= 2:
        path = parts[1].split("?")[0]  # strip query string
    else:
        path = entry.request

    for prefix in _FILTERED_PATH_PREFIXES:
        if path.startswith(prefix):
            return True

    ua_lower = entry.http_user_agent.lower()
    for substr in _FILTERED_UA_SUBSTRINGS:
        if substr in ua_lower:
            return True

    return False


def parse_log_lines(lines, source_label=""):
    """Parse log lines and yield (LogEntry, is_direct_access, format_ok).

    ``format_ok`` is True when the line matches the expected ANSTRAT-1840
    format. Lines matching the legacy format are yielded with
    ``format_ok=False`` so callers can detect un-upgraded logs.
    """
    for raw_line in lines:
        line = raw_line.rstrip("\n").rstrip("\r")
        if not line:
            continue

        m = _LOG_RE.match(line)
        if m:
            entry = LogEntry(
                remote_addr=m.group(1),
                remote_user=m.group(2),
                time_local=m.group(3),
                request=m.group(4),
                status=m.group(5),
                body_bytes_sent=m.group(6),
                http_referer=m.group(7),
                http_user_agent=m.group(8),
                http_x_forwarded_for=m.group(9),
                trusted_proxy=m.group(10),
                dab_jwt=m.group(11),
                raw_line=line,
            )
            is_direct = entry.trusted_proxy == "-" and entry.dab_jwt == "-"
            yield entry, is_direct, True
            continue

        # OCP format (k8s timestamp + combined + extra k=v fields + markers)
        ocp = _OCP_LOG_RE.match(line)
        if ocp:
            entry = LogEntry(
                remote_addr=ocp.group(1),
                remote_user=ocp.group(2),
                time_local=ocp.group(3),
                request=ocp.group(4),
                status=ocp.group(5),
                body_bytes_sent=ocp.group(6),
                http_referer=ocp.group(7),
                http_user_agent=ocp.group(8),
                http_x_forwarded_for=ocp.group(9),
                trusted_proxy=ocp.group(10),
                dab_jwt=ocp.group(11),
                raw_line=line,
            )
            is_direct = entry.trusted_proxy == "-" and entry.dab_jwt == "-"
            yield entry, is_direct, True
            continue

        # Key=value format from containerized AAP sosreports
        kv = _KV_LOG_RE.match(line)
        if kv:
            referer = kv.group(7)
            if referer.startswith('"') and referer.endswith('"'):
                referer = referer[1:-1]
            entry = LogEntry(
                remote_addr=kv.group(2),
                remote_user="-",
                time_local=kv.group(1),
                request=kv.group(4),
                status=kv.group(5),
                body_bytes_sent=kv.group(6),
                http_referer=referer,
                http_user_agent=kv.group(8),
                http_x_forwarded_for=kv.group(3),
                trusted_proxy=kv.group(9),
                dab_jwt=kv.group(10),
                raw_line=line,
            )
            is_direct = entry.trusted_proxy == "-" and entry.dab_jwt == "-"
            yield entry, is_direct, True
            continue

        # Check if it matches legacy format (no trailing marker fields)
        lm = _LEGACY_LOG_RE.match(line)
        if lm:
            entry = LogEntry(
                remote_addr=lm.group(1),
                remote_user=lm.group(2),
                time_local=lm.group(3),
                request=lm.group(4),
                status=lm.group(5),
                body_bytes_sent=lm.group(6),
                http_referer=lm.group(7),
                http_user_agent=lm.group(8),
                http_x_forwarded_for=lm.group(9),
                trusted_proxy=None,
                dab_jwt=None,
                raw_line=line,
            )
            yield entry, False, False
            continue

        # Non-matching lines (binary, empty, other formats) are silently skipped


# ── Analysis & reporting ────────────────────────────────────────────

class ComponentReport(object):
    """Aggregates direct-access data for one component."""

    def __init__(self, name):
        self.name = name
        self.total_requests = 0
        self.direct_access_count = 0
        self.filtered_count = 0
        self.legacy_format_count = 0
        # path -> count
        self.direct_by_path = collections.Counter()
        # remote_addr -> count
        self.direct_by_ip = collections.Counter()
        # raw lines
        self.direct_lines = []

    @property
    def via_gateway_count(self):
        return self.total_requests - self.direct_access_count - self.filtered_count - self.legacy_format_count


def analyze(input_path, output_dir=None, include_filtered=False):
    """Run full analysis.  Returns (list[ComponentReport], errors)."""
    input_type, component_logs = _detect_input_type(input_path)
    if input_type is None:
        return [], ["Could not detect input type for: %s" % input_path]

    errors = []
    reports = []

    if not component_logs:
        errors.append("No nginx access log files found in: %s" % input_path)
        return reports, errors

    for comp_name in sorted(component_logs):
        report = ComponentReport(comp_name)
        for log_path in sorted(component_logs[comp_name]):
            try:
                fh = _open_log_file(log_path)
            except (IOError, OSError) as exc:
                errors.append("Cannot open %s: %s" % (log_path, exc))
                continue
            try:
                for entry, is_direct, format_ok in parse_log_lines(fh, log_path):
                    report.total_requests += 1
                    if not format_ok:
                        report.legacy_format_count += 1
                        continue
                    if is_direct:
                        if _is_filtered(entry) and not include_filtered:
                            report.filtered_count += 1
                            continue
                        report.direct_access_count += 1
                        parts = entry.request.split()
                        path = parts[1].split("?")[0] if len(parts) >= 2 else entry.request
                        report.direct_by_path[path] += 1
                        report.direct_by_ip[entry.remote_addr] += 1
                        report.direct_lines.append(entry.raw_line)
                    else:
                        if not _is_filtered(entry):
                            pass  # normal gateway traffic
                        else:
                            report.filtered_count += 1
            finally:
                fh.close()
        reports.append(report)

    return reports, errors


def print_summary(reports, errors, input_type, file=None):
    """Print a human-readable summary to stdout (or the given file)."""
    if file is None:
        file = sys.stdout

    print("=" * 60, file=file)
    print("AAP Direct Component Access Report", file=file)
    print("=" * 60, file=file)
    print("", file=file)

    if errors:
        for err in errors:
            print("WARNING: %s" % err, file=file)
        print("", file=file)

    has_direct = False
    has_legacy = False
    for report in reports:
        print("Component: %s" % report.name, file=file)
        print("  Total log lines:     %d" % report.total_requests, file=file)
        print("  Via gateway:         %d" % report.via_gateway_count, file=file)
        print("  Direct access:       %d" % report.direct_access_count, file=file)
        print("  Filtered (probes):   %d" % report.filtered_count, file=file)
        if report.legacy_format_count > 0:
            print("  Legacy format:       %d (log format not updated)" % report.legacy_format_count, file=file)
            has_legacy = True
        print("", file=file)
        if report.direct_access_count > 0:
            has_direct = True

    if has_direct:
        print("RESULT: Direct component access DETECTED", file=file)
        print("Review the detailed report for specifics.", file=file)
    elif has_legacy:
        print("RESULT: Cannot determine — log format has not been updated", file=file)
        print("Update nginx config to include trusted_proxy_present and", file=file)
        print("dab_jwt_present fields, then collect new logs.", file=file)
    else:
        total = sum(r.total_requests for r in reports)
        if total == 0:
            print("RESULT: No log entries found", file=file)
        else:
            print("RESULT: No direct component access detected", file=file)


def write_detailed_report(reports, output_path):
    """Write a detailed breakdown to a file."""
    with io.open(output_path, "w", encoding="utf-8") as fh:
        fh.write(u"AAP Direct Component Access — Detailed Report\n")
        fh.write(u"=" * 60 + u"\n\n")

        for report in reports:
            if report.direct_access_count == 0:
                continue

            fh.write(u"Component: %s\n" % report.name)
            fh.write(u"-" * 40 + u"\n")
            fh.write(u"Direct access requests: %d\n\n" % report.direct_access_count)

            fh.write(u"Top paths:\n")
            for path, count in report.direct_by_path.most_common(20):
                fh.write(u"  %6d  %s\n" % (count, path))
            fh.write(u"\n")

            fh.write(u"Top source IPs:\n")
            for ip, count in report.direct_by_ip.most_common(20):
                fh.write(u"  %6d  %s\n" % (count, ip))
            fh.write(u"\n\n")


def write_raw_log(reports, output_path):
    """Write raw nginx log lines flagged as direct access."""
    with io.open(output_path, "w", encoding="utf-8") as fh:
        for report in reports:
            for line in report.direct_lines:
                fh.write(u"%s\n" % line)


# ── CLI ─────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        description="Detect direct API access to AAP platform components "
                    "by analyzing nginx access logs.",
    )
    parser.add_argument(
        "input",
        help="Path to a SOSReport directory, must-gather directory, or "
             "individual nginx access log file.",
    )
    parser.add_argument(
        "-o", "--output-dir",
        default=".",
        help="Directory to write report files to (default: current directory).",
    )
    parser.add_argument(
        "--include-filtered",
        action="store_true",
        default=False,
        help="Include health checks and probe requests in the report.",
    )
    parser.add_argument(
        "-V", "--version",
        action="version",
        version="%(prog)s " + __version__,
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    input_path = os.path.abspath(args.input)
    if not os.path.exists(input_path):
        print("Error: path does not exist: %s" % input_path, file=sys.stderr)
        return 1

    output_dir = os.path.abspath(args.output_dir)
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    input_type, _ = _detect_input_type(input_path)
    if input_type is None:
        print("Error: could not detect input type for: %s" % input_path, file=sys.stderr)
        return 1

    print("Detected input type: %s" % input_type)
    print("")

    reports, errors = analyze(input_path, output_dir, args.include_filtered)

    print_summary(reports, errors, input_type)

    # Write output files
    report_path = os.path.join(output_dir, "direct-access-report.txt")
    raw_path = os.path.join(output_dir, "direct-access-raw.log")

    write_detailed_report(reports, report_path)
    write_raw_log(reports, raw_path)

    total_direct = sum(r.direct_access_count for r in reports)
    if total_direct > 0:
        print("")
        print("Detailed report: %s" % report_path)
        print("Raw log lines:   %s" % raw_path)

    # Exit code: 2 if direct access detected, 0 otherwise
    has_legacy = any(r.legacy_format_count > 0 for r in reports)
    if total_direct > 0:
        return 2
    elif has_legacy:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
