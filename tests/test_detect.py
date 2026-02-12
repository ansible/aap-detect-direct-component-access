"""Tests for aap_detect_direct_component_access.detect."""

from __future__ import print_function

import gzip
import io
import os
import shutil
import tempfile
import unittest

# Adjust path so we can import from src/ without installing
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aap_detect_direct_component_access.detect import (
    ComponentReport,
    InputType,
    LogEntry,
    _LOG_RE,
    _LEGACY_LOG_RE,
    _component_from_pod_name,
    _detect_input_type,
    _is_filtered,
    analyze,
    build_parser,
    main,
    parse_log_lines,
    print_summary,
    write_detailed_report,
    write_raw_log,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class TestLogRegex(unittest.TestCase):
    """Test the nginx log line regular expressions."""

    def test_new_format_gateway(self):
        line = (
            '10.0.0.1 - - [12/Feb/2026:10:00:01 +0000] '
            '"GET /api/v2/jobs/ HTTP/1.1" 200 1234 "-" '
            '"python-requests/2.28.0" "-" trusted-proxy dab-jwt'
        )
        m = _LOG_RE.match(line)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "10.0.0.1")
        self.assertEqual(m.group(4), "GET /api/v2/jobs/ HTTP/1.1")
        self.assertEqual(m.group(10), "trusted-proxy")
        self.assertEqual(m.group(11), "dab-jwt")

    def test_new_format_direct(self):
        line = (
            '10.0.0.2 - - [12/Feb/2026:10:00:03 +0000] '
            '"GET /api/v2/jobs/ HTTP/1.1" 200 1234 "-" '
            '"curl/7.68.0" "-" - -'
        )
        m = _LOG_RE.match(line)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(10), "-")
        self.assertEqual(m.group(11), "-")

    def test_legacy_format(self):
        line = (
            '10.0.0.1 - - [12/Feb/2026:10:00:01 +0000] '
            '"GET /api/v2/jobs/ HTTP/1.1" 200 1234 "-" '
            '"python-requests/2.28.0" "-"'
        )
        m = _LOG_RE.match(line)
        self.assertIsNone(m)  # should NOT match new format
        lm = _LEGACY_LOG_RE.match(line)
        self.assertIsNotNone(lm)

    def test_partial_markers(self):
        """One marker present, one absent — not direct access."""
        line = (
            '10.0.0.5 - - [12/Feb/2026:10:00:10 +0000] '
            '"GET /api/v2/workflow_job_templates/ HTTP/1.1" 200 789 "-" '
            '"python-requests/2.28.0" "-" - dab-jwt'
        )
        m = _LOG_RE.match(line)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(10), "-")
        self.assertEqual(m.group(11), "dab-jwt")


class TestParseLogLines(unittest.TestCase):
    """Test parse_log_lines generator."""

    def test_new_format_classification(self):
        lines = [
            '10.0.0.1 - - [12/Feb/2026:10:00:01 +0000] "GET /api/v2/jobs/ HTTP/1.1" 200 1234 "-" "python-requests/2.28.0" "-" trusted-proxy dab-jwt\n',
            '10.0.0.2 - - [12/Feb/2026:10:00:03 +0000] "GET /api/v2/jobs/ HTTP/1.1" 200 1234 "-" "curl/7.68.0" "-" - -\n',
        ]
        results = list(parse_log_lines(lines))
        self.assertEqual(len(results), 2)

        entry1, is_direct1, fmt_ok1 = results[0]
        self.assertFalse(is_direct1)
        self.assertTrue(fmt_ok1)

        entry2, is_direct2, fmt_ok2 = results[1]
        self.assertTrue(is_direct2)
        self.assertTrue(fmt_ok2)

    def test_legacy_format_detected(self):
        lines = [
            '10.0.0.1 - - [12/Feb/2026:10:00:01 +0000] "GET /api/v2/jobs/ HTTP/1.1" 200 1234 "-" "python-requests/2.28.0" "-"\n',
        ]
        results = list(parse_log_lines(lines))
        self.assertEqual(len(results), 1)
        _entry, is_direct, fmt_ok = results[0]
        self.assertFalse(is_direct)
        self.assertFalse(fmt_ok)

    def test_empty_lines_skipped(self):
        lines = ["", "\n", "   \n"]
        results = list(parse_log_lines(lines))
        self.assertEqual(len(results), 0)

    def test_garbage_lines_skipped(self):
        lines = ["this is not a log line\n", "random garbage\n"]
        results = list(parse_log_lines(lines))
        self.assertEqual(len(results), 0)


class TestFiltering(unittest.TestCase):
    """Test the health-check / probe filter."""

    def _make_entry(self, request, user_agent="curl/7.68.0"):
        return LogEntry(
            remote_addr="10.0.0.1",
            remote_user="-",
            time_local="12/Feb/2026:10:00:01 +0000",
            request=request,
            status="200",
            body_bytes_sent="100",
            http_referer="-",
            http_user_agent=user_agent,
            http_x_forwarded_for="-",
            trusted_proxy="-",
            dab_jwt="-",
            raw_line="",
        )

    def test_health_check_filtered(self):
        entry = self._make_entry("GET /api/v2/ping/ HTTP/1.1")
        self.assertTrue(_is_filtered(entry))

    def test_config_endpoint_filtered(self):
        entry = self._make_entry("GET /api/v2/config/ HTTP/1.1")
        self.assertTrue(_is_filtered(entry))

    def test_kube_probe_filtered(self):
        entry = self._make_entry("GET /api/v2/jobs/ HTTP/1.1", "kube-probe/1.27")
        self.assertTrue(_is_filtered(entry))

    def test_static_filtered(self):
        entry = self._make_entry("GET /static/media/logo.svg HTTP/1.1")
        self.assertTrue(_is_filtered(entry))

    def test_normal_api_not_filtered(self):
        entry = self._make_entry("GET /api/v2/jobs/ HTTP/1.1")
        self.assertFalse(_is_filtered(entry))

    def test_api_with_query_string(self):
        entry = self._make_entry("GET /api/v2/jobs/?page=2 HTTP/1.1")
        self.assertFalse(_is_filtered(entry))

    def test_healthz_filtered(self):
        entry = self._make_entry("GET /healthz HTTP/1.1")
        self.assertTrue(_is_filtered(entry))

    def test_readyz_filtered(self):
        entry = self._make_entry("GET /readyz HTTP/1.1")
        self.assertTrue(_is_filtered(entry))


class TestComponentDetection(unittest.TestCase):
    """Test component name inference from pod names."""

    def test_controller(self):
        self.assertEqual(_component_from_pod_name("my-aap-controller-web-abc123"), "controller")
        self.assertEqual(_component_from_pod_name("awx-web-5f8d9c"), "controller")
        self.assertEqual(_component_from_pod_name("tower-nginx-abc"), "controller")

    def test_hub(self):
        self.assertEqual(_component_from_pod_name("my-aap-hub-api-abc123"), "hub")
        self.assertEqual(_component_from_pod_name("galaxy-web-abc"), "hub")
        self.assertEqual(_component_from_pod_name("pulp-api-abc"), "hub")

    def test_eda(self):
        self.assertEqual(_component_from_pod_name("my-aap-eda-api-abc123"), "eda")

    def test_unknown(self):
        self.assertEqual(_component_from_pod_name("redis-abc123"), "unknown")


class TestAnalyze(unittest.TestCase):
    """Test the analyze() function with fixture files."""

    def test_new_format_file(self):
        log_path = os.path.join(FIXTURES, "sample_new_format.log")
        reports, errors = analyze(log_path)
        self.assertEqual(len(errors), 0)
        self.assertEqual(len(reports), 1)
        report = reports[0]
        self.assertEqual(report.total_requests, 11)
        # Direct access: lines 3, 4, 8 (lines 5,6 are filtered probes, 9 is static)
        self.assertEqual(report.direct_access_count, 3)
        # Filtered: lines 5 (ping + kube-probe), 6 (config + kube-probe), 9 (static)
        self.assertEqual(report.filtered_count, 3)

    def test_legacy_format_file(self):
        log_path = os.path.join(FIXTURES, "sample_legacy_format.log")
        reports, errors = analyze(log_path)
        self.assertEqual(len(errors), 0)
        self.assertEqual(len(reports), 1)
        report = reports[0]
        self.assertEqual(report.total_requests, 3)
        self.assertEqual(report.legacy_format_count, 3)
        self.assertEqual(report.direct_access_count, 0)

    def test_all_gateway_file(self):
        log_path = os.path.join(FIXTURES, "sample_all_gateway.log")
        reports, errors = analyze(log_path)
        self.assertEqual(len(errors), 0)
        report = reports[0]
        self.assertEqual(report.direct_access_count, 0)
        self.assertEqual(report.total_requests, 3)

    def test_empty_file(self):
        log_path = os.path.join(FIXTURES, "sample_empty.log")
        reports, errors = analyze(log_path)
        self.assertEqual(len(errors), 0)
        report = reports[0]
        self.assertEqual(report.total_requests, 0)

    def test_include_filtered(self):
        log_path = os.path.join(FIXTURES, "sample_new_format.log")
        reports, errors = analyze(log_path, include_filtered=True)
        report = reports[0]
        # With filtering disabled, probes and static are counted as direct
        # Lines 3,4,5,6,8,9 all have - - markers
        self.assertEqual(report.direct_access_count, 6)
        self.assertEqual(report.filtered_count, 0)

    def test_nonexistent_path(self):
        reports, errors = analyze("/nonexistent/path/to/logs")
        self.assertTrue(len(errors) > 0)


class TestInputDetection(unittest.TestCase):
    """Test auto-detection of input type."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_single_file(self):
        fpath = os.path.join(self.tmpdir, "access.log")
        with open(fpath, "w") as f:
            f.write("test\n")
        input_type, logs = _detect_input_type(fpath)
        self.assertEqual(input_type, InputType.LOG_FILE)

    def test_sosreport(self):
        sos_dir = os.path.join(self.tmpdir, "var", "log", "containers")
        os.makedirs(sos_dir)
        with open(os.path.join(sos_dir, "controller-nginx-abc.log"), "w") as f:
            f.write("test\n")
        input_type, logs = _detect_input_type(self.tmpdir)
        self.assertEqual(input_type, InputType.SOSREPORT)
        self.assertIn("controller", logs)

    def test_must_gather(self):
        ns_dir = os.path.join(self.tmpdir, "namespaces", "aap", "pods",
                              "my-aap-controller-web-abc", "nginx", "nginx", "logs")
        os.makedirs(ns_dir)
        with open(os.path.join(ns_dir, "current.log"), "w") as f:
            f.write("test\n")
        input_type, logs = _detect_input_type(self.tmpdir)
        self.assertEqual(input_type, InputType.MUST_GATHER)
        self.assertIn("controller", logs)

    def test_must_gather_nested(self):
        """must-gather with a random-named subdirectory."""
        ns_dir = os.path.join(self.tmpdir, "quay-io-sha256-abc123",
                              "namespaces", "aap", "pods",
                              "my-eda-api-abc", "nginx", "nginx", "logs")
        os.makedirs(ns_dir)
        with open(os.path.join(ns_dir, "current.log"), "w") as f:
            f.write("test\n")
        input_type, logs = _detect_input_type(self.tmpdir)
        self.assertEqual(input_type, InputType.MUST_GATHER)
        self.assertIn("eda", logs)


class TestGzipSupport(unittest.TestCase):
    """Test that gzipped log files are handled correctly."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_gzipped_log(self):
        line = (
            '10.0.0.2 - - [12/Feb/2026:10:00:03 +0000] '
            '"GET /api/v2/jobs/ HTTP/1.1" 200 1234 "-" '
            '"curl/7.68.0" "-" - -\n'
        )
        gz_path = os.path.join(self.tmpdir, "access.log.gz")
        with gzip.open(gz_path, "wt") as f:
            f.write(line)
        reports, errors = analyze(gz_path)
        self.assertEqual(len(errors), 0)
        report = reports[0]
        self.assertEqual(report.direct_access_count, 1)


class TestOutputFiles(unittest.TestCase):
    """Test report and raw log file generation."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_writes_report_and_raw(self):
        log_path = os.path.join(FIXTURES, "sample_new_format.log")
        reports, errors = analyze(log_path)

        report_path = os.path.join(self.tmpdir, "direct-access-report.txt")
        raw_path = os.path.join(self.tmpdir, "direct-access-raw.log")

        write_detailed_report(reports, report_path)
        write_raw_log(reports, raw_path)

        self.assertTrue(os.path.isfile(report_path))
        self.assertTrue(os.path.isfile(raw_path))

        with io.open(report_path, "r") as f:
            content = f.read()
        self.assertIn("Top paths", content)
        self.assertIn("/api/v2/jobs/", content)

        with io.open(raw_path, "r") as f:
            raw_lines = f.readlines()
        self.assertEqual(len(raw_lines), 3)


class TestCLI(unittest.TestCase):
    """Test CLI argument parsing and exit codes."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_version(self):
        with self.assertRaises(SystemExit) as cm:
            main(["--version"])
        self.assertEqual(cm.exception.code, 0)

    def test_nonexistent_input(self):
        ret = main(["/nonexistent/path", "-o", self.tmpdir])
        self.assertEqual(ret, 1)

    def test_direct_access_exit_code(self):
        log_path = os.path.join(FIXTURES, "sample_new_format.log")
        ret = main([log_path, "-o", self.tmpdir])
        self.assertEqual(ret, 2)  # direct access detected

    def test_clean_exit_code(self):
        log_path = os.path.join(FIXTURES, "sample_all_gateway.log")
        ret = main([log_path, "-o", self.tmpdir])
        self.assertEqual(ret, 0)

    def test_legacy_exit_code(self):
        log_path = os.path.join(FIXTURES, "sample_legacy_format.log")
        ret = main([log_path, "-o", self.tmpdir])
        self.assertEqual(ret, 3)  # legacy format


class TestSummaryOutput(unittest.TestCase):
    """Test print_summary output."""

    def test_summary_direct_access(self):
        log_path = os.path.join(FIXTURES, "sample_new_format.log")
        reports, errors = analyze(log_path)
        buf = io.StringIO()
        print_summary(reports, errors, InputType.LOG_FILE, file=buf)
        output = buf.getvalue()
        self.assertIn("Direct access:", output)
        self.assertIn("DETECTED", output)

    def test_summary_no_direct(self):
        log_path = os.path.join(FIXTURES, "sample_all_gateway.log")
        reports, errors = analyze(log_path)
        buf = io.StringIO()
        print_summary(reports, errors, InputType.LOG_FILE, file=buf)
        output = buf.getvalue()
        self.assertIn("No direct component access detected", output)

    def test_summary_legacy(self):
        log_path = os.path.join(FIXTURES, "sample_legacy_format.log")
        reports, errors = analyze(log_path)
        buf = io.StringIO()
        print_summary(reports, errors, InputType.LOG_FILE, file=buf)
        output = buf.getvalue()
        self.assertIn("Cannot determine", output)


if __name__ == "__main__":
    unittest.main()
