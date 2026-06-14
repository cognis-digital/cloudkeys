"""Hardening tests for CLOUDKEYS — edge cases, bad input, error paths.

All tests are purely in-process; no network, no real credentials.
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cloudkeys.core import (  # noqa: E402
    scan_text,
    scan_path,
    scan,
    to_json,
    ScanResult,
    TOOL_NAME,
    TOOL_VERSION,
)
from cloudkeys import cli  # noqa: E402


# ---------------------------------------------------------------------------
# core.scan_text — None / empty / wrong type
# ---------------------------------------------------------------------------


class TestScanTextEdgeCases(unittest.TestCase):
    def test_none_input_returns_empty(self):
        """scan_text(None) must return [] without raising."""
        result = scan_text(None)
        self.assertEqual(result, [])

    def test_empty_string_returns_empty(self):
        result = scan_text("")
        self.assertEqual(result, [])

    def test_whitespace_only_returns_empty(self):
        result = scan_text("   \n\t  ")
        self.assertEqual(result, [])

    def test_wrong_type_raises_type_error(self):
        with self.assertRaises(TypeError):
            scan_text(12345)

    def test_very_long_clean_line_no_crash(self):
        """A single 1 MB line of safe text must not crash."""
        big = "x" * (1024 * 1024)
        result = scan_text(big)
        self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# core.scan_path — missing path, unreadable file
# ---------------------------------------------------------------------------


class TestScanPathEdgeCases(unittest.TestCase):
    def test_missing_path_records_error(self):
        res = scan_path("/no/such/path/cloudkeys_test_xyz")
        self.assertGreater(len(res.errors), 0)
        self.assertEqual(res.files_scanned, 0)
        self.assertEqual(res.count, 0)

    def test_empty_file_scanned_no_findings(self):
        with tempfile.TemporaryDirectory() as d:
            fp = os.path.join(d, "empty.txt")
            open(fp, "w").close()
            res = scan_path(fp)
            self.assertEqual(res.files_scanned, 1)
            self.assertEqual(res.count, 0)

    def test_empty_directory_no_crash(self):
        with tempfile.TemporaryDirectory() as d:
            res = scan_path(d)
            self.assertEqual(res.files_scanned, 0)
            self.assertEqual(res.count, 0)
            self.assertEqual(len(res.errors), 0)


# ---------------------------------------------------------------------------
# core.scan / core.to_json — public convenience API
# ---------------------------------------------------------------------------


class TestScanPublicAPI(unittest.TestCase):
    def test_core_tool_name_and_version_exported(self):
        """TOOL_NAME / TOOL_VERSION must be importable from core."""
        self.assertEqual(TOOL_NAME, "cloudkeys")
        self.assertTrue(TOOL_VERSION)

    def test_scan_empty_string_returns_scan_result(self):
        res = scan("")
        self.assertIsInstance(res, ScanResult)
        self.assertEqual(res.count, 0)

    def test_scan_inline_text_detects_key(self):
        res = scan("key=AKIAIOSFODNN7EXAMPLE")
        self.assertGreaterEqual(res.count, 1)

    def test_scan_missing_path_treated_as_text(self):
        # When the target string doesn't exist as a path, scan() treats it as
        # inline text — it must not raise.
        res = scan("/no/such/path_ck_test_xyz")
        self.assertIsInstance(res, ScanResult)

    def test_scan_existing_file(self):
        with tempfile.TemporaryDirectory() as d:
            fp = os.path.join(d, "sample.env")
            with open(fp, "w") as fh:
                fh.write("NOTHING=interesting\n")
            res = scan(fp)
            self.assertIsInstance(res, ScanResult)
            self.assertEqual(res.files_scanned, 1)

    def test_to_json_returns_valid_json(self):
        res = ScanResult()
        out = to_json(res)
        data = json.loads(out)
        self.assertIn("finding_count", data)
        self.assertEqual(data["finding_count"], 0)

    def test_to_json_wrong_type_raises(self):
        with self.assertRaises(TypeError):
            to_json("not a ScanResult")

    def test_scan_wrong_type_raises(self):
        with self.assertRaises(TypeError):
            scan(42)


# ---------------------------------------------------------------------------
# CLI — error paths and edge cases
# ---------------------------------------------------------------------------


class TestCLIHardening(unittest.TestCase):
    def _run(self, argv, stdin_text=None):
        """Run cli.main() capturing stdout and stderr."""
        out = io.StringIO()
        err = io.StringIO()
        old_out, old_err, old_in = sys.stdout, sys.stderr, sys.stdin
        sys.stdout = out
        sys.stderr = err
        if stdin_text is not None:
            sys.stdin = io.StringIO(stdin_text)
        try:
            code = cli.main(argv)
        finally:
            sys.stdout, sys.stderr, sys.stdin = old_out, old_err, old_in
        return code, out.getvalue(), err.getvalue()

    def test_missing_file_returns_exit_2(self):
        """Scanning a non-existent file should exit 2 (all errors, no files)."""
        code, out, err = self._run(["scan", "/no/such/file_ck_xyz"])
        # errors present, 0 files scanned -> exit 2
        self.assertEqual(code, 2)

    def test_scan_empty_stdin_exits_zero(self):
        code, out, _ = self._run(["scan", "-"], stdin_text="")
        self.assertEqual(code, 0)

    def test_json_output_on_empty_stdin(self):
        code, out, _ = self._run(["--format", "json", "scan", "-"], stdin_text="")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["finding_count"], 0)
        self.assertIn("findings", data)

    def test_unexpected_exception_returns_exit_2(self, *_):
        """Simulate an unexpected error inside _main; main() must catch it."""
        import unittest.mock as mock

        with mock.patch("cloudkeys.cli._main", side_effect=RuntimeError("boom")):
            err = io.StringIO()
            old_err = sys.stderr
            sys.stderr = err
            try:
                code = cli.main(["scan", "-"])
            finally:
                sys.stderr = old_err
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
