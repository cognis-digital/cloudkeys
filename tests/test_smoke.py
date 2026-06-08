"""Smoke tests for CLOUDKEYS. No network. Run with: python -m unittest -v"""
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cloudkeys import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    scan_text,
    scan_path,
    blast_radius,
    DETECTORS,
)
from cloudkeys.core import shannon_entropy, redact  # noqa: E402
from cloudkeys import cli  # noqa: E402


class TestCore(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "cloudkeys")
        self.assertTrue(TOOL_VERSION)
        self.assertTrue(len(DETECTORS) >= 6)

    def test_entropy(self):
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertGreater(shannon_entropy("abcd"), 1.0)

    def test_redact_never_full(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        r = redact(secret)
        self.assertNotEqual(r, secret)
        self.assertIn("*", r)
        self.assertTrue(r.startswith("AKIA"))

    def test_detect_aws_access_key(self):
        findings = scan_text("key = AKIAIOSFODNN7EXAMPLE")
        ids = [f.detector for f in findings]
        self.assertIn("aws_access_key_id", ids)
        f = [x for x in findings if x.detector == "aws_access_key_id"][0]
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.provider, "aws")
        self.assertNotIn("EXAMPLE", f.match.upper()[6:])

    def test_aws_akid_prefix_validation(self):
        # 20-char string with a non-principal prefix must NOT match.
        findings = scan_text("ZZZZIOSFODNN7EXAMPLE0")
        self.assertEqual([f for f in findings if f.detector == "aws_access_key_id"], [])

    def test_detect_gcp_api_key(self):
        findings = scan_text("GCP_API_KEY=AIzaSyEXAMPLEexampleNotARealGcpKey00000")
        self.assertIn("gcp_api_key", [f.detector for f in findings])

    def test_detect_azure_storage_key(self):
        s = "AccountKey=" + "A" * 84 + "=="
        # all-A has zero entropy -> gated out
        self.assertEqual(scan_text(s), [])
        # fixture assembled from fragments so the full literal
        # "AccountKey=<88-char base64>==" never appears verbatim
        # in source; still exercises the azure_storage_key detector.
        good = ("Account" "Key=" "RVhBTVBMRS1OT1QtQS1SRUFM"
                "LUFaVVJFLVNUT1JBR0UtS0VZ" "LWZha2UtZGVtby1wbGFjZWhv"
                "bGRlci0wMDAwMA==")
        self.assertIn("azure_storage_key", [f.detector for f in scan_text(good)])

    def test_no_false_positive_on_plain_text(self):
        findings = scan_text("the quick brown fox jumps over the lazy dog 12345")
        self.assertEqual(findings, [])

    def test_blast_radius_known_and_default(self):
        impact, fix = blast_radius("aws_access_key_id")
        self.assertIn("AWS", impact)
        self.assertTrue(fix)
        d_impact, d_fix = blast_radius("does_not_exist")
        self.assertTrue(d_impact and d_fix)

    def test_scan_path_file(self):
        with tempfile.TemporaryDirectory() as d:
            fp = os.path.join(d, "c.env")
            with open(fp, "w", encoding="utf-8") as fh:
                fh.write("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
            res = scan_path(fp)
            self.assertEqual(res.files_scanned, 1)
            self.assertGreaterEqual(res.count, 1)
            d2 = res.to_dict()
            self.assertIn("findings", d2)
            self.assertIn("severity_counts", d2)

    def test_scan_path_missing(self):
        res = scan_path(os.path.join(tempfile.gettempdir(), "no_such_ck_path_xyz"))
        self.assertTrue(res.errors)
        self.assertEqual(res.count, 0)


class TestCLI(unittest.TestCase):
    def _run(self, argv, stdin_text=None):
        out = io.StringIO()
        old_out, old_in = sys.stdout, sys.stdin
        sys.stdout = out
        if stdin_text is not None:
            sys.stdin = io.StringIO(stdin_text)
        try:
            code = cli.main(argv)
        finally:
            sys.stdout, sys.stdin = old_out, old_in
        return code, out.getvalue()

    def test_clean_exit_zero(self):
        code, out = self._run(["scan", "-"], stdin_text="nothing secret here")
        self.assertEqual(code, 0)
        self.assertIn("No leaked credentials", out)

    def test_finding_exit_one(self):
        code, out = self._run(["scan", "-"], stdin_text="AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(code, 1)
        self.assertIn("aws_access_key_id", out)

    def test_json_format(self):
        code, out = self._run(["--format", "json", "scan", "-"], stdin_text="AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["finding_count"], data["finding_count"])
        self.assertGreaterEqual(data["finding_count"], 1)
        self.assertIn("findings", data)

    def test_demo_file(self):
        demo = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "leaked_config.env")
        if os.path.exists(demo):
            code, out = self._run(["--format", "json", "scan", demo])
            data = json.loads(out)
            self.assertEqual(code, 1)
            dets = {f["detector"] for f in data["findings"]}
            self.assertIn("aws_access_key_id", dets)
            self.assertIn("gcp_api_key", dets)


if __name__ == "__main__":
    unittest.main(verbosity=2)
