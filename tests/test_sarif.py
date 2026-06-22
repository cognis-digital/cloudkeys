"""Tests for SARIF 2.1.0 export and the new demo scenarios."""
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cloudkeys import cli, TOOL_NAME, TOOL_VERSION  # noqa: E402
from cloudkeys.core import scan_text  # noqa: E402
from cloudkeys.sarif import to_sarif, dumps, SARIF_VERSION  # noqa: E402

_DEMOS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "demos"))


def _scan(text):
    from cloudkeys.core import ScanResult
    r = ScanResult()
    r.files_scanned = 1
    r.findings = scan_text(text, source="demo/file.env")
    return r


class TestSarif(unittest.TestCase):
    SAMPLE = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"

    def test_envelope_shape(self):
        log = to_sarif(_scan(self.SAMPLE), TOOL_NAME, TOOL_VERSION)
        self.assertEqual(log["version"], SARIF_VERSION)
        self.assertIn("sarif-schema-2.1.0", log["$schema"])
        self.assertEqual(len(log["runs"]), 1)
        driver = log["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], TOOL_NAME)
        self.assertTrue(driver["rules"])

    def test_results_present_and_levels_valid(self):
        log = to_sarif(_scan(self.SAMPLE), TOOL_NAME, TOOL_VERSION)
        results = log["runs"][0]["results"]
        self.assertGreaterEqual(len(results), 1)
        valid = {"error", "warning", "note", "none"}
        for r in results:
            self.assertIn(r["level"], valid)
            self.assertTrue(r["ruleId"])
            loc = r["locations"][0]["physicalLocation"]
            self.assertIn("uri", loc["artifactLocation"])
            self.assertGreaterEqual(loc["region"]["startLine"], 1)

    def test_uri_forward_slashes(self):
        from cloudkeys.core import ScanResult
        r = ScanResult()
        r.files_scanned = 1
        r.findings = scan_text(self.SAMPLE, source="a\\b\\c.env")
        log = to_sarif(r, TOOL_NAME, TOOL_VERSION)
        uri = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertNotIn("\\", uri)
        self.assertIn("a/b/c.env", uri)

    def test_rule_has_security_severity(self):
        log = to_sarif(_scan(self.SAMPLE), TOOL_NAME, TOOL_VERSION)
        rule = log["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertIn("security-severity", rule["properties"])
        float(rule["properties"]["security-severity"])  # must be numeric

    def test_dumps_is_valid_json(self):
        s = dumps(_scan(self.SAMPLE), TOOL_NAME, TOOL_VERSION)
        json.loads(s)

    def test_empty_result_valid(self):
        from cloudkeys.core import ScanResult
        log = to_sarif(ScanResult(), TOOL_NAME, TOOL_VERSION)
        self.assertEqual(log["runs"][0]["results"], [])
        self.assertEqual(log["runs"][0]["tool"]["driver"]["rules"], [])

    def test_cli_sarif_format(self):
        out = io.StringIO()
        old = sys.stdout
        sys.stdout = out
        sys.stdin = io.StringIO("AKIAIOSFODNN7EXAMPLE")
        try:
            code = cli.main(["--format", "sarif", "scan", "-"])
        finally:
            sys.stdout = old
            sys.stdin = sys.__stdin__
        self.assertEqual(code, 1)
        data = json.loads(out.getvalue())
        self.assertEqual(data["version"], SARIF_VERSION)
        self.assertGreaterEqual(len(data["runs"][0]["results"]), 1)


class TestDemos(unittest.TestCase):
    """Every demo with credentials must actually produce findings."""

    def _scan_path(self, rel):
        from cloudkeys.core import scan_path
        return scan_path(os.path.join(_DEMOS, rel))

    def test_demo_04_aws_credentials(self):
        res = self._scan_path("04-aws-credentials-file/credentials")
        dets = {f.detector for f in res.findings}
        self.assertIn("aws_access_key_id", dets)
        self.assertIn("aws_secret_access_key", dets)
        self.assertEqual(res.count, 4)

    def test_demo_05_gcp_api_key(self):
        res = self._scan_path("05-gcp-api-key/firebase-config.js")
        dets = {f.detector for f in res.findings}
        self.assertIn("gcp_api_key", dets)

    def test_demo_06_terraform(self):
        res = self._scan_path("06-terraform-tfvars/terraform.tfvars")
        dets = {f.detector for f in res.findings}
        self.assertIn("azure_client_secret", dets)
        self.assertIn("aws_access_key_id", dets)

    def test_demo_07_ci_pipeline(self):
        res = self._scan_path("07-ci-pipeline-env/deploy.yml")
        dets = {f.detector for f in res.findings}
        self.assertIn("aws_session_token", dets)
        self.assertIn("gcp_api_key", dets)

    def test_demo_08_kubernetes_secret(self):
        res = self._scan_path("08-kubernetes-secret/secret.yaml")
        dets = {f.detector for f in res.findings}
        self.assertIn("private_key_pem", dets)
        self.assertIn("azure_sas_token", dets)

    def test_demo_09_git_diff(self):
        res = self._scan_path("09-git-diff-precommit/staged.diff")
        dets = {f.detector for f in res.findings}
        self.assertIn("aws_secret_access_key", dets)

    def test_demo_10_clean_baseline(self):
        res = self._scan_path("10-dotenv-clean-baseline/.env.example")
        self.assertEqual(res.count, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
