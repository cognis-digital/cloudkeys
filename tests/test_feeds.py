"""Tests for the cloud IP-range feeds layer + scan attribution.

OFFLINE ONLY. These point COGNIS_FEEDS_CACHE at a committed, trimmed fixture
cache (tests/fixtures/cognis-feeds) and use offline=True, so the suite never
touches the network and CI stays green air-gapped.

Fixture-derived attributable IPs (real CIDRs from the published ranges):
  3.4.12.4    -> AWS  AMAZON       eu-west-1     (3.4.12.4/32)
  34.1.208.1  -> GCP  Google Cloud africa-south1 (34.1.208.0/20)
"""
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

FIXTURE_CACHE = os.path.join(os.path.dirname(__file__), "fixtures", "cognis-feeds")


def _use_fixture_cache():
    os.environ["COGNIS_FEEDS_CACHE"] = FIXTURE_CACHE


class TestFeedsLayer(unittest.TestCase):
    def setUp(self):
        _use_fixture_cache()
        from cloudkeys import feeds
        # Index is memoized per offline flag; clear so each test sees the cache.
        feeds._build_index.cache_clear()
        self.feeds = feeds

    def test_catalog_restricted_to_cloud_feeds(self):
        ids = {f["id"] for f in self.feeds.relevant_catalog()["feeds"]}
        self.assertEqual(ids, {"aws-ip-ranges", "gcp-ip-ranges"})

    def test_list_feeds_shape(self):
        rows = self.feeds.list_feeds()
        self.assertEqual({r["id"] for r in rows}, {"aws-ip-ranges", "gcp-ip-ranges"})
        for r in rows:
            self.assertTrue(r["url"].startswith("https://"))

    def test_fixtures_are_cached_offline(self):
        # offline get must succeed purely from the committed fixture cache
        from cloudkeys import datafeeds
        aws = datafeeds.get("aws-ip-ranges", offline=True,
                            catalog=self.feeds.relevant_catalog())
        self.assertIn("prefixes", aws)
        self.assertGreater(len(aws["prefixes"]), 0)

    def test_attribute_aws_offline(self):
        a = self.feeds.attribute_ip("3.4.12.4", offline=True)
        self.assertIsNotNone(a)
        self.assertEqual(a["cloud"], "aws")
        self.assertEqual(a["region"], "eu-west-1")
        self.assertTrue(a["cidr"])

    def test_attribute_gcp_offline(self):
        a = self.feeds.attribute_ip("34.1.208.1", offline=True)
        self.assertIsNotNone(a)
        self.assertEqual(a["cloud"], "gcp")
        self.assertEqual(a["region"], "africa-south1")

    def test_attribute_unknown_ip(self):
        # RFC1918 / loopback is in neither cloud's published ranges
        self.assertIsNone(self.feeds.attribute_ip("10.0.0.1", offline=True))
        self.assertIsNone(self.feeds.attribute_ip("127.0.0.1", offline=True))

    def test_attribute_garbage_returns_none(self):
        self.assertIsNone(self.feeds.attribute_ip("not-an-ip", offline=True))

    def test_attribute_many(self):
        res = self.feeds.attribute_ips(["3.4.12.4", "10.0.0.1"], offline=True)
        self.assertEqual(res["3.4.12.4"]["cloud"], "aws")
        self.assertIsNone(res["10.0.0.1"])

    def test_offline_with_no_cache_raises(self):
        from cloudkeys import datafeeds
        os.environ["COGNIS_FEEDS_CACHE"] = os.path.join(
            os.path.dirname(__file__), "fixtures", "_empty_cache_xyz")
        self.feeds._build_index.cache_clear()
        with self.assertRaises(FileNotFoundError):
            datafeeds.get("aws-ip-ranges", offline=True,
                          catalog=self.feeds.relevant_catalog())


class TestExtractIPs(unittest.TestCase):
    def test_extract_ipv4(self):
        from cloudkeys.core import extract_ips
        ips = extract_ips("endpoint=3.4.12.4 and db at 34.1.208.1 plus junk 999.1.1.1")
        self.assertIn("3.4.12.4", ips)
        self.assertIn("34.1.208.1", ips)

    def test_extract_dedups(self):
        from cloudkeys.core import extract_ips
        ips = extract_ips("3.4.12.4 3.4.12.4 3.4.12.4")
        self.assertEqual(ips, ["3.4.12.4"])


class TestScanAttribution(unittest.TestCase):
    def setUp(self):
        _use_fixture_cache()
        from cloudkeys import feeds
        feeds._build_index.cache_clear()

    def _run(self, argv, stdin_text=None):
        from cloudkeys import cli
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

    def test_scan_attribute_json_offline(self):
        leak = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nendpoint=3.4.12.4\ndb=34.1.208.1\n"
        code, out = self._run(
            ["--format", "json", "scan", "--attribute", "--offline", "-"],
            stdin_text=leak)
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertGreaterEqual(data["finding_count"], 1)
        attr = data["ip_attributions"]
        self.assertEqual(attr["3.4.12.4"]["cloud"], "aws")
        self.assertEqual(attr["34.1.208.1"]["cloud"], "gcp")

    def test_scan_attribute_table_offline(self):
        leak = "key=AKIAIOSFODNN7EXAMPLE host 3.4.12.4"
        code, out = self._run(
            ["scan", "--attribute", "--offline", "-"], stdin_text=leak)
        self.assertEqual(code, 1)
        self.assertIn("Cloud IP attribution", out)
        self.assertIn("AWS", out)


class TestFeedsCLI(unittest.TestCase):
    def setUp(self):
        _use_fixture_cache()
        from cloudkeys import feeds
        feeds._build_index.cache_clear()

    def _run(self, argv):
        from cloudkeys import cli
        out = io.StringIO()
        old = sys.stdout
        sys.stdout = out
        try:
            code = cli.main(argv)
        finally:
            sys.stdout = old
        return code, out.getvalue()

    def test_feeds_list(self):
        code, out = self._run(["feeds", "list"])
        self.assertEqual(code, 0)
        self.assertIn("aws-ip-ranges", out)
        self.assertIn("gcp-ip-ranges", out)

    def test_feeds_attribute_offline(self):
        code, out = self._run(["feeds", "attribute", "3.4.12.4", "--offline"])
        self.assertEqual(code, 0)
        self.assertIn("AWS", out)
        self.assertIn("eu-west-1", out)

    def test_feeds_get_offline(self):
        code, out = self._run(["--format", "json", "feeds", "get", "gcp-ip-ranges", "--offline"])
        self.assertEqual(code, 0)
        self.assertIn("prefixes", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
