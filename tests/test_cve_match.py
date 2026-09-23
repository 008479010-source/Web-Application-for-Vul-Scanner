"""
Tests for modules/cve_match.py: CVSS scoring/version fallback, NVD response
parsing against fixtures, cache hit/miss via a temp DB, and the process-wide
throttle. requests.get is always mocked — no real network calls.
"""

import json
import os
import unittest
from unittest import mock

from tests._test_helpers import temp_db

from modules import cve_match

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _load_fixture(name):
    with open(os.path.join(FIXTURES, name)) as fh:
        return json.load(fh)


class ScoreToSeverityTests(unittest.TestCase):
    def test_critical_band(self):
        self.assertEqual(cve_match.score_to_severity(9.8), "critical")

    def test_high_band(self):
        self.assertEqual(cve_match.score_to_severity(7.5), "high")

    def test_medium_band(self):
        self.assertEqual(cve_match.score_to_severity(5.0), "medium")

    def test_low_band(self):
        self.assertEqual(cve_match.score_to_severity(1.0), "low")

    def test_none_score_is_info(self):
        self.assertEqual(cve_match.score_to_severity(None), "info")


class ParseNvdResponseTests(unittest.TestCase):
    def test_prefers_cvss_v31_score(self):
        payload = _load_fixture("nvd_response_cvss_v3.json")
        results = cve_match._parse_nvd_response(payload)
        self.assertEqual(results[0]["id"], "CVE-2021-41773")
        self.assertEqual(results[0]["score"], 9.8)
        self.assertEqual(results[0]["severity"], "critical")

    def test_falls_back_to_cvss_v2(self):
        payload = _load_fixture("nvd_response_cvss_v2_only.json")
        results = cve_match._parse_nvd_response(payload)
        self.assertEqual(results[0]["score"], 5.0)
        self.assertEqual(results[0]["severity"], "medium")

    def test_empty_response_is_empty_list(self):
        payload = _load_fixture("nvd_response_empty.json")
        self.assertEqual(cve_match._parse_nvd_response(payload), [])


class UniqueProductVersionsTests(unittest.TestCase):
    def test_skips_missing_version(self):
        pairs = cve_match._unique_product_versions([
            {"product": "nginx", "version": ""},
            {"product": "nginx", "version": "1.18.0"},
        ])
        self.assertEqual(pairs, [("nginx", "1.18.0")])

    def test_deduplicates(self):
        pairs = cve_match._unique_product_versions([
            {"product": "nginx", "version": "1.18.0"},
            {"product": "nginx", "version": "1.18.0"},
        ])
        self.assertEqual(len(pairs), 1)


class RunGlueTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(temp_db())
        cve_match._last_nvd_call_ts = 0.0

    def test_skipped_when_no_product_version_pairs(self):
        result = cve_match.run("93.184.216.34", {"error": None, "open_ports": []})
        self.assertIn("skipped", result)

    def test_cache_hit_avoids_network_call(self):
        import db
        db.store_cve_cache("nginx::1.18.0", "nginx", "1.18.0", [{"id": "CVE-X", "severity": "low", "score": 1.0, "description": ""}], 3600)
        pd = {"error": None, "open_ports": [{"product": "nginx", "version": "1.18.0"}]}

        with mock.patch("modules.cve_match.requests.get") as mock_get:
            result = cve_match.run("93.184.216.34", pd)

        mock_get.assert_not_called()
        self.assertEqual(result["cve_matches"][0]["source"], "cache")

    def test_live_lookup_on_cache_miss(self):
        pd = {"error": None, "open_ports": [{"product": "nginx", "version": "1.18.0"}]}
        fake_response = mock.Mock()
        fake_response.status_code = 200
        fake_response.json.return_value = _load_fixture("nvd_response_cvss_v3.json")
        fake_response.raise_for_status.return_value = None

        with mock.patch("modules.cve_match.requests.get", return_value=fake_response) as mock_get, \
             mock.patch("modules.cve_match.time.sleep"):
            result = cve_match.run("93.184.216.34", pd)

        mock_get.assert_called_once()
        self.assertEqual(result["cve_matches"][0]["source"], "live")
        self.assertEqual(result["cve_matches"][0]["cves"][0]["id"], "CVE-2021-41773")

    def test_throttle_applies_shared_delay_between_calls(self):
        # First call is far after the (reset-to-0) last call timestamp, so it
        # doesn't need to sleep. The second call happens only 0.2s after the
        # first (per the mocked clock) - well inside the no-API-key 6.5s
        # delay - so it must sleep. This only works if the timestamp set by
        # the first call is visible to the second, proving the throttle state
        # is shared (module-level), not local to one _throttle_nvd() call.
        with mock.patch("modules.cve_match.time.monotonic", side_effect=[100.0, 100.0, 100.2, 100.2]), \
             mock.patch("modules.cve_match.time.sleep") as mock_sleep:
            cve_match._throttle_nvd()
            cve_match._throttle_nvd()

        mock_sleep.assert_called_once()


if __name__ == "__main__":
    unittest.main()
