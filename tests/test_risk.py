"""
Tests for the cross-source severity aggregation in modules/risk.py — one
test per rule/source, plus sort-order and count-aggregation invariants.
"""

import unittest

from modules import risk


class PortDiscoveryRiskTests(unittest.TestCase):
    def test_telnet_is_critical(self):
        result = risk.assess("1.2.3.4", {"portdiscovery": {"open_ports": [
            {"port": 23, "protocol": "tcp", "service": "telnet", "banner": "telnetd"}
        ]}})
        self.assertEqual(result["highest_severity"], "critical")

    def test_rdp_is_high(self):
        result = risk.assess("1.2.3.4", {"portdiscovery": {"open_ports": [
            {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server", "banner": ""}
        ]}})
        self.assertEqual(result["highest_severity"], "high")

    def test_unknown_port_is_info(self):
        result = risk.assess("1.2.3.4", {"portdiscovery": {"open_ports": [
            {"port": 54321, "protocol": "tcp", "service": "unknown", "banner": ""}
        ]}})
        self.assertEqual(result["highest_severity"], "info")


class NseVulnRiskTests(unittest.TestCase):
    def test_vulnerable_verdict_is_high_by_default(self):
        result = risk.assess("1.2.3.4", {"nse_vuln": {"findings": [
            {"script_id": "http-vuln-cve2021-41773", "port": 80, "verdict": "vulnerable",
             "severity": "high", "output": "VULNERABLE", "cve_ids": ["CVE-2021-41773"]}
        ]}})
        self.assertEqual(result["highest_severity"], "high")
        self.assertEqual(result["findings"][0]["cve_ids"], ["CVE-2021-41773"])

    def test_critical_script_hint_bumps_to_critical(self):
        result = risk.assess("1.2.3.4", {"nse_vuln": {"findings": [
            {"script_id": "smb-vuln-ms17-010", "port": 445, "verdict": "vulnerable",
             "severity": "critical", "output": "VULNERABLE", "cve_ids": []}
        ]}})
        self.assertEqual(result["highest_severity"], "critical")


class NiktoRiskTests(unittest.TestCase):
    def test_high_signal_keyword_is_high(self):
        result = risk.assess("1.2.3.4", {"webvuln_nikto": {"results": [
            {"service_port": 80, "error": None, "findings": [
                {"description": "Default credential found for admin", "uri": "/admin/", "osvdb_id": "", "severity": "high"}
            ]}
        ]}})
        self.assertEqual(result["highest_severity"], "high")

    def test_generic_item_is_low(self):
        result = risk.assess("1.2.3.4", {"webvuln_nikto": {"results": [
            {"service_port": 80, "error": None, "findings": [
                {"description": "Generic header observation", "uri": "/", "osvdb_id": "", "severity": "low"}
            ]}
        ]}})
        self.assertEqual(result["highest_severity"], "low")


class CveMatchRiskTests(unittest.TestCase):
    def test_critical_cvss_score_is_critical(self):
        result = risk.assess("1.2.3.4", {"cve_match": {"cve_matches": [
            {"product": "Apache", "version": "2.4.49", "source": "live", "error": None, "cves": [
                {"id": "CVE-2021-41773", "severity": "critical", "score": 9.8, "description": "..."}
            ]}
        ]}})
        self.assertEqual(result["highest_severity"], "critical")
        self.assertIn("CVE-2021-41773", result["findings"][0]["cve_ids"])


class AggregationTests(unittest.TestCase):
    def test_findings_sorted_by_severity_rank(self):
        result = risk.assess("1.2.3.4", {"portdiscovery": {"open_ports": [
            {"port": 54321, "protocol": "tcp", "service": "unknown", "banner": ""},
            {"port": 23, "protocol": "tcp", "service": "telnet", "banner": ""},
            {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server", "banner": ""},
        ]}})
        severities = [f["severity"] for f in result["findings"]]
        self.assertEqual(severities, ["critical", "high", "info"])

    def test_counts_reflect_findings(self):
        result = risk.assess("1.2.3.4", {"portdiscovery": {"open_ports": [
            {"port": 23, "protocol": "tcp", "service": "telnet", "banner": ""},
            {"port": 22, "protocol": "tcp", "service": "ssh", "banner": ""},
        ]}})
        self.assertEqual(result["counts"]["critical"], 1)

    def test_no_findings_highest_severity_is_info(self):
        result = risk.assess("1.2.3.4", {"portdiscovery": {"open_ports": []}})
        self.assertEqual(result["highest_severity"], "info")
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()
