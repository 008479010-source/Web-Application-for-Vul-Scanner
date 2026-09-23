"""
Tests for modules/nse_vuln.py: command construction, XML parsing against a
fixture, and the skip/error glue paths.
"""

import os
import subprocess
import unittest
from unittest import mock

from modules import nse_vuln

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _read_fixture(name):
    with open(os.path.join(FIXTURES, name)) as fh:
        return fh.read()


PORTDISCOVERY_RESULT = {
    "error": None,
    "open_ports": [
        {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache", "version": "2.4.49"},
        {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "7.9"},
    ],
}


class CommandConstructionTests(unittest.TestCase):
    def test_command_shape(self):
        argv = nse_vuln._build_command("93.184.216.34", [80, 22])
        self.assertEqual(argv[0], nse_vuln.config.NMAP_PATH)
        self.assertIn("--script", argv)
        self.assertIn("vuln", argv)
        self.assertEqual(argv[-1], "93.184.216.34")


class ParsingTests(unittest.TestCase):
    def test_vulnerable_finding_extracted_with_cve(self):
        findings = nse_vuln._parse_output(_read_fixture("nmap_vuln_scan.xml"))
        vulnerable = [f for f in findings if f["verdict"] == "vulnerable"]
        self.assertEqual(len(vulnerable), 1)
        self.assertEqual(vulnerable[0]["port"], 80)
        self.assertIn("CVE-2021-41773", vulnerable[0]["cve_ids"])
        self.assertEqual(vulnerable[0]["severity"], "high")

    def test_not_vulnerable_hostscript_produces_no_finding(self):
        findings = nse_vuln._parse_output(_read_fixture("nmap_vuln_scan.xml"))
        script_ids = [f["script_id"] for f in findings]
        self.assertNotIn("smb-vuln-ms17-010", script_ids)

    def test_inconclusive_output_is_info(self):
        findings = nse_vuln._parse_output(_read_fixture("nmap_vuln_scan.xml"))
        info_findings = [f for f in findings if f["script_id"] == "ssh2-enum-algos"]
        self.assertEqual(len(info_findings), 1)
        self.assertEqual(info_findings[0]["severity"], "info")

    def test_critical_hint_bumps_severity(self):
        xml = _read_fixture("nmap_vuln_scan.xml").replace(
            "http-vuln-cve2021-41773", "http-vuln-backdoor-cve2021-41773"
        )
        findings = nse_vuln._parse_output(xml)
        vulnerable = [f for f in findings if f["verdict"] == "vulnerable"]
        self.assertEqual(vulnerable[0]["severity"], "critical")


class RunGlueTests(unittest.TestCase):
    def test_skips_when_no_open_ports(self):
        result = nse_vuln.run("93.184.216.34", {"error": None, "open_ports": []})
        self.assertIn("skipped", result)

    def test_skips_when_portdiscovery_errored(self):
        result = nse_vuln.run("93.184.216.34", {"error": "nmap not found", "open_ports": []})
        self.assertIn("skipped", result)

    def test_missing_nmap_is_error_not_exception(self):
        with mock.patch("modules.nse_vuln.binary_available", return_value=False):
            result = nse_vuln.run("93.184.216.34", PORTDISCOVERY_RESULT)
        self.assertIsNotNone(result["error"])
        self.assertEqual(result["findings"], [])

    def test_successful_run_returns_parsed_findings(self):
        proc = subprocess.CompletedProcess(args=[], returncode=0, stdout=_read_fixture("nmap_vuln_scan.xml"), stderr="")
        with mock.patch("modules.nse_vuln.binary_available", return_value=True), \
             mock.patch("modules.nse_vuln.run_tool", return_value=proc):
            result = nse_vuln.run("93.184.216.34", PORTDISCOVERY_RESULT)
        self.assertIsNone(result["error"])
        self.assertTrue(any(f["verdict"] == "vulnerable" for f in result["findings"]))

    def test_timeout_discards_partial_results(self):
        with mock.patch("modules.nse_vuln.binary_available", return_value=True), \
             mock.patch("modules.nse_vuln.run_tool", side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=1)):
            result = nse_vuln.run("93.184.216.34", PORTDISCOVERY_RESULT)
        self.assertIn("timed out", result["error"])
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()
