"""
Tests for modules/webvuln_nikto.py: service selection, command shape,
XML parsing against a fixture, and the run() glue path (with run_tool
mocked to write fixture content to the temp output file, since nikto
itself is never invoked in unit tests).
"""

import os
import subprocess
import unittest
from unittest import mock

from modules import webvuln_nikto

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _read_fixture(name):
    with open(os.path.join(FIXTURES, name)) as fh:
        return fh.read()


class QualifyingServicesTests(unittest.TestCase):
    def test_selects_http_named_service(self):
        services = webvuln_nikto._qualifying_services([
            {"port": 8080, "service": "http-proxy"},
            {"port": 22, "service": "ssh"},
        ])
        self.assertEqual([s["port"] for s in services], [8080])

    def test_selects_well_known_port_even_without_http_in_name(self):
        services = webvuln_nikto._qualifying_services([{"port": 443, "service": "ssl"}])
        self.assertEqual(len(services), 1)
        self.assertTrue(services[0]["is_https"])

    def test_caps_at_max_services(self):
        ports = [{"port": p, "service": "http"} for p in (80, 8080, 8000, 8888, 9090)]
        services = webvuln_nikto._qualifying_services(ports)
        self.assertLessEqual(len(services), webvuln_nikto.config.NIKTO_MAX_SERVICES_PER_TARGET)


class CommandConstructionTests(unittest.TestCase):
    def test_command_includes_ssl_flag_when_https(self):
        argv = webvuln_nikto._build_command("example.com", 443, True, "/tmp/out.xml")
        self.assertIn("-ssl", argv)
        self.assertIn("example.com", argv)

    def test_command_omits_ssl_flag_when_http(self):
        argv = webvuln_nikto._build_command("example.com", 80, False, "/tmp/out.xml")
        self.assertNotIn("-ssl", argv)


class SeverityTests(unittest.TestCase):
    def test_high_signal_keyword(self):
        self.assertEqual(webvuln_nikto._severity_for_description("Default credential found for admin"), "high")

    def test_medium_signal_keyword(self):
        self.assertEqual(webvuln_nikto._severity_for_description("Outdated Apache version detected"), "medium")

    def test_generic_description(self):
        self.assertEqual(webvuln_nikto._severity_for_description("Some header is missing"), "low")


class ParsingTests(unittest.TestCase):
    def test_parses_items_from_fixture(self):
        findings = webvuln_nikto._parse_output(_read_fixture("nikto_output.xml"))
        self.assertEqual(len(findings), 2)
        self.assertTrue(any(f["severity"] == "high" for f in findings))


class RunGlueTests(unittest.TestCase):
    def test_skipped_when_no_qualifying_services(self):
        result = webvuln_nikto.run("93.184.216.34", {"error": None, "open_ports": [{"port": 22, "service": "ssh"}]})
        self.assertIn("skipped", result)

    def test_missing_nikto_is_error(self):
        pd = {"error": None, "open_ports": [{"port": 80, "service": "http"}]}
        with mock.patch("modules.webvuln_nikto.binary_available", return_value=False):
            result = webvuln_nikto.run("93.184.216.34", pd)
        self.assertEqual(result["error"], "nikto not installed")

    def test_successful_scan_returns_parsed_findings(self):
        pd = {"error": None, "open_ports": [{"port": 80, "service": "http"}]}
        fixture_content = _read_fixture("nikto_output.xml")

        def fake_run_tool(argv, timeout):
            output_path = argv[argv.index("-output") + 1]
            with open(output_path, "w") as fh:
                fh.write(fixture_content)
            return subprocess.CompletedProcess(args=argv, returncode=1, stdout="", stderr="")

        with mock.patch("modules.webvuln_nikto.binary_available", return_value=True), \
             mock.patch("modules.webvuln_nikto.run_tool", side_effect=fake_run_tool):
            result = webvuln_nikto.run("93.184.216.34", pd)

        self.assertIsNone(result["error"])
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(len(result["results"][0]["findings"]), 2)

    def test_per_service_timeout_is_isolated(self):
        pd = {"error": None, "open_ports": [{"port": 80, "service": "http"}]}
        with mock.patch("modules.webvuln_nikto.binary_available", return_value=True), \
             mock.patch("modules.webvuln_nikto.run_tool", side_effect=subprocess.TimeoutExpired(cmd="nikto", timeout=1)):
            result = webvuln_nikto.run("93.184.216.34", pd)
        self.assertEqual(len(result["results"]), 1)
        self.assertIn("timed out", result["results"][0]["error"])


if __name__ == "__main__":
    unittest.main()
