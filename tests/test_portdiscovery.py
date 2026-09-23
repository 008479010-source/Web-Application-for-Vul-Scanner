"""
Tests for modules/portdiscovery.py: command construction, output parsing
against fixture files, and the masscan-fails -> nmap-fallback glue path —
all without invoking real binaries.
"""

import os
import subprocess
import unittest
from unittest import mock

from modules import portdiscovery

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _read_fixture(name):
    with open(os.path.join(FIXTURES, name)) as fh:
        return fh.read()


class CommandConstructionTests(unittest.TestCase):
    def test_masscan_command_shape(self):
        argv = portdiscovery._build_masscan_command("93.184.216.34")
        self.assertEqual(argv[0], portdiscovery.config.MASSCAN_PATH)
        self.assertEqual(argv[-1], "93.184.216.34")
        self.assertIn("-oL", argv)

    def test_nmap_command_shape(self):
        argv = portdiscovery._build_nmap_command("93.184.216.34", [22, 80])
        self.assertEqual(argv[0], portdiscovery.config.NMAP_PATH)
        self.assertEqual(argv[-1], "93.184.216.34")
        self.assertIn("-sV", argv)
        self.assertIn("22,80", argv)


class MasscanParsingTests(unittest.TestCase):
    def test_parses_open_ports_ignoring_comments(self):
        text = _read_fixture("masscan_output_list.txt")
        ports = portdiscovery._parse_masscan_output(text)
        self.assertEqual(sorted(ports), [22, 80])

    def test_empty_output_is_empty_list_not_failure(self):
        self.assertEqual(portdiscovery._parse_masscan_output(""), [])


class NmapXmlParsingTests(unittest.TestCase):
    def test_parses_open_ports_with_product_version(self):
        xml_text = _read_fixture("nmap_service_scan.xml")
        parsed = portdiscovery._parse_nmap_xml(xml_text)
        self.assertEqual(parsed["resolved_ip"], "93.184.216.34")
        ports = {p["port"]: p for p in parsed["open_ports"]}
        self.assertEqual(ports[80]["product"], "nginx")
        self.assertEqual(ports[80]["version"], "1.18.0")
        self.assertEqual(ports[22]["product"], "OpenSSH")

    def test_closed_ports_are_excluded(self):
        xml_text = _read_fixture("nmap_service_scan.xml")
        parsed = portdiscovery._parse_nmap_xml(xml_text)
        ports = [p["port"] for p in parsed["open_ports"]]
        self.assertNotIn(21, ports)


class RunGlueTests(unittest.TestCase):
    def test_masscan_success_feeds_nmap(self):
        masscan_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout=_read_fixture("masscan_output_list.txt"), stderr="")
        nmap_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout=_read_fixture("nmap_service_scan.xml"), stderr="")

        with mock.patch("modules.portdiscovery.binary_available", return_value=True), \
             mock.patch("modules.portdiscovery.run_tool", side_effect=[masscan_proc, nmap_proc]) as run_tool:
            result = portdiscovery.run("93.184.216.34")

        self.assertEqual(result["discovery_method"], "masscan+nmap")
        self.assertEqual(result["open_count"], 2)
        self.assertEqual(run_tool.call_count, 2)

    def test_masscan_failure_falls_back_to_nmap_only(self):
        nmap_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout=_read_fixture("nmap_service_scan.xml"), stderr="")

        def fake_binary_available(path):
            return path == portdiscovery.config.NMAP_PATH

        with mock.patch("modules.portdiscovery.binary_available", side_effect=fake_binary_available), \
             mock.patch("modules.portdiscovery.run_tool", return_value=nmap_proc) as run_tool:
            result = portdiscovery.run("93.184.216.34")

        self.assertEqual(result["discovery_method"], "nmap-fallback")
        self.assertEqual(result["open_count"], 2)
        run_tool.assert_called_once()

    def test_masscan_clean_zero_ports_is_not_a_failure(self):
        masscan_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        with mock.patch("modules.portdiscovery.binary_available", return_value=True), \
             mock.patch("modules.portdiscovery.run_tool", return_value=masscan_proc) as run_tool:
            result = portdiscovery.run("93.184.216.34")

        self.assertEqual(result["discovery_method"], "masscan+nmap")
        self.assertEqual(result["open_count"], 0)
        self.assertIsNone(result["error"])
        run_tool.assert_called_once()  # nmap is never invoked over zero ports

    def test_missing_nmap_is_hard_error(self):
        with mock.patch("modules.portdiscovery.binary_available", return_value=False):
            result = portdiscovery.run("93.184.216.34")
        self.assertIsNotNone(result["error"])
        self.assertEqual(result["open_ports"], [])

    def test_nmap_timeout_is_isolated_error(self):
        with mock.patch("modules.portdiscovery.binary_available", return_value=True), \
             mock.patch("modules.portdiscovery.run_tool", side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=1)):
            result = portdiscovery.run("93.184.216.34")
        self.assertIn("timed out", result["error"])


if __name__ == "__main__":
    unittest.main()
