"""
Safety invariants for every external-tool invocation: argv is always a
list (never a shell string), shell is always False, argv[0] is always a
config-defined binary path, and the target string appears as exactly one
argv element - never interpolated into a larger string. These are
correctness requirements, not style preferences, since these modules
execute real external binaries against user-influenced (product/version)
and user-provided (target) strings.
"""

import inspect
import unittest
from unittest import mock

from modules import _proc, nse_vuln, portdiscovery, webvuln_nikto

TARGET = "93.184.216.34; rm -rf /"  # deliberately hostile-looking, but treated as opaque data


class RunToolInvariantTests(unittest.TestCase):
    def test_run_tool_never_uses_shell(self):
        with mock.patch("modules._proc.subprocess.run") as mock_run:
            _proc.run_tool(["nmap", "-sV", TARGET], timeout=5)
        _, kwargs = mock_run.call_args
        self.assertFalse(kwargs.get("shell", False))

    def test_run_tool_passes_argv_as_list(self):
        with mock.patch("modules._proc.subprocess.run") as mock_run:
            _proc.run_tool(["nmap", "-sV", TARGET], timeout=5)
        args, _ = mock_run.call_args
        self.assertIsInstance(args[0], list)


class CommandBuilderInvariantTests(unittest.TestCase):
    def _assert_safe(self, argv, expected_binary):
        self.assertIsInstance(argv, list)
        self.assertEqual(argv[0], expected_binary)
        self.assertEqual(argv.count(TARGET), 1, "target must appear as exactly one argv element")
        for element in argv:
            self.assertIsInstance(element, str)

    def test_portdiscovery_masscan_command(self):
        self._assert_safe(portdiscovery._build_masscan_command(TARGET), portdiscovery.config.MASSCAN_PATH)

    def test_portdiscovery_nmap_command(self):
        self._assert_safe(portdiscovery._build_nmap_command(TARGET, [80]), portdiscovery.config.NMAP_PATH)

    def test_nse_vuln_command(self):
        self._assert_safe(nse_vuln._build_command(TARGET, [80]), nse_vuln.config.NMAP_PATH)

    def test_webvuln_nikto_command(self):
        self._assert_safe(
            webvuln_nikto._build_command(TARGET, 80, False, "/tmp/out.xml"),
            webvuln_nikto.config.NIKTO_PATH,
        )


class NoRawFlagsFromCallerTests(unittest.TestCase):
    """None of the run()/command-builder signatures accept a free-form
    flags/args parameter from the caller - the only inputs are the
    pre-validated target and internally-computed port lists."""

    def test_portdiscovery_run_signature_has_no_flags_param(self):
        params = set(inspect.signature(portdiscovery.run).parameters)
        self.assertEqual(params, {"target", "progress_cb"})

    def test_nse_vuln_run_signature_has_no_flags_param(self):
        params = set(inspect.signature(nse_vuln.run).parameters)
        self.assertEqual(params, {"target", "portdiscovery_result", "progress_cb"})

    def test_webvuln_nikto_run_signature_has_no_flags_param(self):
        params = set(inspect.signature(webvuln_nikto.run).parameters)
        self.assertEqual(params, {"target", "portdiscovery_result", "progress_cb"})


if __name__ == "__main__":
    unittest.main()
