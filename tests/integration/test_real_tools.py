"""
True end-to-end tests against the real nmap/masscan/nikto binaries and a
local ephemeral HTTP server. NOT run by default:

- masscan needs raw-socket privilege (root or cap_net_raw via setcap),
  which most CI/dev environments don't grant.
- None of the three binaries can be assumed present in a generic
  environment.

Opt in explicitly:  VULNSCAN_RUN_INTEGRATION_TESTS=1 python -m unittest tests.integration.test_real_tools
"""

import http.server
import os
import shutil
import threading
import unittest

from modules import portdiscovery

RUN_INTEGRATION = os.environ.get("VULNSCAN_RUN_INTEGRATION_TESTS") == "1"


@unittest.skipUnless(RUN_INTEGRATION and shutil.which("nmap"), "set VULNSCAN_RUN_INTEGRATION_TESTS=1 and install nmap to run")
class RealPortDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.server = http.server.HTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()

    def test_discovers_local_http_server(self):
        result = portdiscovery.run("127.0.0.1")
        self.assertIsNone(result["error"])
        ports = [p["port"] for p in result["open_ports"]]
        self.assertIn(self.port, ports)


if __name__ == "__main__":
    unittest.main()
