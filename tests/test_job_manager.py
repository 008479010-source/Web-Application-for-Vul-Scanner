"""
Exercises the background job lifecycle (threaded execution, per-module
progress tracking, percent computation, status transitions, and the
portdiscovery -> {nse_vuln, cve_match, webvuln_nikto} dependency wiring)
with fast fake module runners standing in for the real tool-invoking
modules — this is about proving the orchestration logic is correct,
independent of what any one module actually does.
"""

import time
import unittest
from unittest import mock

from tests._test_helpers import temp_db

import job_manager


def _fake_portdiscovery(_target, progress_cb=None):
    if progress_cb:
        progress_cb("done")
    return {"resolved_ip": "93.184.216.34", "open_ports": [{"port": 80, "product": "nginx", "version": "1.18.0"}],
            "open_count": 1, "discovery_method": "nmap-fallback", "masscan_error": None, "error": None}


def _fake_nse_vuln(_target, pd_result, progress_cb=None):
    assert pd_result.get("open_ports"), "nse_vuln should receive portdiscovery's result"
    return {"error": None, "findings": []}


def _fake_cve_match(_target, pd_result, progress_cb=None):
    assert pd_result.get("open_ports"), "cve_match should receive portdiscovery's result"
    return {"error": None, "cve_matches": []}


def _fake_webvuln_nikto(_target, pd_result, progress_cb=None):
    assert pd_result.get("open_ports"), "webvuln_nikto should receive portdiscovery's result"
    return {"error": None, "results": []}


class NormalizeModulesTests(unittest.TestCase):
    def test_dependent_module_auto_adds_portdiscovery(self):
        self.assertEqual(job_manager.normalize_modules(["nse_vuln"]), ["portdiscovery", "nse_vuln"])

    def test_invalid_modules_are_dropped(self):
        self.assertEqual(job_manager.normalize_modules(["portdiscovery", "not_a_real_module"]), ["portdiscovery"])

    def test_order_follows_module_order_regardless_of_input_order(self):
        result = job_manager.normalize_modules(["webvuln_nikto", "cve_match", "portdiscovery"])
        self.assertEqual(result, ["portdiscovery", "cve_match", "webvuln_nikto"])


class JobManagerTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(temp_db())

    def _wait_for_completion(self, job_id, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            job = job_manager.get_job(job_id)
            if job["status"] in ("completed", "error"):
                return job
            time.sleep(0.05)
        self.fail("Job did not complete within timeout")

    @mock.patch.object(job_manager, "MODULE_RUNNERS", {
        "portdiscovery": _fake_portdiscovery,
        "nse_vuln": _fake_nse_vuln,
        "cve_match": _fake_cve_match,
        "webvuln_nikto": _fake_webvuln_nikto,
    })
    def test_job_runs_all_modules_and_wires_dependency(self):
        job_id = job_manager.create_job(
            ["example.com"], ["portdiscovery", "nse_vuln", "cve_match", "webvuln_nikto"], engagement_id="test-eng",
        )
        job = self._wait_for_completion(job_id)

        self.assertEqual(job["status"], "completed")
        self.assertEqual(job_manager.compute_percent(job), 100)
        for module in ["portdiscovery", "nse_vuln", "cve_match", "webvuln_nikto"]:
            self.assertEqual(job["progress"]["example.com"][module], "done")
            self.assertIn(module, job["results"]["example.com"])

        self.assertEqual(job["progress"]["example.com"]["risk"], "done")
        self.assertIn("highest_severity", job["results"]["example.com"]["risk"])

    @mock.patch.object(job_manager, "MODULE_RUNNERS", {
        "portdiscovery": mock.Mock(side_effect=RuntimeError("boom")),
    })
    def test_module_failure_is_isolated_and_reported(self):
        job_id = job_manager.create_job(["example.com"], ["portdiscovery"], engagement_id="test-eng")
        job = self._wait_for_completion(job_id)

        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["progress"]["example.com"]["portdiscovery"], "error")
        self.assertIn("error", job["results"]["example.com"]["portdiscovery"])
        self.assertEqual(job["progress"]["example.com"]["risk"], "done")

    def test_unknown_job_id_returns_none(self):
        self.assertIsNone(job_manager.get_job("does-not-exist"))

    @mock.patch.object(job_manager, "MODULE_RUNNERS", {"portdiscovery": _fake_portdiscovery})
    def test_create_job_records_audit_events(self):
        import db
        job_id = job_manager.create_job(["example.com"], ["portdiscovery"], engagement_id="test-eng")
        self._wait_for_completion(job_id)

        events = db.list_audit_events()
        event_types = [e["event_type"] for e in events]
        self.assertIn("scan_started", event_types)
        self.assertIn("scan_completed", event_types)


if __name__ == "__main__":
    unittest.main()
