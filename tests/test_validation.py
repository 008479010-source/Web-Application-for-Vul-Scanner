"""
Unit tests for input normalization/validation in app.py — target parsing
(strips scheme/path/port, validates hostnames/IPs), bulk file parsing (CSV-
with-header, CSV-without-header, plain newline list), and the Flask routes
(engagements, scans, report/export endpoints, audit log, tool health).
"""

import time
import unittest
from unittest import mock

from tests._test_helpers import SAMPLE_ENGAGEMENT_FIELDS, temp_db

import app
import db
import job_manager


class NormalizeTargetTests(unittest.TestCase):
    def test_plain_domain_passes_through_lowercased(self):
        self.assertEqual(app.normalize_target("Example.COM"), "example.com")

    def test_strips_scheme_and_path(self):
        self.assertEqual(app.normalize_target("https://example.com/some/path?x=1"), "example.com")

    def test_strips_port(self):
        self.assertEqual(app.normalize_target("example.com:8443"), "example.com")

    def test_accepts_ipv4(self):
        self.assertEqual(app.normalize_target("203.0.113.10"), "203.0.113.10")

    def test_accepts_ipv6(self):
        self.assertEqual(app.normalize_target("2001:db8::1"), "2001:db8::1")

    def test_rejects_garbage(self):
        self.assertIsNone(app.normalize_target("not a domain!! ***"))

    def test_rejects_empty(self):
        self.assertIsNone(app.normalize_target(""))
        self.assertIsNone(app.normalize_target("   "))


class BulkUploadParsingTests(unittest.TestCase):
    def test_plain_newline_list(self):
        text = "example.com\ntest.example.org\n203.0.113.10\n"
        self.assertEqual(
            app._extract_candidates_from_upload(text),
            ["example.com", "test.example.org", "203.0.113.10"],
        )

    def test_csv_with_recognized_header(self):
        text = "domain,notes\nexample.com,primary\ntest.example.org,secondary\n"
        self.assertEqual(
            app._extract_candidates_from_upload(text),
            ["example.com", "test.example.org"],
        )

    def test_csv_without_header_uses_first_column(self):
        text = "example.com,primary\ntest.example.org,secondary\n"
        self.assertEqual(
            app._extract_candidates_from_upload(text),
            ["example.com", "test.example.org"],
        )

    def test_empty_upload(self):
        self.assertEqual(app._extract_candidates_from_upload(""), [])


class FlaskEndpointTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(temp_db())
        app.app.testing = True
        self.client = app.app.test_client()

    def _active_engagement_id(self):
        fields = dict(SAMPLE_ENGAGEMENT_FIELDS, testing_window_start="2020-01-01", testing_window_end="2099-12-31")
        return db.create_engagement(fields)

    def test_scan_requires_engagement(self):
        resp = self.client.post("/api/scan", json={"target": "example.com", "modules": ["portdiscovery"]})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("scope", resp.get_json()["error"].lower())

    def test_scan_rejects_unknown_engagement(self):
        resp = self.client.post(
            "/api/scan",
            json={"target": "example.com", "modules": ["portdiscovery"], "engagement_id": "does-not-exist"},
        )
        self.assertEqual(resp.status_code, 404)

    def test_scan_rejects_not_yet_started_engagement(self):
        fields = dict(SAMPLE_ENGAGEMENT_FIELDS, testing_window_start="2099-01-01", testing_window_end="2099-12-31")
        engagement_id = db.create_engagement(fields)
        resp = self.client.post(
            "/api/scan",
            json={"target": "example.com", "modules": ["portdiscovery"], "engagement_id": engagement_id},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("hasn't started", resp.get_json()["error"])

    def test_scan_rejects_expired_engagement(self):
        fields = dict(SAMPLE_ENGAGEMENT_FIELDS, testing_window_start="2020-01-01", testing_window_end="2020-01-02")
        engagement_id = db.create_engagement(fields)
        resp = self.client.post(
            "/api/scan",
            json={"target": "example.com", "modules": ["portdiscovery"], "engagement_id": engagement_id},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("expired", resp.get_json()["error"])

    def test_scan_rejects_invalid_target(self):
        resp = self.client.post(
            "/api/scan",
            json={"target": "not a domain!!", "modules": ["portdiscovery"], "engagement_id": self._active_engagement_id()},
        )
        self.assertEqual(resp.status_code, 400)

    def test_scan_requires_at_least_one_module(self):
        resp = self.client.post(
            "/api/scan",
            json={"target": "example.com", "modules": [], "engagement_id": self._active_engagement_id()},
        )
        self.assertEqual(resp.status_code, 400)

    @mock.patch.object(job_manager, "MODULE_RUNNERS", {"portdiscovery": lambda t, progress_cb=None: {"open_ports": [], "error": None}})
    def test_scan_with_active_engagement_starts_job(self):
        resp = self.client.post(
            "/api/scan",
            json={"target": "127.0.0.1", "modules": ["portdiscovery"], "engagement_id": self._active_engagement_id()},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("job_id", resp.get_json())

    def test_scan_auto_adds_portdiscovery_dependency(self):
        with mock.patch.object(job_manager, "create_job", return_value="fake-job-id") as spy:
            self.client.post(
                "/api/scan",
                json={"target": "example.com", "modules": ["nse_vuln"], "engagement_id": self._active_engagement_id()},
            )
        called_modules = spy.call_args[0][1]
        self.assertIn("portdiscovery", called_modules)

    def test_bulk_rejects_more_than_cap(self):
        text = "\n".join(f"host{i}.example.com" for i in range(config_max_bulk() + 1))
        resp = self.client.post(
            "/api/scan/bulk",
            data={
                "engagement_id": self._active_engagement_id(),
                "modules": ["portdiscovery"],
                "file": (make_file(text), "targets.txt"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("capped", resp.get_json()["error"])

    def test_unknown_job_returns_404(self):
        resp = self.client.get("/api/scan/doesnotexist")
        self.assertEqual(resp.status_code, 404)

    def test_index_page_loads(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Vuln Scan Toolkit", resp.data)

    def test_create_and_list_engagements(self):
        resp = self.client.post("/api/engagements", json=SAMPLE_ENGAGEMENT_FIELDS)
        self.assertEqual(resp.status_code, 200)
        engagement_id = resp.get_json()["engagement_id"]

        resp = self.client.get("/api/engagements")
        ids = [e["id"] for e in resp.get_json()["engagements"]]
        self.assertIn(engagement_id, ids)

    def test_create_engagement_rejects_missing_fields(self):
        resp = self.client.post("/api/engagements", json={"client_name": "Acme"})
        self.assertEqual(resp.status_code, 400)

    def test_audit_log_endpoint_returns_events(self):
        self._active_engagement_id()
        resp = self.client.get("/api/audit")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(len(resp.get_json()["events"]) >= 1)

    def test_tool_health_endpoint_returns_all_three_tools(self):
        resp = self.client.get("/api/health/tools")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(set(data.keys()), {"nmap", "masscan", "nikto"})
        for info in data.values():
            self.assertIn("available", info)


def config_max_bulk():
    import config
    return config.MAX_BULK_TARGETS


def make_file(text):
    import io
    return io.BytesIO(text.encode("utf-8"))


class ReportAndExportEndpointTests(unittest.TestCase):
    """Covers the report/export routes against a completed job, using a
    fake fast module runner so this stays network-independent."""

    def setUp(self):
        self.enterContext(temp_db())
        app.app.testing = True
        self.client = app.app.test_client()

        engagement_id = db.create_engagement(
            dict(SAMPLE_ENGAGEMENT_FIELDS, testing_window_start="2020-01-01", testing_window_end="2099-12-31")
        )
        with mock.patch.object(job_manager, "MODULE_RUNNERS", {
            "portdiscovery": lambda t, progress_cb=None: {"open_ports": [], "open_count": 0, "resolved_ip": None,
                                                            "discovery_method": "nmap-fallback", "masscan_error": None, "error": None},
        }):
            self.job_id = job_manager.create_job(["example.com"], ["portdiscovery"], engagement_id)

        deadline = time.time() + 5
        while time.time() < deadline:
            if job_manager.get_job(self.job_id)["status"] in ("completed", "error"):
                break
            time.sleep(0.05)

    def test_report_view_returns_html(self):
        resp = self.client.get(f"/api/scan/{self.job_id}/report")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Scope", resp.data)
        self.assertIn(b"Acme Corp", resp.data)

    def test_report_download_sets_attachment_headers(self):
        resp = self.client.get(f"/api/scan/{self.job_id}/report?download=1")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("attachment", resp.headers.get("Content-Disposition", ""))

    def test_export_json_returns_json_attachment(self):
        resp = self.client.get(f"/api/scan/{self.job_id}/export.json")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "application/json")

    def test_export_csv_returns_csv_attachment(self):
        resp = self.client.get(f"/api/scan/{self.job_id}/export.csv")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "text/csv")

    def test_report_and_exports_record_audit_events(self):
        self.client.get(f"/api/scan/{self.job_id}/report")
        self.client.get(f"/api/scan/{self.job_id}/export.json")
        events = [e["event_type"] for e in db.list_audit_events()]
        self.assertIn("report_exported", events)


if __name__ == "__main__":
    unittest.main()
