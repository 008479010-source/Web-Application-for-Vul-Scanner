"""
Tests for report_builder.render_report — the PTES-structured HTML report.
Uses a real (temp) engagement record and a hand-built job dict shaped like
what job_manager actually produces.
"""

import unittest

from tests._test_helpers import SAMPLE_ENGAGEMENT_FIELDS, temp_db

import app as app_module
import db
import report_builder


def _sample_job():
    return {
        "id": "abc123def456",
        "engagement_id": "eng1",
        "targets": ["example.com"],
        "modules": ["portdiscovery", "nse_vuln", "cve_match", "webvuln_nikto"],
        "status": "completed",
        "created_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:05:00+00:00",
        "results": {
            "example.com": {
                "portdiscovery": {
                    "resolved_ip": "93.184.216.34",
                    "discovery_method": "nmap-fallback",
                    "masscan_error": None,
                    "open_ports": [
                        {"port": 23, "protocol": "tcp", "service": "telnet", "product": "", "version": "",
                         "extrainfo": "", "banner": "telnetd"},
                    ],
                    "open_count": 1,
                    "error": None,
                },
                "nse_vuln": {"error": None, "findings": []},
                "webvuln_nikto": {"error": None, "results": []},
                "cve_match": {"error": None, "cve_matches": [], "products_checked": [], "rate_limited": False},
                "risk": {
                    "findings": [
                        {"severity": "critical", "category": "open-port",
                         "title": "Port 23/tcp open (telnet)",
                         "description": "Telnet - unencrypted remote administration.",
                         "evidence": "telnetd", "source": "portdiscovery", "cve_ids": []},
                        {"severity": "high", "category": "cve-candidate",
                         "title": "CVE-2021-41773 - candidate match for Apache 2.4.49",
                         "description": "Path traversal vulnerability.",
                         "evidence": "CVSS 9.8", "source": "cve_match", "cve_ids": ["CVE-2021-41773"]},
                    ],
                    "counts": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
                    "highest_severity": "critical",
                },
            },
        },
        "progress": {},
        "error": None,
    }


_UNSET = object()


class ReportBuilderTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(temp_db())
        self.engagement = db.get_engagement(db.create_engagement(SAMPLE_ENGAGEMENT_FIELDS))
        self.job = _sample_job()

    def _render(self, job=_UNSET, engagement=_UNSET):
        with app_module.app.test_request_context():
            return report_builder.render_report(
                self.job if job is _UNSET else job,
                self.engagement if engagement is _UNSET else engagement,
            )

    def test_report_includes_engagement_details(self):
        html = self._render()
        self.assertIn("Acme Corp", html)
        self.assertIn("Q3 Vulnerability Assessment", html)
        self.assertIn("Jane Smith, CISO", html)

    def test_report_handles_missing_engagement(self):
        html = self._render(engagement=None)
        self.assertIn("No Scope", html)

    def test_report_includes_executive_summary_counts(self):
        html = self._render()
        self.assertIn("Critical", html)
        self.assertIn("example.com", html)

    def test_report_includes_methodology_standards(self):
        html = self._render()
        self.assertIn("PTES", html)
        self.assertIn("ATT&amp;CK", html)
        self.assertIn("NIST SP 800-115", html)

    def test_report_includes_findings_and_cve_ids(self):
        html = self._render()
        self.assertIn("Port 23/tcp open (telnet)", html)
        self.assertIn("CVE-2021-41773", html)
        self.assertIn("sev-critical", html)
        self.assertIn("sev-high", html)

    def test_report_includes_recommendation_for_cve_candidate(self):
        html = self._render()
        self.assertIn("Manually verify whether the installed version", html)

    def test_report_includes_open_ports_table(self):
        html = self._render()
        self.assertIn("Open ports", html)
        self.assertIn("telnetd", html)

    def test_report_includes_raw_appendix_data(self):
        html = self._render()
        self.assertIn("Appendix", html)
        self.assertIn("93.184.216.34", html)

    def test_report_with_no_findings_shows_clean_message(self):
        job = _sample_job()
        job["results"]["example.com"]["risk"] = {
            "findings": [], "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}, "highest_severity": "none",
        }
        html = self._render(job=job)
        self.assertIn("No risk findings flagged", html)


if __name__ == "__main__":
    unittest.main()
