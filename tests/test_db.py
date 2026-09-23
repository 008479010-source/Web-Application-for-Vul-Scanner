"""
Tests for the SQLite-backed engagement (Scope & Authorization) persistence
layer, the audit log, and the NVD CVE cache. Every test runs against a
throwaway temp database.
"""

import unittest
from datetime import datetime, timezone

from tests._test_helpers import SAMPLE_ENGAGEMENT_FIELDS, temp_db

import db


class EngagementTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(temp_db())

    def test_create_and_get_engagement(self):
        engagement_id = db.create_engagement(SAMPLE_ENGAGEMENT_FIELDS)
        engagement = db.get_engagement(engagement_id)
        self.assertIsNotNone(engagement)
        self.assertEqual(engagement["client_name"], "Acme Corp")
        self.assertEqual(engagement["engagement_name"], "Q3 Vulnerability Assessment")

    def test_get_unknown_engagement_returns_none(self):
        self.assertIsNone(db.get_engagement("does-not-exist"))

    def test_list_engagements_sorted_newest_first(self):
        first_id = db.create_engagement(SAMPLE_ENGAGEMENT_FIELDS)
        second_fields = dict(SAMPLE_ENGAGEMENT_FIELDS, engagement_name="Second Engagement")
        second_id = db.create_engagement(second_fields)

        engagements = db.list_engagements()
        ids = [e["id"] for e in engagements]
        self.assertIn(first_id, ids)
        self.assertIn(second_id, ids)
        self.assertLess(ids.index(second_id), ids.index(first_id))

    def test_window_status_active(self):
        fields = dict(SAMPLE_ENGAGEMENT_FIELDS, testing_window_start="2020-01-01", testing_window_end="2099-12-31")
        engagement = db.get_engagement(db.create_engagement(fields))
        self.assertEqual(db.engagement_window_status(engagement), "active")

    def test_window_status_not_started(self):
        fields = dict(SAMPLE_ENGAGEMENT_FIELDS, testing_window_start="2099-01-01", testing_window_end="2099-12-31")
        engagement = db.get_engagement(db.create_engagement(fields))
        self.assertEqual(db.engagement_window_status(engagement), "not_started")

    def test_window_status_expired(self):
        fields = dict(SAMPLE_ENGAGEMENT_FIELDS, testing_window_start="2020-01-01", testing_window_end="2020-01-02")
        engagement = db.get_engagement(db.create_engagement(fields))
        self.assertEqual(db.engagement_window_status(engagement), "expired")

    def test_window_end_date_is_inclusive_of_whole_day(self):
        today = datetime.now(timezone.utc).date().isoformat()
        fields = dict(SAMPLE_ENGAGEMENT_FIELDS, testing_window_start="2020-01-01", testing_window_end=today)
        engagement = db.get_engagement(db.create_engagement(fields))
        self.assertEqual(db.engagement_window_status(engagement), "active")

    def test_creating_engagement_writes_audit_event(self):
        db.create_engagement(SAMPLE_ENGAGEMENT_FIELDS)
        events = db.list_audit_events()
        self.assertTrue(any(e["event_type"] == "engagement_created" for e in events))


class AuditLogTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(temp_db())

    def test_record_and_list_events(self):
        db.record_audit_event("scan_started", engagement_id="eng1", job_id="job1", detail={"targets": ["example.com"]})
        db.record_audit_event("scan_completed", engagement_id="eng1", job_id="job1")

        events = db.list_audit_events()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["event_type"], "scan_completed")
        self.assertEqual(events[1]["event_type"], "scan_started")

    def test_list_events_respects_limit(self):
        for i in range(5):
            db.record_audit_event("test_event", detail=str(i))
        events = db.list_audit_events(limit=3)
        self.assertEqual(len(events), 3)


class CveCacheTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(temp_db())

    def test_cache_miss_returns_none(self):
        self.assertIsNone(db.get_cve_cache("nginx::1.18.0"))

    def test_store_then_get_round_trips(self):
        results = [{"id": "CVE-2021-41773", "severity": "critical", "score": 9.8, "description": "..."}]
        db.store_cve_cache("nginx::1.18.0", "nginx", "1.18.0", results, ttl_seconds=3600)
        cached = db.get_cve_cache("nginx::1.18.0")
        self.assertEqual(cached, results)

    def test_expired_entry_is_not_returned(self):
        results = [{"id": "CVE-0000-0000", "severity": "info", "score": None, "description": "x"}]
        db.store_cve_cache("oldapp::1.0", "oldapp", "1.0", results, ttl_seconds=-1)
        self.assertIsNone(db.get_cve_cache("oldapp::1.0"))


if __name__ == "__main__":
    unittest.main()
