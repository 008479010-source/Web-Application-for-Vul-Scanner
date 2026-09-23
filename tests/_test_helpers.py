"""
Shared test helpers: isolate each test's database writes into a throwaway
SQLite file rather than touching the app's real data/vulnscan.db.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import tempfile

import config
import db


@contextlib.contextmanager
def temp_db():
    original_path = config.DB_PATH
    tmpdir = tempfile.mkdtemp(prefix="vuln-scan-toolkit-test-")
    config.DB_PATH = os.path.join(tmpdir, "test.db")
    db.init_db()
    try:
        yield
    finally:
        config.DB_PATH = original_path
        shutil.rmtree(tmpdir, ignore_errors=True)


SAMPLE_ENGAGEMENT_FIELDS = {
    "client_name": "Acme Corp",
    "engagement_name": "Q3 Vulnerability Assessment",
    "scope_description": "*.example.com, 203.0.113.0/24 — active vulnerability scanning authorized",
    "authorized_by": "Jane Smith, CISO",
    "authorization_date": "2026-01-01",
    "testing_window_start": "2020-01-01",
    "testing_window_end": "2099-12-31",
    "rules_of_engagement": "No denial-of-service; business hours only.",
    "contact_name": "John Doe",
    "contact_email": "john@example.com",
}
