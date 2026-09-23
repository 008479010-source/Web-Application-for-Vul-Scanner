"""All tunables for Vuln Scan Toolkit in one place. Everything here is
env-overridable so deployments can adjust behavior without touching code."""

from __future__ import annotations

import os

SECRET_KEY = os.environ.get("VULNSCAN_SECRET_KEY", "dev-key-change-me")

DB_PATH = os.environ.get(
    "VULNSCAN_DB_PATH",
    os.path.join(os.path.dirname(__file__), "data", "vulnscan.db"),
)

# --- Job orchestration ---
# Lower than a passive-recon tool would use: NSE vuln scripts + nikto can run
# 15-25+ minutes per target, so fewer concurrent jobs and a longer retention
# window keep results around long enough to actually be reviewed.
MAX_CONCURRENT_JOBS = 2
JOB_RETENTION_SECONDS = 7200
MAX_BULK_TARGETS = 5

# --- External tool binaries (override if not on PATH) ---
NMAP_PATH = os.environ.get("NMAP_PATH", "nmap")
MASSCAN_PATH = os.environ.get("MASSCAN_PATH", "masscan")
NIKTO_PATH = os.environ.get("NIKTO_PATH", "nikto")

# --- Port discovery: masscan (wide/fast) -> nmap -sV (deep) ---
MASSCAN_PORT_RANGE = os.environ.get("MASSCAN_PORT_RANGE", "1-1024")
MASSCAN_RATE_PPS = int(os.environ.get("MASSCAN_RATE_PPS", "1000"))
MASSCAN_WAIT_SECONDS = 3
MASSCAN_TIMEOUT = 120

NMAP_VERSION_INTENSITY = 5
NMAP_SERVICE_SCAN_TIMEOUT = 180

# Fallback port list used when masscan is unavailable/fails - nmap alone
# scans these instead of the full masscan range.
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5900,
    5985, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200,
    11211, 27017,
]

# --- NSE vuln scanning (active) ---
NSE_SCRIPT_TIMEOUT = 60
NSE_VULN_SCAN_TIMEOUT = 900
NSE_MAX_PORTS = 50

# --- nikto (web misconfig scan) ---
NIKTO_TIMEOUT_PER_SERVICE = 480
NIKTO_MAX_SERVICES_PER_TARGET = 4
HTTP_LIKE_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8081, 8888, 9090}

# --- NVD CVE matching ---
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY")
NVD_HTTP_TIMEOUT = 15
NVD_RESULTS_PER_PAGE = 20
NVD_MAX_RESULTS_PER_PRODUCT = 10
NVD_REQUEST_DELAY_NO_KEY = 6.5
NVD_REQUEST_DELAY_WITH_KEY = 0.65
CVE_CACHE_TTL_SECONDS = int(os.environ.get("CVE_CACHE_TTL_SECONDS", str(7 * 86400)))

USER_AGENT = "VulnScanToolkit/1.0 (authorized-security-testing)"
