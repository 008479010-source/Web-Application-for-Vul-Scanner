"""Live NVD CVE matching against product+version pairs found by
portdiscovery.

Uses NVD's keywordSearch (free-text), not exact CPE matching - this is
faster to implement and doesn't require deriving well-formed CPE strings
from banner text, but it means matches are candidates requiring human
triage, not confirmed vulnerabilities. That framing must carry through to
the report/UI, not just this module's docstring.

NVD's public rate limit (5 requests/rolling-30s without an API key, 50/30s
with one) is global to the whole process/IP, not per scan job. Since
MAX_CONCURRENT_JOBS allows more than one job to run cve_match at the same
time, the throttle state below is intentionally module-level (shared
across every job thread), not local to a single run() call.
"""

from __future__ import annotations

import threading
import time

import requests

import config
import db

_nvd_lock = threading.Lock()
_last_nvd_call_ts = 0.0

_PLACEHOLDER_VERSIONS = {"", "unknown", "n/a"}


def _throttle_nvd() -> None:
    global _last_nvd_call_ts
    delay = config.NVD_REQUEST_DELAY_WITH_KEY if config.NVD_API_KEY else config.NVD_REQUEST_DELAY_NO_KEY
    with _nvd_lock:
        wait = delay - (time.monotonic() - _last_nvd_call_ts)
        if wait > 0:
            time.sleep(wait)
        _last_nvd_call_ts = time.monotonic()


def _unique_product_versions(open_ports: list[dict]) -> list[tuple[str, str]]:
    seen = set()
    pairs = []
    for p in open_ports:
        product = (p.get("product") or "").strip()
        version = (p.get("version") or "").strip()
        if not product or version.lower() in _PLACEHOLDER_VERSIONS:
            continue
        key = (product.lower(), version)
        if key not in seen:
            seen.add(key)
            pairs.append((product, version))
    return pairs


def _cache_key(product: str, version: str) -> str:
    return f"{product.lower()}::{version}"


def _cvss_score(cve_obj: dict) -> tuple[float | None, str]:
    metrics = cve_obj.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            if score is not None:
                return float(score), key
    return None, ""


def score_to_severity(score: float | None) -> str:
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def _parse_nvd_response(payload: dict) -> list[dict]:
    results = []
    for vuln in payload.get("vulnerabilities", []):
        cve_obj = vuln.get("cve", {})
        cve_id = cve_obj.get("id", "")
        description = ""
        for d in cve_obj.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        score, _source = _cvss_score(cve_obj)
        results.append({
            "id": cve_id,
            "severity": score_to_severity(score),
            "score": score,
            "description": description,
        })
    results.sort(key=lambda r: (r["score"] is None, -(r["score"] or 0)))
    return results[: config.NVD_MAX_RESULTS_PER_PRODUCT]


def _query_nvd(product: str, version: str) -> list[dict]:
    keyword = f"{product} {version}".strip().replace("\n", " ").replace("\r", " ")[:100]
    headers = {"User-Agent": config.USER_AGENT}
    if config.NVD_API_KEY:
        headers["apiKey"] = config.NVD_API_KEY

    _throttle_nvd()
    resp = requests.get(
        config.NVD_API_URL,
        params={"keywordSearch": keyword, "resultsPerPage": config.NVD_RESULTS_PER_PAGE},
        headers=headers,
        timeout=config.NVD_HTTP_TIMEOUT,
    )
    if resp.status_code == 429:
        time.sleep(5)
        _throttle_nvd()
        resp = requests.get(
            config.NVD_API_URL,
            params={"keywordSearch": keyword, "resultsPerPage": config.NVD_RESULTS_PER_PAGE},
            headers=headers,
            timeout=config.NVD_HTTP_TIMEOUT,
        )
    resp.raise_for_status()
    return _parse_nvd_response(resp.json())


def run(target: str, portdiscovery_result: dict, progress_cb=None) -> dict:
    if portdiscovery_result.get("error"):
        return {"skipped": "port discovery failed; nothing to match", "cve_matches": []}

    pairs = _unique_product_versions(portdiscovery_result.get("open_ports", []))
    if not pairs:
        return {"skipped": "no product+version pairs available for CVE matching", "cve_matches": []}

    matches = []
    rate_limited = False

    for i, (product, version) in enumerate(pairs, start=1):
        if progress_cb:
            progress_cb(f"CVE lookup {i}/{len(pairs)} ({product} {version})")

        cache_key = _cache_key(product, version)
        cached = db.get_cve_cache(cache_key)
        if cached is not None:
            matches.append({"product": product, "version": version, "source": "cache", "cves": cached, "error": None})
            continue

        if rate_limited:
            matches.append({
                "product": product, "version": version, "source": None, "cves": [],
                "error": "skipped: NVD rate limit reached earlier in this scan",
            })
            continue

        try:
            cves = _query_nvd(product, version)
            db.store_cve_cache(cache_key, product, version, cves, config.CVE_CACHE_TTL_SECONDS)
            matches.append({"product": product, "version": version, "source": "live", "cves": cves, "error": None})
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 429:
                rate_limited = True
            matches.append({
                "product": product, "version": version, "source": None, "cves": [],
                "error": f"NVD request failed: {exc}",
            })
        except Exception as exc:  # noqa: BLE001
            matches.append({
                "product": product, "version": version, "source": None, "cves": [],
                "error": f"NVD request failed: {exc}",
            })

    return {"error": None, "products_checked": [{"product": p, "version": v} for p, v in pairs],
            "cve_matches": matches, "rate_limited": rate_limited}
