"""
Builds a PTES-style vulnerability-assessment report from a completed (or
in-progress) scan job: Executive Summary, Scope & Authorization,
Methodology, Findings with risk ratings, Recommendations, and a raw-data
Appendix.

Rendered as a single self-contained HTML file - printable to PDF from any
browser - so no extra PDF-generation dependency is needed.
"""

from __future__ import annotations

from datetime import datetime, timezone

from flask import render_template

from modules.risk import SEVERITY_ORDER

METHODOLOGY_MAP = {
    "portdiscovery": {
        "phase": "Vulnerability Analysis",
        "description": "Fast wide port discovery (masscan) handed off to nmap service/version detection "
                        "(-sV) on the ports found open.",
        "standards": [
            "PTES — Vulnerability Analysis",
            "NIST SP 800-115 §5.2 (Network Port and Service Identification)",
            "MITRE ATT&CK T1595.001 (Active Scanning: Scanning IP Blocks)",
        ],
    },
    "nse_vuln": {
        "phase": "Vulnerability Analysis (active)",
        "description": "nmap NSE 'vuln' script category run against discovered open ports - genuine active "
                        "vulnerability probing, not passive version matching.",
        "standards": [
            "PTES — Vulnerability Analysis",
            "NIST SP 800-115 §5.3 (Vulnerability Scanning)",
            "MITRE ATT&CK T1595.002 (Active Scanning: Vulnerability Scanning)",
        ],
    },
    "webvuln_nikto": {
        "phase": "Vulnerability Analysis (active)",
        "description": "nikto web-server misconfiguration and known-vulnerability scan against each "
                        "discovered HTTP/HTTPS service.",
        "standards": [
            "PTES — Vulnerability Analysis",
            "OWASP Testing Guide — Configuration and Deployment Management Testing",
            "MITRE ATT&CK T1595.002 (Active Scanning: Vulnerability Scanning)",
        ],
    },
    "cve_match": {
        "phase": "Vulnerability Analysis",
        "description": "Detected product/version pairs matched against live NVD CVE data via free-text "
                        "keyword search. Matches are candidates requiring human triage, not confirmed "
                        "vulnerabilities — NVD keywordSearch is not exact CPE matching.",
        "standards": [
            "PTES — Vulnerability Analysis",
            "NIST SP 800-115 §5.3 (Vulnerability Scanning)",
            "Referenced concept: FIRST CVSS severity rating scale",
        ],
    },
    "risk": {
        "phase": "Vulnerability Analysis / Reporting",
        "description": "Automated qualitative risk rating (Critical/High/Medium/Low/Info) unifying CVSS "
                        "scores, NSE script verdicts, nikto findings, and open-port heuristics.",
        "standards": [
            "PTES — Reporting (risk rating)",
            "Referenced concept: FIRST CVSS severity rating scale",
            "Referenced concept: NIST Cybersecurity Framework risk categories",
        ],
    },
}

RECOMMENDATION_BY_CATEGORY = {
    "open-port": "Confirm whether this port needs to be internet-facing. Close it, or restrict access with a "
                 "firewall rule, if it does not need to be public.",
    "nse-vuln": "Investigate and remediate the specific vulnerability nmap's NSE script flagged; verify the "
                "affected service is patched to a version that addresses it.",
    "web-misconfig": "Address the specific web-server misconfiguration nikto flagged (e.g. remove exposed "
                      "backup/config files, disable directory listing, apply the latest vendor patches).",
    "cve-candidate": "Manually verify whether the installed version is actually affected by the listed CVE(s) "
                      "(NVD keyword matches are candidates, not confirmed hits), then patch or mitigate "
                      "accordingly.",
}

SEVERITY_LABEL = {
    "critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info", "none": "None",
}


def _aggregate_executive_summary(job: dict) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    targets_with_findings = 0
    for target_results in job["results"].values():
        risk = target_results.get("risk", {})
        target_counts = risk.get("counts", {})
        if any(target_counts.values()):
            targets_with_findings += 1
        for sev, n in target_counts.items():
            counts[sev] = counts.get(sev, 0) + n

    highest = next((s for s in SEVERITY_ORDER if counts.get(s, 0) > 0), "none")
    return {
        "targets_tested": len(job["targets"]),
        "targets_with_findings": targets_with_findings,
        "severity_counts": counts,
        "highest_overall_severity": highest,
    }


def _methodology_sections(job: dict) -> list[dict]:
    sections = []
    for module in job.get("modules", []):
        if module in METHODOLOGY_MAP:
            sections.append(METHODOLOGY_MAP[module])
    if job.get("modules"):
        sections.append(METHODOLOGY_MAP["risk"])
    return sections


def _recommendations(job: dict) -> list[dict]:
    seen_categories: dict[str, str] = {}
    for target_results in job["results"].values():
        for finding in target_results.get("risk", {}).get("findings", []):
            cat = finding["category"]
            if cat not in seen_categories and cat in RECOMMENDATION_BY_CATEGORY:
                seen_categories[cat] = RECOMMENDATION_BY_CATEGORY[cat]
    return [{"category": cat, "text": text} for cat, text in seen_categories.items()]


def render_report(job: dict, engagement: dict | None) -> str:
    context = {
        "job": job,
        "engagement": engagement,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "executive_summary": _aggregate_executive_summary(job),
        "methodology_sections": _methodology_sections(job),
        "recommendations": _recommendations(job),
        "severity_order": SEVERITY_ORDER,
        "severity_label": SEVERITY_LABEL,
    }
    return render_template("report.html", **context)
