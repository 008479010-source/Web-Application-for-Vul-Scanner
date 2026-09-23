"""Cross-source severity aggregation: takes the raw output of
portdiscovery / nse_vuln / webvuln_nikto / cve_match for one target and
produces one unified, sorted findings list.

Pure functions, no I/O - same contract shape throughout: assess() returns
{"findings": [...], "counts": {severity: n}, "highest_severity": str}, so
report_builder.py and the CSV/JSON exports don't need to special-case
which module a finding came from.

The severity buckets below are a heuristic triage aid, not a CVSS
calculator or a compliance standard - treat them as a starting point for
analyst review, same disclaimer spirit as any rule-based risk scorer.
"""

from __future__ import annotations

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Ports with no CVE/NSE/nikto finding attached still get a baseline
# heuristic rating so an open, unexplained service isn't silently ignored.
_PORT_RISK_RULES = {
    21: ("medium", "FTP - often plaintext credentials/anonymous access"),
    23: ("critical", "Telnet - unencrypted remote administration"),
    25: ("low", "SMTP - review for open relay/spoofing exposure"),
    53: ("info", "DNS service exposed"),
    110: ("medium", "POP3 - often plaintext credentials"),
    111: ("medium", "RPCbind - historically used to enumerate/attack RPC services"),
    135: ("high", "MS RPC endpoint mapper - common lateral-movement target"),
    139: ("high", "NetBIOS - legacy SMB, high attack surface"),
    143: ("medium", "IMAP - often plaintext credentials"),
    445: ("high", "SMB - frequent target for worms/lateral movement (verify patch level)"),
    1433: ("medium", "MSSQL exposed directly to the network"),
    1521: ("medium", "Oracle DB listener exposed directly to the network"),
    2049: ("medium", "NFS exposed - verify export permissions"),
    3306: ("medium", "MySQL exposed directly to the network"),
    3389: ("high", "RDP exposed - common brute-force/exploit target"),
    5432: ("medium", "PostgreSQL exposed directly to the network"),
    5900: ("high", "VNC exposed - often weak/no authentication"),
    6379: ("high", "Redis exposed - frequently unauthenticated by default"),
    9200: ("medium", "Elasticsearch exposed - verify authentication is enabled"),
    11211: ("medium", "Memcached exposed - can be abused for amplification/data exposure"),
    27017: ("medium", "MongoDB exposed - verify authentication is enabled"),
}


def _finding(severity: str, category: str, title: str, description: str,
             evidence: str | None = None, source: str | None = None,
             cve_ids: list[str] | None = None) -> dict:
    return {
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "evidence": evidence,
        "source": source,
        "cve_ids": cve_ids or [],
    }


def _assess_portdiscovery(results: dict) -> list[dict]:
    findings = []
    for p in results.get("open_ports", []):
        port = p["port"]
        rule = _PORT_RISK_RULES.get(port)
        if rule:
            severity, reason = rule
        else:
            severity, reason = "info", "No specific risk rule matched this port; review whether it needs to be externally reachable."
        findings.append(_finding(
            severity, "open-port", f"Port {port}/{p.get('protocol', 'tcp')} open ({p.get('service') or 'unknown'})",
            reason, evidence=p.get("banner") or None, source="portdiscovery",
        ))
    return findings


def _assess_nse_vuln(results: dict) -> list[dict]:
    findings = []
    for f in results.get("findings", []):
        if f["verdict"] == "vulnerable":
            title = f"nmap NSE: {f['script_id']} reports VULNERABLE"
        else:
            title = f"nmap NSE: {f['script_id']} (informational)"
        port_note = f" (port {f['port']})" if f.get("port") else ""
        findings.append(_finding(
            f["severity"], "nse-vuln", title + port_note,
            f["output"][:500], evidence=f["output"][:300], source="nse_vuln",
            cve_ids=f.get("cve_ids", []),
        ))
    return findings


def _assess_nikto(results: dict) -> list[dict]:
    findings = []
    for service_result in results.get("results", []):
        if service_result.get("error"):
            continue
        port = service_result.get("service_port")
        for item in service_result.get("findings", []):
            findings.append(_finding(
                item["severity"], "web-misconfig",
                f"nikto (port {port}): {item['description'][:80]}",
                item["description"], evidence=item.get("uri") or None, source="webvuln_nikto",
            ))
    return findings


def _assess_cve_match(results: dict) -> list[dict]:
    findings = []
    for match in results.get("cve_matches", []):
        if match.get("error"):
            continue
        for cve in match.get("cves", []):
            findings.append(_finding(
                cve["severity"], "cve-candidate",
                f"{cve['id']} - candidate match for {match['product']} {match['version']}",
                (cve.get("description") or "")[:500] + "  [Candidate match from free-text NVD keyword search - requires human verification, not a confirmed vulnerability.]",
                evidence=f"CVSS {cve['score']}" if cve.get("score") is not None else None,
                source="cve_match", cve_ids=[cve["id"]],
            ))
    return findings


def assess(target: str, module_results: dict) -> dict:
    findings: list[dict] = []

    if "portdiscovery" in module_results:
        findings += _assess_portdiscovery(module_results["portdiscovery"])
    if "nse_vuln" in module_results:
        findings += _assess_nse_vuln(module_results["nse_vuln"])
    if "webvuln_nikto" in module_results:
        findings += _assess_nikto(module_results["webvuln_nikto"])
    if "cve_match" in module_results:
        findings += _assess_cve_match(module_results["cve_match"])

    findings.sort(key=lambda f: _RANK.get(f["severity"], len(SEVERITY_ORDER)))

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    highest_severity = next((s for s in SEVERITY_ORDER if counts.get(s)), "info")

    return {"findings": findings, "counts": counts, "highest_severity": highest_severity}
