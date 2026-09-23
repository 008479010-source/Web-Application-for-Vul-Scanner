"""Active vulnerability detection via nmap's NSE 'vuln' script category.

Deliberately a *separate* nmap invocation from portdiscovery.py (which
already ran -sV once) rather than combining into one `-sV --script vuln`
call, so a hung/crashing script here can't also corrupt portdiscovery's
data - cve_match and webvuln_nikto both depend on portdiscovery having
succeeded independently of whether this module has trouble. The cost is
roughly double nmap wall-clock per target; that's an accepted tradeoff for
fault isolation, not an oversight.
"""

from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET

import config
from modules._proc import binary_available, run_tool

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

# Script-name substrings that indicate a severe, well-known class of
# vulnerability (remote code execution, known worms/backdoors) - used to
# bump a VULNERABLE verdict from High to Critical. This is a heuristic
# judgment call for triage purposes, not an authoritative classification.
_CRITICAL_SCRIPT_HINTS = ("rce", "backdoor", "eternalblue", "shellshock", "smb-vuln-ms17-010")


def _build_command(target: str, ports: list[int]) -> list[str]:
    port_csv = ",".join(str(int(p)) for p in ports)
    return [
        config.NMAP_PATH,
        "-sV", "-Pn",
        "--script", "vuln",
        "--script-timeout", f"{config.NSE_SCRIPT_TIMEOUT}s",
        "-p", port_csv,
        "-oX", "-",
        target,
    ]


def _script_findings(script_el, port: int | None) -> list[dict]:
    findings = []
    script_id = script_el.get("id", "")
    output = script_el.get("output", "") or ""
    upper = output.upper()

    if "NOT VULNERABLE" in upper:
        return findings  # confirmed clean - no finding to report
    if "VULNERABLE" in upper:
        verdict = "vulnerable"
        severity = "critical" if any(h in script_id.lower() for h in _CRITICAL_SCRIPT_HINTS) else "high"
    elif output.strip():
        verdict = "info"
        severity = "info"
    else:
        return findings  # ran, produced nothing - not a finding

    findings.append({
        "script_id": script_id,
        "port": port,
        "verdict": verdict,
        "severity": severity,
        "output": output.strip(),
        "cve_ids": _CVE_RE.findall(output),
    })
    return findings


def _parse_output(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    host = root.find("host")
    if host is None:
        return []

    findings = []
    for script_el in host.findall("hostscript/script"):
        findings.extend(_script_findings(script_el, port=None))

    ports_el = host.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            port = int(port_el.get("portid"))
            for script_el in port_el.findall("script"):
                findings.extend(_script_findings(script_el, port=port))

    return findings


def run(target: str, portdiscovery_result: dict, progress_cb=None) -> dict:
    if portdiscovery_result.get("error") or not portdiscovery_result.get("open_ports"):
        return {"skipped": "no open ports available from port discovery", "findings": []}

    if not binary_available(config.NMAP_PATH):
        return {"error": "nmap not found; NSE vuln scan skipped", "findings": []}

    ports = [p["port"] for p in portdiscovery_result["open_ports"][: config.NSE_MAX_PORTS]]

    if progress_cb:
        progress_cb(f"nmap --script vuln ({len(ports)} ports)")

    try:
        proc = run_tool(_build_command(target, ports), timeout=config.NSE_VULN_SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {
            "error": f"NSE vuln scan timed out after {config.NSE_VULN_SCAN_TIMEOUT}s (results discarded)",
            "findings": [],
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": f"NSE vuln scan failed: {exc}", "findings": []}

    if proc.returncode != 0:
        return {"error": f"nmap exited with status {proc.returncode}: {proc.stderr.strip()[:300]}", "findings": []}

    try:
        findings = _parse_output(proc.stdout)
    except ET.ParseError as exc:
        return {"error": f"failed to parse nmap XML output: {exc}", "findings": []}

    return {"error": None, "findings": findings}
