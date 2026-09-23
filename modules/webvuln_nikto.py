"""Web-server misconfiguration/vulnerability scanning via nikto, run once
per HTTP/HTTPS service that portdiscovery found open.

nikto writes to a real temp file rather than piping XML to stdout: unlike
nmap's well-documented, version-stable `-oX -`, nikto's stdout support for
`-Format xml` isn't uniformly reliable across versions/forks. A temp file
read back afterwards is the standard, portable approach.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET

import config
from modules._proc import binary_available, run_tool

_HIGH_SIGNAL_KEYWORDS = ("sql injection", "xss", "cross-site scripting", "backdoor", "default credential", "default password")
_MEDIUM_SIGNAL_KEYWORDS = ("outdated", "backup file", "directory listing", "shellshock", "config file")


def _qualifying_services(open_ports: list[dict]) -> list[dict]:
    qualifying = []
    for p in open_ports:
        service = (p.get("service") or "").lower()
        port = p.get("port")
        if "http" in service or port in config.HTTP_LIKE_PORTS:
            is_https = port in (443, 8443) or "ssl" in service or "https" in service
            qualifying.append({"port": port, "is_https": is_https})
    return qualifying[: config.NIKTO_MAX_SERVICES_PER_TARGET]


def _build_command(target: str, port: int, is_https: bool, output_path: str) -> list[str]:
    argv = [
        config.NIKTO_PATH,
        "-h", target,
        "-p", str(port),
    ]
    if is_https:
        argv.append("-ssl")
    argv += [
        "-Format", "xml",
        "-output", output_path,
        "-nointeractive",
        "-timeout", str(config.NIKTO_TIMEOUT_PER_SERVICE),
    ]
    return argv


def _severity_for_description(description: str) -> str:
    lower = description.lower()
    if any(k in lower for k in _HIGH_SIGNAL_KEYWORDS):
        return "high"
    if any(k in lower for k in _MEDIUM_SIGNAL_KEYWORDS):
        return "medium"
    return "low"


def _parse_output(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    findings = []
    for item in root.findall(".//item"):
        description_el = item.find("description")
        description = (description_el.text or "").strip() if description_el is not None else ""
        if not description:
            continue
        uri_el = item.find("uri") if item.find("uri") is not None else item.find("namelink")
        findings.append({
            "description": description,
            "uri": (uri_el.text or "").strip() if uri_el is not None and uri_el.text else "",
            "osvdb_id": item.get("osvdbid", ""),
            "severity": _severity_for_description(description),
        })
    return findings


def _scan_one_service(target: str, port: int, is_https: bool) -> dict:
    fd, output_path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    try:
        proc = run_tool(
            _build_command(target, port, is_https, output_path),
            timeout=config.NIKTO_TIMEOUT_PER_SERVICE + 30,
        )
        if proc.returncode not in (0, 1):  # nikto returns 1 when findings exist
            return {"service_port": port, "error": f"nikto exited with status {proc.returncode}", "findings": []}
        with open(output_path, "r", errors="ignore") as fh:
            xml_text = fh.read()
        if not xml_text.strip():
            return {"service_port": port, "error": "nikto produced no output", "findings": []}
        findings = _parse_output(xml_text)
        return {"service_port": port, "error": None, "findings": findings}
    except subprocess.TimeoutExpired:
        return {"service_port": port, "error": f"nikto scan of port {port} timed out", "findings": []}
    except ET.ParseError as exc:
        return {"service_port": port, "error": f"failed to parse nikto XML output: {exc}", "findings": []}
    except Exception as exc:  # noqa: BLE001
        return {"service_port": port, "error": f"nikto scan of port {port} failed: {exc}", "findings": []}
    finally:
        try:
            os.unlink(output_path)
        except OSError:
            pass


def run(target: str, portdiscovery_result: dict, progress_cb=None) -> dict:
    if portdiscovery_result.get("error"):
        return {"skipped": "port discovery failed; no services to scan", "results": []}

    services = _qualifying_services(portdiscovery_result.get("open_ports", []))
    if not services:
        return {"skipped": "no HTTP/HTTPS services discovered", "results": []}

    if not binary_available(config.NIKTO_PATH):
        return {"error": "nikto not installed", "results": []}

    results = []
    for i, svc in enumerate(services, start=1):
        if progress_cb:
            progress_cb(f"nikto {i}/{len(services)} (port {svc['port']})")
        results.append(_scan_one_service(target, svc["port"], svc["is_https"]))

    return {"error": None, "results": results}
