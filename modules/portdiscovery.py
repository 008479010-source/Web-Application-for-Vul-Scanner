"""Two-stage port/service discovery: masscan for a fast wide sweep, then
nmap -sV for deep per-port service/version probing on whatever masscan
found open. This module's output (product+version per open port) is what
feeds nse_vuln, cve_match, and webvuln_nikto.

masscan needs raw-socket privilege (root, or cap_net_raw via setcap) and
won't be available/usable in every environment, so a full nmap-only
fallback path is mandatory, not optional - without it this module (and
everything downstream of it) would simply stop working wherever masscan
can't run.
"""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET

import config
from modules._proc import binary_available, run_tool


def _build_masscan_command(target: str) -> list[str]:
    return [
        config.MASSCAN_PATH,
        "-p", config.MASSCAN_PORT_RANGE,
        "--rate", str(config.MASSCAN_RATE_PPS),
        "--wait", str(config.MASSCAN_WAIT_SECONDS),
        "-oL", "-",
        target,
    ]


def _parse_masscan_output(stdout: str) -> list[int]:
    """Returns a list of open TCP ports. masscan's list format is
    'open tcp <port> <ip> <timestamp>' with '#'-prefixed comment lines."""
    ports = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 4 or parts[0] != "open" or parts[1] != "tcp":
            continue
        try:
            ports.append(int(parts[2]))
        except ValueError:
            continue
    return ports


def _build_nmap_command(target: str, ports: list[int]) -> list[str]:
    port_csv = ",".join(str(int(p)) for p in ports)
    return [
        config.NMAP_PATH,
        "-sV", "-Pn",
        "--version-intensity", str(config.NMAP_VERSION_INTENSITY),
        "-p", port_csv,
        "-oX", "-",
        target,
    ]


def _parse_nmap_xml(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    host = root.find("host")
    if host is None:
        return {"resolved_ip": None, "open_ports": []}

    resolved_ip = None
    for addr in host.findall("address"):
        if addr.get("addrtype") in ("ipv4", "ipv6"):
            resolved_ip = addr.get("addr")
            break

    open_ports = []
    ports_el = host.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            service = service_el.get("name", "") if service_el is not None else ""
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            extrainfo = service_el.get("extrainfo", "") if service_el is not None else ""
            banner = " ".join(p for p in (product, version, extrainfo) if p).strip() or service

            open_ports.append({
                "port": int(port_el.get("portid")),
                "protocol": port_el.get("protocol", "tcp"),
                "state": "open",
                "service": service,
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
                "banner": banner,
            })

    return {"resolved_ip": resolved_ip, "open_ports": open_ports}


def run(target: str, progress_cb=None) -> dict:
    if not binary_available(config.NMAP_PATH):
        return {
            "resolved_ip": None,
            "discovery_method": None,
            "masscan_error": None,
            "open_ports": [],
            "open_count": 0,
            "error": "nmap is required for service detection and was not found on PATH",
        }

    masscan_error = None
    discovery_method = "masscan+nmap"
    candidate_ports = None

    if binary_available(config.MASSCAN_PATH):
        if progress_cb:
            progress_cb("masscan discovery")
        try:
            proc = run_tool(_build_masscan_command(target), timeout=config.MASSCAN_TIMEOUT)
            if proc.returncode == 0:
                candidate_ports = _parse_masscan_output(proc.stdout)
            else:
                masscan_error = f"masscan exited with status {proc.returncode}: {proc.stderr.strip()[:300]}"
        except Exception as exc:  # noqa: BLE001 - any masscan failure just triggers fallback
            masscan_error = f"masscan failed: {exc}"
    else:
        masscan_error = "masscan not found on PATH"

    if candidate_ports is None:
        # masscan missing/failed/timed out - fall back to nmap alone over a
        # curated port list. A masscan run that succeeded with zero open
        # ports is NOT a failure and does not fall into this branch.
        discovery_method = "nmap-fallback"
        candidate_ports = list(config.TOP_PORTS)
    elif not candidate_ports:
        # masscan ran fine and legitimately found nothing open.
        return {
            "resolved_ip": None,
            "discovery_method": discovery_method,
            "masscan_error": masscan_error,
            "open_ports": [],
            "open_count": 0,
            "error": None,
        }

    if progress_cb:
        progress_cb("nmap service detection")
    try:
        proc = run_tool(_build_nmap_command(target, candidate_ports), timeout=config.NMAP_SERVICE_SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {
            "resolved_ip": None,
            "discovery_method": discovery_method,
            "masscan_error": masscan_error,
            "open_ports": [],
            "open_count": 0,
            "error": f"nmap service scan timed out after {config.NMAP_SERVICE_SCAN_TIMEOUT}s",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "resolved_ip": None,
            "discovery_method": discovery_method,
            "masscan_error": masscan_error,
            "open_ports": [],
            "open_count": 0,
            "error": f"nmap service scan failed: {exc}",
        }

    if proc.returncode != 0:
        return {
            "resolved_ip": None,
            "discovery_method": discovery_method,
            "masscan_error": masscan_error,
            "open_ports": [],
            "open_count": 0,
            "error": f"nmap exited with status {proc.returncode}: {proc.stderr.strip()[:300]}",
        }

    try:
        parsed = _parse_nmap_xml(proc.stdout)
    except ET.ParseError as exc:
        return {
            "resolved_ip": None,
            "discovery_method": discovery_method,
            "masscan_error": masscan_error,
            "open_ports": [],
            "open_count": 0,
            "error": f"failed to parse nmap XML output: {exc}",
        }

    return {
        "resolved_ip": parsed["resolved_ip"],
        "discovery_method": discovery_method,
        "masscan_error": masscan_error,
        "open_ports": parsed["open_ports"],
        "open_count": len(parsed["open_ports"]),
        "error": None,
    }
