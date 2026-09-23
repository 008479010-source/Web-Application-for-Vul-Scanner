"""
Vuln Scan Toolkit — a standalone web app for the vulnerability-scanning
phase of authorized penetration tests / security assessments.

Unlike a passive recon tool, this app runs genuinely ACTIVE, intrusive
scans (nmap NSE vuln scripts, nikto) via external binaries (nmap, masscan,
nikto). Only ever point it at systems you own or are explicitly authorized
to actively vulnerability-scan — see README.md.

Run with:  python app.py
Then open: http://127.0.0.1:5001
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import shutil
import subprocess
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request, send_file

import config
import db
import job_manager
import report_builder

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*$"
)

_HEADER_KEYWORDS = {"target", "domain", "host", "hostname", "ip", "ip_address", "address"}

_REQUIRED_ENGAGEMENT_FIELDS = [
    "client_name", "engagement_name", "scope_description", "authorized_by",
    "authorization_date", "testing_window_start", "testing_window_end",
]

_TOOL_BINARIES = {
    "nmap": (config.NMAP_PATH, "--version"),
    "masscan": (config.MASSCAN_PATH, "--version"),
    "nikto": (config.NIKTO_PATH, "-Version"),
}


def _extract_candidates_from_upload(text: str) -> list[str]:
    """Accepts either a plain newline-separated list of targets, or a CSV
    with an optional header row naming the target column."""
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return []

    if "," not in lines[0]:
        return lines

    reader = csv.reader(io.StringIO(text))
    rows = [row for row in reader if row]
    if not rows:
        return []

    first_row_lower = [cell.strip().lower() for cell in rows[0]]
    col_idx = 0
    has_header = False
    for i, cell in enumerate(first_row_lower):
        if cell in _HEADER_KEYWORDS:
            col_idx = i
            has_header = True
            break

    data_rows = rows[1:] if has_header else rows
    return [row[col_idx] for row in data_rows if len(row) > col_idx]


def normalize_target(raw: str) -> str | None:
    """Strip scheme/path/port cruft from user input and validate it's a
    plausible hostname or IP address. Returns None if invalid."""
    if not raw:
        return None
    value = raw.strip()
    value = re.sub(r"^[a-zA-Z]+://", "", value)
    value = value.split("/")[0]
    value = value.split(":")[0] if value.count(":") == 1 else value

    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    if _HOSTNAME_RE.match(value):
        return value.lower()
    return None


def _validate_engagement_payload(payload: dict) -> str | None:
    for field in _REQUIRED_ENGAGEMENT_FIELDS:
        if not str(payload.get(field, "")).strip():
            return f"Missing required field: {field.replace('_', ' ')}."

    try:
        start = datetime.fromisoformat(payload["testing_window_start"])
        end = datetime.fromisoformat(payload["testing_window_end"])
    except ValueError:
        return "Testing window start/end must be valid dates (YYYY-MM-DD)."

    if end < start:
        return "Testing window end date must be on or after the start date."

    return None


def _get_active_engagement_or_error(engagement_id: str):
    if not engagement_id:
        return None, (jsonify({"error": "A Scope & Authorization record is required before scanning."}), 400)

    engagement = db.get_engagement(engagement_id)
    if not engagement:
        return None, (jsonify({"error": "Unknown engagement id."}), 404)

    status = db.engagement_window_status(engagement)
    if status == "not_started":
        return None, (jsonify({
            "error": f"This engagement's authorized testing window hasn't started yet "
                     f"(begins {engagement['testing_window_start']})."
        }), 400)
    if status == "expired":
        return None, (jsonify({
            "error": f"This engagement's authorized testing window has expired "
                     f"(ended {engagement['testing_window_end']}). Create a new engagement to continue testing."
        }), 400)

    return engagement, None


@app.route("/")
def index():
    return render_template("index.html")


# ---------- Scope & Authorization (engagements) ----------

@app.route("/api/engagements", methods=["POST"])
def create_engagement():
    payload = request.get_json(silent=True) or {}
    error = _validate_engagement_payload(payload)
    if error:
        return jsonify({"error": error}), 400

    engagement_id = db.create_engagement(payload)
    return jsonify({"engagement_id": engagement_id})


@app.route("/api/engagements", methods=["GET"])
def list_engagements():
    engagements = db.list_engagements()
    for e in engagements:
        e["window_status"] = db.engagement_window_status(e)
    return jsonify({"engagements": engagements})


@app.route("/api/engagements/<engagement_id>", methods=["GET"])
def get_engagement(engagement_id):
    engagement = db.get_engagement(engagement_id)
    if not engagement:
        return jsonify({"error": "Unknown engagement id."}), 404
    engagement["window_status"] = db.engagement_window_status(engagement)
    return jsonify(engagement)


# ---------- Tool health ----------

@app.route("/api/health/tools", methods=["GET"])
def health_tools():
    """Lets the UI show a readiness banner before a long scan is submitted,
    instead of only discovering a missing tool after a job fails."""
    status = {}
    for name, (path, version_flag) in _TOOL_BINARIES.items():
        found = shutil.which(path) is not None
        version = None
        if found:
            try:
                proc = subprocess.run([path, version_flag], capture_output=True, text=True, timeout=3)
                version = _extract_version_line(name, proc.stdout, proc.stderr)
            except Exception:  # noqa: BLE001
                version = None
        status[name] = {"available": found, "version": version}
    return jsonify(status)


def _extract_version_line(name: str, stdout: str, stderr: str) -> str | None:
    text = stdout or stderr or ""
    if name == "nikto":
        for line in text.splitlines():
            if line.strip().startswith("Nikto main"):
                return line.strip()
        return "installed" if text else None
    first_line = text.strip().splitlines()[0] if text.strip() else None
    return first_line


# ---------- Scans ----------

@app.route("/api/scan", methods=["POST"])
def start_scan():
    payload = request.get_json(silent=True) or {}

    engagement, err = _get_active_engagement_or_error(payload.get("engagement_id"))
    if err:
        return err

    target = normalize_target(payload.get("target", ""))
    if not target:
        return jsonify({"error": "Invalid target. Provide a domain name or IP address."}), 400

    modules = job_manager.normalize_modules(payload.get("modules", []))
    if not modules:
        return jsonify({"error": "Select at least one scan module."}), 400

    job_id = job_manager.create_job([target], modules, engagement["id"])
    return jsonify({"job_id": job_id})


@app.route("/api/scan/bulk", methods=["POST"])
def start_bulk_scan():
    engagement, err = _get_active_engagement_or_error(request.form.get("engagement_id"))
    if err:
        return err

    modules = job_manager.normalize_modules(request.form.getlist("modules"))
    if not modules:
        return jsonify({"error": "Select at least one scan module."}), 400

    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file uploaded. Provide a CSV or plain-text list of targets."}), 400

    candidates = _extract_candidates_from_upload(file.read().decode("utf-8", errors="ignore"))

    targets = []
    seen = set()
    for raw in candidates:
        target = normalize_target(raw)
        if target and target not in seen:
            targets.append(target)
            seen.add(target)

    if not targets:
        return jsonify({"error": "No valid targets found in the uploaded file."}), 400
    if len(targets) > config.MAX_BULK_TARGETS:
        return jsonify({
            "error": f"Too many targets ({len(targets)}). Bulk mode is capped at "
                     f"{config.MAX_BULK_TARGETS} per job — active vulnerability scans (NSE scripts, "
                     f"nikto) can take many minutes per target, so a large batch would run for hours "
                     f"unattended against someone else's infrastructure."
        }), 400

    job_id = job_manager.create_job(targets, modules, engagement["id"])
    return jsonify({"job_id": job_id, "targets": targets})


@app.route("/api/scan/<job_id>", methods=["GET"])
def scan_status(job_id):
    job = job_manager.get_job(job_id)
    if not job:
        return jsonify({"error": "Unknown job id."}), 404
    job["percent"] = job_manager.compute_percent(job)
    job["engagement"] = db.get_engagement(job.get("engagement_id"))
    return jsonify(job)


@app.route("/api/scan/<job_id>/export.json", methods=["GET"])
def export_json(job_id):
    job = job_manager.get_job(job_id)
    if not job:
        return jsonify({"error": "Unknown job id."}), 404
    job["engagement"] = db.get_engagement(job.get("engagement_id"))
    db.record_audit_event("report_exported", engagement_id=job.get("engagement_id"), job_id=job_id, detail="json")
    buf = io.BytesIO(json.dumps(job, indent=2, default=str).encode("utf-8"))
    return send_file(
        buf, mimetype="application/json", as_attachment=True,
        download_name=f"vulnscan-raw-{job_id}.json",
    )


@app.route("/api/scan/<job_id>/export.csv", methods=["GET"])
def export_csv(job_id):
    job = job_manager.get_job(job_id)
    if not job:
        return jsonify({"error": "Unknown job id."}), 404

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "target", "highest_risk_severity", "open_ports", "product_versions",
        "critical_findings", "high_findings", "medium_findings", "low_findings",
        "nse_vulnerable_count", "nikto_finding_count", "cve_candidate_count",
    ])

    for target, results in job["results"].items():
        pd = results.get("portdiscovery", {})
        open_ports = ";".join(str(p["port"]) for p in pd.get("open_ports", []))
        product_versions = ";".join(
            f"{p['product']} {p['version']}".strip() for p in pd.get("open_ports", []) if p.get("product")
        )

        risk_res = results.get("risk", {})
        counts = risk_res.get("counts", {})

        nse_res = results.get("nse_vuln", {})
        nse_vulnerable = sum(1 for f in nse_res.get("findings", []) if f.get("verdict") == "vulnerable")

        nikto_res = results.get("webvuln_nikto", {})
        nikto_findings = sum(len(sr.get("findings", [])) for sr in nikto_res.get("results", []))

        cve_res = results.get("cve_match", {})
        cve_count = sum(len(m.get("cves", [])) for m in cve_res.get("cve_matches", []))

        writer.writerow([
            target, risk_res.get("highest_severity", ""), open_ports, product_versions,
            counts.get("critical", 0), counts.get("high", 0), counts.get("medium", 0), counts.get("low", 0),
            nse_vulnerable, nikto_findings, cve_count,
        ])

    db.record_audit_event("report_exported", engagement_id=job.get("engagement_id"), job_id=job_id, detail="csv")
    buf = io.BytesIO(output.getvalue().encode("utf-8"))
    return send_file(
        buf, mimetype="text/csv", as_attachment=True,
        download_name=f"vulnscan-summary-{job_id}.csv",
    )


@app.route("/api/scan/<job_id>/report", methods=["GET"])
def scan_report(job_id):
    job = job_manager.get_job(job_id)
    if not job:
        return jsonify({"error": "Unknown job id."}), 404
    engagement = db.get_engagement(job.get("engagement_id"))
    html = report_builder.render_report(job, engagement)

    download = request.args.get("download") == "1"
    db.record_audit_event(
        "report_exported", engagement_id=job.get("engagement_id"), job_id=job_id,
        detail="html-download" if download else "html-view",
    )
    if download:
        buf = io.BytesIO(html.encode("utf-8"))
        return send_file(
            buf, mimetype="text/html", as_attachment=True,
            download_name=f"vulnscan-report-{job_id}.html",
        )
    return html


# ---------- Audit log ----------

@app.route("/api/audit", methods=["GET"])
def audit_log():
    limit = min(int(request.args.get("limit", 100)), 500)
    return jsonify({"events": db.list_audit_events(limit)})


if __name__ == "__main__":
    job_manager.start_cleanup_thread()
    app.run(debug=True, host="127.0.0.1", port=5001)
