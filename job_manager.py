"""
In-memory job orchestration for vulnerability scans.

Same shape as a passive recon tool's job manager would be, with one real
difference: three of the four modules (nse_vuln, cve_match, webvuln_nikto)
technically depend on portdiscovery's output (open ports + detected
service/product/version), so this module wires that hand-off explicitly
and guarantees portdiscovery always runs first when any dependent module
is selected - even if the caller forgot to ask for it.

Scans run in background threads so the HTTP request that kicks one off
returns immediately with a job_id; the frontend polls GET /api/scan/<id>
for live progress and results. Active scans here (NSE vuln scripts, nikto)
can run for many minutes per target, unlike a passive recon scan.

State lives in a process-wide dict guarded by a lock - fine for a single
Flask process. Scale beyond that would need a shared store (Redis, etc).
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timezone

import config
import db
from modules import cve_match, nse_vuln, portdiscovery, risk, webvuln_nikto

VALID_MODULES = {"portdiscovery", "nse_vuln", "cve_match", "webvuln_nikto"}
MODULE_ORDER = ["portdiscovery", "nse_vuln", "cve_match", "webvuln_nikto"]
_DEPENDENT_MODULES = {"nse_vuln", "cve_match", "webvuln_nikto"}

MODULE_RUNNERS = {
    "portdiscovery": portdiscovery.run,
    "nse_vuln": nse_vuln.run,
    "cve_match": cve_match.run,
    "webvuln_nikto": webvuln_nikto.run,
}

# Risk assessment always runs after a target's selected modules finish - not
# user-selectable, since it only reasons over what the other modules found.
_RISK_STEP = "risk"

_jobs: dict[str, dict] = {}
_lock = threading.Lock()
_active_job_count = 0
_active_lock = threading.Lock()


def normalize_modules(selected: list[str]) -> list[str]:
    """Filters to valid modules and auto-adds portdiscovery whenever a
    dependent module is selected without it - a hard technical
    prerequisite, not just a UI default."""
    chosen = {m for m in selected if m in VALID_MODULES}
    if chosen & _DEPENDENT_MODULES:
        chosen.add("portdiscovery")
    return [m for m in MODULE_ORDER if m in chosen]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_job(targets: list[str], modules: list[str], engagement_id: str) -> str:
    modules = normalize_modules(modules)
    job_id = uuid.uuid4().hex[:12]
    with _lock:
        _jobs[job_id] = {
            "id": job_id,
            "engagement_id": engagement_id,
            "targets": targets,
            "modules": modules,
            "status": "queued",
            "created_at": _now(),
            "finished_at": None,
            "results": {t: {} for t in targets},
            "progress": {
                t: {**{m: "pending" for m in modules}, _RISK_STEP: "pending"} for t in targets
            },
            "error": None,
        }
    db.record_audit_event(
        "scan_started", engagement_id=engagement_id, job_id=job_id,
        detail={"targets": targets, "modules": modules},
    )
    threading.Thread(target=_run_job, args=(job_id,), daemon=True).start()
    return job_id


def get_job(job_id: str) -> dict | None:
    with _lock:
        job = _jobs.get(job_id)
        return dict(job) if job else None


def _set_module_status(job_id: str, target: str, module: str, status: str) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if job:
            job["progress"][target][module] = status


def _set_module_result(job_id: str, target: str, module: str, result) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if job:
            job["results"][target][module] = result


def _run_module(job_id: str, target: str, module: str) -> None:
    _set_module_status(job_id, target, module, "running")
    try:
        def progress_cb(text):
            _set_module_status(job_id, target, module, f"running ({text})")

        if module in _DEPENDENT_MODULES:
            with _lock:
                pd_result = dict(_jobs[job_id]["results"][target].get("portdiscovery", {}))
            result = MODULE_RUNNERS[module](target, pd_result, progress_cb=progress_cb)
        else:
            result = MODULE_RUNNERS[module](target, progress_cb=progress_cb)
        _set_module_result(job_id, target, module, result)
        _set_module_status(job_id, target, module, "done")
    except Exception as exc:  # noqa: BLE001 - a single module failing shouldn't kill the job
        _set_module_result(job_id, target, module, {"error": str(exc)})
        _set_module_status(job_id, target, module, "error")


def _run_job(job_id: str) -> None:
    global _active_job_count

    # Politely cap how many jobs run concurrently across the whole app.
    while True:
        with _active_lock:
            if _active_job_count < config.MAX_CONCURRENT_JOBS:
                _active_job_count += 1
                break
        time.sleep(0.25)

    with _lock:
        job = _jobs[job_id]
        job["status"] = "running"
        targets = list(job["targets"])
        modules = list(job["modules"])

    engagement_id = job.get("engagement_id")
    try:
        for target in targets:
            for module in modules:
                _run_module(job_id, target, module)
            _run_risk_assessment(job_id, target)
        with _lock:
            _jobs[job_id]["status"] = "completed"
            _jobs[job_id]["finished_at"] = _now()
        db.record_audit_event("scan_completed", engagement_id=engagement_id, job_id=job_id,
                               detail={"targets": targets})
    except Exception as exc:  # noqa: BLE001
        with _lock:
            _jobs[job_id]["status"] = "error"
            _jobs[job_id]["error"] = str(exc)
            _jobs[job_id]["finished_at"] = _now()
        db.record_audit_event("scan_failed", engagement_id=engagement_id, job_id=job_id, detail=str(exc))
    finally:
        with _active_lock:
            _active_job_count -= 1


def _run_risk_assessment(job_id: str, target: str) -> None:
    _set_module_status(job_id, target, _RISK_STEP, "running")
    try:
        with _lock:
            target_results = dict(_jobs[job_id]["results"][target])
        assessment = risk.assess(target, target_results)
        _set_module_result(job_id, target, _RISK_STEP, assessment)
        _set_module_status(job_id, target, _RISK_STEP, "done")
    except Exception as exc:  # noqa: BLE001
        _set_module_result(job_id, target, _RISK_STEP, {"error": str(exc)})
        _set_module_status(job_id, target, _RISK_STEP, "error")


def compute_percent(job: dict) -> int:
    total = 0
    done = 0
    for target_progress in job["progress"].values():
        for status in target_progress.values():
            total += 1
            if status == "done" or status == "error":
                done += 1
    return int((done / total) * 100) if total else 0


def _cleanup_loop() -> None:
    while True:
        time.sleep(60)
        cutoff = time.time() - config.JOB_RETENTION_SECONDS
        with _lock:
            stale = [
                jid for jid, job in _jobs.items()
                if job["status"] in ("completed", "error")
                and job.get("finished_at")
                and datetime.fromisoformat(job["finished_at"]).timestamp() < cutoff
            ]
            for jid in stale:
                del _jobs[jid]


def start_cleanup_thread() -> None:
    threading.Thread(target=_cleanup_loop, daemon=True).start()
