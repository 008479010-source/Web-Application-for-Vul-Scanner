/* Vuln Scan Toolkit — frontend logic. No frameworks, no build step, no
   third-party JS — everything the app needs ships in this one file. */

(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
  const SEVERITY_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info", none: "None" };

  let currentEngagement = null;
  let pollTimer = null;

  // ---------- small utilities ----------

  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function badgeRow(items, cls = "") {
    if (!items || items.length === 0) return `<div class="empty-state">None found</div>`;
    return `<div class="badge-row">${items.map(i => `<span class="badge ${cls}">${escapeHtml(i)}</span>`).join("")}</div>`;
  }

  function kvTable(obj) {
    const entries = Object.entries(obj || {}).filter(([, v]) => v !== null && v !== undefined && v !== "");
    if (entries.length === 0) return `<div class="empty-state">No data</div>`;
    const rows = entries.map(([k, v]) => {
      let display;
      if (Array.isArray(v)) display = v.length ? v.map(escapeHtml).join("<br>") : "&mdash;";
      else if (typeof v === "object") display = escapeHtml(JSON.stringify(v));
      else display = escapeHtml(v);
      return `<tr><th>${escapeHtml(k)}</th><td>${display}</td></tr>`;
    }).join("");
    return `<table class="data-table">${rows}</table>`;
  }

  function sevBadge(sev) {
    return `<span class="sev-badge sev-${escapeHtml(sev)}">${escapeHtml(SEVERITY_LABEL[sev] || sev)}</span>`;
  }

  // ---------- top-level view switching (Scan / Audit Log) ----------

  $$(".top-nav-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      $$(".top-nav-btn").forEach(b => b.classList.remove("active"));
      $$(".view").forEach(v => v.classList.remove("active"));
      btn.classList.add("active");
      $(`#${btn.dataset.view}`).classList.add("active");
      if (btn.dataset.view === "audit-view") loadAuditLog();
    });
  });

  // ---------- scoped tab switching (each .card is its own tab group) ----------

  $$(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const scope = btn.closest(".card") || document;
      $$(".tab-btn", scope).forEach(b => b.classList.remove("active"));
      $$(".tab-panel", scope).forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      const panel = $(`#tab-${btn.dataset.tab}`, scope);
      if (panel) panel.classList.add("active");
      setError("");
      setEngagementError("");
    });
  });

  function setError(msg) { $("#form-error").textContent = msg || ""; }
  function setEngagementError(msg) { $("#engagement-error").textContent = msg || ""; }

  // ---------- tool readiness (nmap / masscan / nikto) ----------

  async function loadToolHealth() {
    const row = $("#tool-health-row");
    if (!row) return;
    try {
      const resp = await fetch("/api/health/tools");
      const status = await resp.json();
      row.innerHTML = Object.entries(status).map(([name, info]) => {
        const cls = info.available ? "ok" : "missing";
        const label = info.available ? (info.version || "available") : "not found";
        return `<span class="tool-pill ${cls}">${escapeHtml(name)}: ${escapeHtml(label)}</span>`;
      }).join("");
    } catch (err) {
      row.innerHTML = `<span class="tool-pill missing">Could not check tool availability</span>`;
    }
  }

  loadToolHealth();

  // ---------- Scope & Authorization (engagements) ----------

  async function loadEngagementList() {
    try {
      const resp = await fetch("/api/engagements");
      const data = await resp.json();
      const select = $("#engagement-select");
      select.innerHTML = "";
      if (!data.engagements || data.engagements.length === 0) {
        select.innerHTML = `<option value="">No saved engagements yet</option>`;
        return;
      }
      data.engagements.forEach(e => {
        const opt = document.createElement("option");
        opt.value = e.id;
        opt.textContent = `${e.client_name} — ${e.engagement_name} (${e.window_status})`;
        select.appendChild(opt);
      });
    } catch (err) {
      // Non-fatal — the "New Engagement" tab still works.
    }
  }

  $("#save-engagement-btn").addEventListener("click", async () => {
    setEngagementError("");
    const fields = {
      client_name: $("#eng-client").value.trim(),
      engagement_name: $("#eng-name").value.trim(),
      scope_description: $("#eng-scope").value.trim(),
      authorized_by: $("#eng-authorized-by").value.trim(),
      authorization_date: $("#eng-auth-date").value,
      testing_window_start: $("#eng-window-start").value,
      testing_window_end: $("#eng-window-end").value,
      rules_of_engagement: $("#eng-roe").value.trim(),
      contact_name: $("#eng-contact-name").value.trim(),
      contact_email: $("#eng-contact-email").value.trim(),
    };

    try {
      const resp = await fetch("/api/engagements", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(fields),
      });
      const data = await resp.json();
      if (!resp.ok) {
        setEngagementError(data.error || "Failed to save engagement.");
        return;
      }
      await activateEngagement(data.engagement_id);
    } catch (err) {
      setEngagementError("Network error saving engagement: " + err.message);
    }
  });

  $("#use-engagement-btn").addEventListener("click", async () => {
    const id = $("#engagement-select").value;
    if (!id) {
      setEngagementError("Select a saved engagement first.");
      return;
    }
    await activateEngagement(id);
  });

  async function activateEngagement(engagementId) {
    try {
      const resp = await fetch(`/api/engagements/${engagementId}`);
      const engagement = await resp.json();
      if (!resp.ok) {
        setEngagementError(engagement.error || "Could not load engagement.");
        return;
      }
      currentEngagement = engagement;
      renderEngagementSummary(engagement);
    } catch (err) {
      setEngagementError("Network error loading engagement: " + err.message);
    }
  }

  function renderEngagementSummary(engagement) {
    $("#engagement-setup").hidden = true;
    const summary = $("#engagement-active-summary");
    summary.hidden = false;

    const statusMessages = {
      active: "Authorized — active scans may run.",
      not_started: `Testing window has not started yet (begins ${engagement.testing_window_start}). Scans are blocked until then.`,
      expired: `Testing window ended ${engagement.testing_window_end}. Create a new engagement to keep testing.`,
    };

    summary.innerHTML = `
      <div class="engagement-summary-box">
        <div>
          <div class="eng-title">${escapeHtml(engagement.client_name)} &mdash; ${escapeHtml(engagement.engagement_name)}</div>
          <div class="eng-meta">Scope: ${escapeHtml(engagement.scope_description)}</div>
          <div class="eng-meta">Window: ${escapeHtml(engagement.testing_window_start)} &rarr; ${escapeHtml(engagement.testing_window_end)} &middot; Authorized by ${escapeHtml(engagement.authorized_by)}</div>
          <div class="eng-meta">${escapeHtml(statusMessages[engagement.window_status] || "")}</div>
        </div>
        <div style="display:flex; flex-direction:column; gap:8px; align-items:flex-end;">
          <span class="window-status-pill window-status-${escapeHtml(engagement.window_status)}">${escapeHtml(engagement.window_status.replace("_", " "))}</span>
          <button class="btn btn-secondary" id="change-engagement-btn">Change</button>
        </div>
      </div>`;

    $("#change-engagement-btn").addEventListener("click", () => {
      currentEngagement = null;
      summary.hidden = true;
      $("#engagement-setup").hidden = false;
      $("#scan-forms-card").hidden = true;
      loadEngagementList();
    });

    $("#scan-forms-card").hidden = engagement.window_status !== "active";
    if (engagement.window_status !== "active") {
      setError("");
    }
  }

  loadEngagementList();

  // ---------- kicking off scans ----------

  function selectedModules(scopeId) {
    return $$(`#${scopeId} input[type="checkbox"]:checked`).map(cb => cb.value);
  }

  $("#start-single-btn").addEventListener("click", async () => {
    setError("");
    if (!currentEngagement) {
      setError("Set up Scope & Authorization before starting a scan.");
      return;
    }
    const target = $("#target-input").value.trim();
    if (!target) {
      setError("Enter a target domain or IP address.");
      return;
    }
    const modules = selectedModules("module-select-single");
    if (modules.length === 0) {
      setError("Select at least one scan module.");
      return;
    }

    const btn = $("#start-single-btn");
    btn.disabled = true;
    try {
      const resp = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, modules, engagement_id: currentEngagement.id }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        setError(data.error || "Failed to start scan.");
        return;
      }
      beginPolling(data.job_id);
    } catch (err) {
      setError("Network error starting scan: " + err.message);
    } finally {
      btn.disabled = false;
    }
  });

  $("#start-bulk-btn").addEventListener("click", async () => {
    setError("");
    if (!currentEngagement) {
      setError("Set up Scope & Authorization before starting a scan.");
      return;
    }
    const fileInput = $("#bulk-file-input");
    if (!fileInput.files || fileInput.files.length === 0) {
      setError("Choose a CSV or text file listing your targets.");
      return;
    }
    const modules = selectedModules("module-select-bulk");
    if (modules.length === 0) {
      setError("Select at least one scan module.");
      return;
    }

    const form = new FormData();
    form.append("file", fileInput.files[0]);
    form.append("engagement_id", currentEngagement.id);
    modules.forEach(m => form.append("modules", m));

    const btn = $("#start-bulk-btn");
    btn.disabled = true;
    try {
      const resp = await fetch("/api/scan/bulk", { method: "POST", body: form });
      const data = await resp.json();
      if (!resp.ok) {
        setError(data.error || "Failed to start bulk scan.");
        return;
      }
      beginPolling(data.job_id);
    } catch (err) {
      setError("Network error starting bulk scan: " + err.message);
    } finally {
      btn.disabled = false;
    }
  });

  // ---------- polling ----------
  // Active scans (NSE vuln scripts, nikto) run minutes per target, not
  // seconds — poll less aggressively than a passive recon tool would.

  function beginPolling(jobId) {
    const progressCard = $("#progress-card");
    progressCard.hidden = false;
    $("#results-card").hidden = true;
    $("#job-id-label").textContent = `job ${jobId}`;
    $("#progress-bar-fill").style.width = "0%";
    $("#progress-details").innerHTML = "";

    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(() => pollOnce(jobId), 2500);
    pollOnce(jobId);
  }

  async function pollOnce(jobId) {
    try {
      const resp = await fetch(`/api/scan/${jobId}`);
      const job = await resp.json();
      if (!resp.ok) {
        clearInterval(pollTimer);
        setError(job.error || "Lost track of the scan job.");
        return;
      }
      renderProgress(job);
      if (job.status === "completed" || job.status === "error") {
        clearInterval(pollTimer);
        renderResults(job);
      }
    } catch (err) {
      clearInterval(pollTimer);
      setError("Network error while polling scan status: " + err.message);
    }
  }

  function renderProgress(job) {
    $("#progress-bar-fill").style.width = `${job.percent}%`;
    const blocks = Object.entries(job.progress).map(([target, moduleStatuses]) => {
      const chips = Object.entries(moduleStatuses).map(([mod, status]) => {
        const cls = status === "done" ? "status-done"
          : status === "error" ? "status-error"
          : status.startsWith("running") ? "status-running"
          : "";
        return `<span class="module-chip ${cls}">${escapeHtml(mod)}: ${escapeHtml(status)}</span>`;
      }).join("");
      return `<div class="target-progress-block">
        <div class="target-name">${escapeHtml(target)}</div>
        <div class="module-chip-row">${chips}</div>
      </div>`;
    }).join("");
    $("#progress-details").innerHTML = blocks;
  }

  // ---------- rendering results ----------

  function renderResults(job) {
    $("#results-card").hidden = false;
    $("#view-report-btn").href = `/api/scan/${job.id}/report`;
    $("#download-report-btn").href = `/api/scan/${job.id}/report?download=1`;
    $("#export-json-btn").href = `/api/scan/${job.id}/export.json`;
    $("#export-csv-btn").href = `/api/scan/${job.id}/export.csv`;

    const resultsBody = $("#results-body");

    if (job.status === "error") {
      resultsBody.innerHTML = `<div class="error-block">Scan failed: ${escapeHtml(job.error || "unknown error")}</div>`;
      return;
    }

    const blocks = Object.entries(job.results).map(([target, modResults], idx) => {
      const sections = [];
      if ("risk" in modResults) sections.push(renderRisk(modResults.risk));
      if ("portdiscovery" in modResults) sections.push(renderPortDiscovery(modResults.portdiscovery));
      if ("nse_vuln" in modResults) sections.push(renderNseVuln(modResults.nse_vuln));
      if ("webvuln_nikto" in modResults) sections.push(renderNikto(modResults.webvuln_nikto));
      if ("cve_match" in modResults) sections.push(renderCveMatch(modResults.cve_match));

      const highest = (modResults.risk && modResults.risk.highest_severity) || "none";

      return `<div class="target-result-block">
        <div class="target-result-header" data-toggle>
          <span>${escapeHtml(target)} &nbsp; ${sevBadge(highest)}</span>
          <span class="note-text">click to expand/collapse</span>
        </div>
        <div class="target-result-body" ${idx === 0 ? "" : "hidden"}>
          ${sections.join("")}
        </div>
      </div>`;
    }).join("");

    resultsBody.innerHTML = blocks;

    $$(".target-result-header", resultsBody).forEach(header => {
      header.addEventListener("click", () => {
        const body = header.nextElementSibling;
        body.hidden = !body.hidden;
      });
    });
  }

  function renderRisk(risk) {
    if (!risk || risk.error) {
      return risk && risk.error ? `<div class="module-section"><h3>Risk Assessment</h3><div class="error-block">${escapeHtml(risk.error)}</div></div>` : "";
    }
    const pills = SEVERITY_ORDER.map(sev => `
      <div class="risk-pill">
        <span class="n">${risk.counts[sev] || 0}</span>
        <span class="l">${SEVERITY_LABEL[sev]}</span>
      </div>`).join("");

    const rows = (risk.findings || []).map(f => `
      <tr>
        <th>${sevBadge(f.severity)}</th>
        <td>
          <div><strong>${escapeHtml(f.title)}</strong></div>
          <div class="note-text" style="font-style:normal;">${escapeHtml(f.description)}</div>
          ${f.cve_ids && f.cve_ids.length ? `<div class="note-text">CVE: ${f.cve_ids.map(escapeHtml).join(", ")}</div>` : ""}
          ${f.evidence ? `<div class="note-text">Evidence: ${escapeHtml(f.evidence)}</div>` : ""}
        </td>
      </tr>`).join("");

    const table = rows ? `<table class="data-table">${rows}</table>` : `<div class="empty-state">No risk findings flagged for this target.</div>`;

    return `<div class="module-section">
      <h3>Risk Assessment</h3>
      <div class="risk-summary-row">${pills}</div>
      ${table}
    </div>`;
  }

  function renderPortDiscovery(data) {
    if (!data) return "";
    if (data.error) {
      return `<div class="module-section"><h3>Port &amp; Service Discovery</h3><div class="error-block">${escapeHtml(data.error)}</div></div>`;
    }
    const rows = (data.open_ports || []).map(p => `
      <tr>
        <th>${p.port}/${escapeHtml(p.protocol)}</th>
        <td>${escapeHtml(p.service || "")}${p.banner ? " &mdash; " + escapeHtml(p.banner) : ""}</td>
      </tr>`).join("");
    const table = rows ? `<table class="data-table">${rows}</table>` : `<div class="empty-state">No open ports found.</div>`;
    const method = data.discovery_method ? ` (${escapeHtml(data.discovery_method)})` : "";
    return `<div class="module-section">
      <h3>Port &amp; Service Discovery &mdash; ${data.open_count || 0} open${method}</h3>
      ${data.masscan_error ? `<div class="note-text">masscan note: ${escapeHtml(data.masscan_error)}</div>` : ""}
      ${table}
    </div>`;
  }

  function renderNseVuln(data) {
    if (!data) return "";
    if (data.skipped) return `<div class="module-section"><h3>Active Vulnerability Scan (nmap NSE)</h3><div class="note-text">${escapeHtml(data.skipped)}</div></div>`;
    if (data.error) return `<div class="module-section"><h3>Active Vulnerability Scan (nmap NSE)</h3><div class="error-block">${escapeHtml(data.error)}</div></div>`;
    const findings = data.findings || [];
    const rows = findings.map(f => `
      <tr>
        <th>${sevBadge(f.severity)}</th>
        <td>
          <div><strong>${escapeHtml(f.script_id)}</strong>${f.port ? ` (port ${f.port})` : ""}</div>
          <div class="note-text" style="font-style:normal; white-space:pre-wrap;">${escapeHtml(f.output.slice(0, 400))}</div>
          ${f.cve_ids && f.cve_ids.length ? `<div class="note-text">CVE: ${f.cve_ids.map(escapeHtml).join(", ")}</div>` : ""}
        </td>
      </tr>`).join("");
    const table = rows ? `<table class="data-table">${rows}</table>` : `<div class="empty-state">No NSE vuln script findings.</div>`;
    return `<div class="module-section"><h3>Active Vulnerability Scan (nmap NSE --script vuln)</h3>${table}</div>`;
  }

  function renderNikto(data) {
    if (!data) return "";
    if (data.skipped) return `<div class="module-section"><h3>Web Vulnerability Scan (nikto)</h3><div class="note-text">${escapeHtml(data.skipped)}</div></div>`;
    if (data.error) return `<div class="module-section"><h3>Web Vulnerability Scan (nikto)</h3><div class="error-block">${escapeHtml(data.error)}</div></div>`;

    const sections = (data.results || []).map(svc => {
      if (svc.error) {
        return `<div class="note-text">Port ${svc.service_port}: ${escapeHtml(svc.error)}</div>`;
      }
      const rows = (svc.findings || []).map(item => `
        <tr>
          <th>${sevBadge(item.severity)}</th>
          <td>${escapeHtml(item.description)}${item.uri ? ` &mdash; <span class="note-text">${escapeHtml(item.uri)}</span>` : ""}</td>
        </tr>`).join("");
      const table = rows ? `<table class="data-table">${rows}</table>` : `<div class="empty-state">No findings for port ${svc.service_port}.</div>`;
      return `<h4 style="font-size:12.5px; color:var(--text-dim); margin:12px 0 4px;">Port ${svc.service_port}</h4>${table}`;
    }).join("");

    return `<div class="module-section"><h3>Web Vulnerability Scan (nikto)</h3>${sections || '<div class="empty-state">No web services scanned.</div>'}</div>`;
  }

  function renderCveMatch(data) {
    if (!data) return "";
    if (data.skipped) return `<div class="module-section"><h3>CVE Matching (NVD)</h3><div class="note-text">${escapeHtml(data.skipped)}</div></div>`;

    const rateLimitNote = data.rate_limited
      ? `<div class="note-text">NVD rate limit reached during this scan — some lookups were skipped.</div>` : "";

    const sections = (data.cve_matches || []).map(match => {
      if (match.error) {
        return `<div class="note-text">${escapeHtml(match.product)} ${escapeHtml(match.version)}: ${escapeHtml(match.error)}</div>`;
      }
      const rows = (match.cves || []).map(cve => `
        <tr>
          <th>${sevBadge(cve.severity)}</th>
          <td>
            <div><strong>${escapeHtml(cve.id)}</strong>${cve.score !== null && cve.score !== undefined ? ` (CVSS ${cve.score})` : ""}</div>
            <div class="note-text" style="font-style:normal;">${escapeHtml((cve.description || "").slice(0, 300))}</div>
          </td>
        </tr>`).join("");
      const table = rows ? `<table class="data-table">${rows}</table>` : `<div class="empty-state">No CVEs matched.</div>`;
      return `<h4 style="font-size:12.5px; color:var(--text-dim); margin:12px 0 4px;">${escapeHtml(match.product)} ${escapeHtml(match.version)} (${escapeHtml(match.source || "")})</h4>${table}`;
    }).join("");

    return `<div class="module-section">
      <h3>CVE Matching (NVD keyword search)</h3>
      <div class="note-text">Candidate matches from free-text keyword search — require human verification, not confirmed vulnerabilities.</div>
      ${rateLimitNote}
      ${sections || '<div class="empty-state">No product/version pairs available to match.</div>'}
    </div>`;
  }

  // ---------- audit log ----------

  async function loadAuditLog() {
    const body = $("#audit-log-body");
    body.innerHTML = `<div class="empty-state">Loading…</div>`;
    try {
      const resp = await fetch("/api/audit");
      const data = await resp.json();
      if (!data.events || data.events.length === 0) {
        body.innerHTML = `<div class="empty-state">No audit events yet.</div>`;
        return;
      }
      const rows = data.events.map(e => `
        <tr>
          <td>${escapeHtml(e.ts)}</td>
          <td>${escapeHtml(e.event_type)}</td>
          <td>${escapeHtml(e.engagement_id || "—")}</td>
          <td>${escapeHtml(e.job_id || "—")}</td>
          <td>${escapeHtml(e.detail || "")}</td>
        </tr>`).join("");
      body.innerHTML = `<table class="audit-table">
        <tr><th>Timestamp (UTC)</th><th>Event</th><th>Engagement</th><th>Job</th><th>Detail</th></tr>
        ${rows}
      </table>`;
    } catch (err) {
      body.innerHTML = `<div class="error-block">Failed to load audit log: ${escapeHtml(err.message)}</div>`;
    }
  }

  $("#refresh-audit-btn").addEventListener("click", loadAuditLog);
})();
