# Vuln Scan Toolkit

A self-contained web app for the **vulnerability-scanning phase** of
authorized penetration tests and security assessments. It's a companion
tool to a separate reconnaissance app — this one picks up where passive
recon leaves off: it actively probes discovered services for known
vulnerabilities using **nmap**, **masscan**, and **nikto**, plus live
**NVD** CVE lookups, and produces a structured engagement report and an
append-only audit trail, gated by the same kind of Scope & Authorization
workflow as the recon tool.

## ⚠️ Usage policy — read this before running a scan

**This tool runs ACTIVE, INTRUSIVE scans — not passive reconnaissance.**
The NSE vuln-script and nikto modules send real probes specifically
designed to trigger and detect vulnerabilities. This means:

- Scans are **noisy and detectable** — they will very likely appear in the
  target's own logs, IDS/IPS, and SOC alerting.
- In rare cases, aggressive probes against fragile or poorly-written
  services can cause instability.
- Your written authorization must **specifically cover active
  vulnerability scanning** — authorization that only covers passive
  reconnaissance is not sufficient for this tool.

**Only scan systems you own or have explicit written authorization to
actively vulnerability-test.** Unauthorized scanning can violate:

- The U.S. **Computer Fraud and Abuse Act (CFAA)** and equivalent
  computer-misuse laws in other countries
- Data-protection regulations such as **GDPR**, **HIPAA**, **PCI DSS**, and
  **CCPA** when personal or cardholder data is in scope
- The acceptable-use policy of virtually every hosting provider and ISP

This tool enforces a **Scope & Authorization workflow** identical in spirit
to the recon tool's: every scan must be linked to an engagement record
(client, in-scope assets, who authorized it, and a testing window), and
the app blocks scans outside that window. This is a documentation aid and
a reminder, not a legal safeguard — it doesn't verify that the
authorization you enter is real or that your scope description accurately
covers active scanning. The responsibility for lawful, in-scope,
appropriately-authorized use is entirely yours. Follow the
ethical/professional-conduct expectations of bodies like **CREST** and
**(ISC)²** and any corporate policy or client agreement that applies.

## What it Does

| Module | What it does |
|---|---|
| **Scope & Authorization** | Pre-engagement record required before any scan can start; enforces the testing window |
| **Port &amp; service discovery** | masscan for a fast wide sweep, handed off to nmap `-sV` for deep per-port service/version detection |
| **Active vulnerability scan** | nmap's NSE `vuln` script category run against discovered open ports — genuine active probing, not just version matching |
| **CVE matching** | Detected product/version pairs matched against live NVD CVE data via free-text keyword search, with a local cache and rate-limit-aware throttling |
| **Web vulnerability scan** | nikto run against every discovered HTTP/HTTPS service for misconfigurations and known web vulnerabilities |
| **Risk assessment** | Unifies CVSS scores, NSE verdicts, nikto findings, and open-port heuristics into one Critical/High/Medium/Low/Info scale |
| **Reporting** | PTES-structured report (Executive Summary, Scope & Authorization, Methodology, Findings, Recommendations, Appendix) plus raw JSON/CSV exports |
| **Audit log** | Append-only local record of every engagement and scan lifecycle event |

Every module degrades gracefully — a missing binary, a timeout, or a
network error never crashes the whole scan; it's reported as an error for
that module/target and the rest continues. Supports a **single-target**
scan and a small **bulk mode** (CSV or plain text upload, capped at 5
targets per job — active scans take much longer per target than passive
recon, so bulk mode is deliberately conservative).

## How it Works

Scans run as background threads so the UI stays responsive; the frontend
polls `GET /api/scan/<job_id>` every ~2.5s for live progress. Three of the
four modules (`nse_vuln`, `cve_match`, `webvuln_nikto`) depend on
`portdiscovery`'s output (open ports + detected product/version) —
`job_manager.py` automatically adds `portdiscovery` to the module list
whenever a dependent module is selected, even if you forgot to ask for it.
Risk assessment always runs last, automatically. `GET /api/health/tools`
lets the UI show whether nmap/masscan/nikto are actually installed
*before* you submit a scan that will otherwise fail partway through.

### Project layout

```
app.py             Flask routes: engagements, scans, status polling, reports, audit log, tool health
job_manager.py      In-memory background job orchestration (threaded, concurrency cap,
                    module-dependency wiring, automatic risk assessment, job cleanup)
db.py              SQLite persistence for engagements, the audit log, and the NVD CVE cache
report_builder.py  Builds the PTES-structured report from a job + engagement record
modules/
  _proc.py         Shared safe-subprocess helper (single choke point for nmap/masscan/nikto calls)
  portdiscovery.py masscan -> nmap -sV two-stage port/service discovery
  nse_vuln.py      nmap NSE `--script vuln` active vulnerability scanning
  webvuln_nikto.py nikto web vulnerability/misconfiguration scanning
  cve_match.py     Live NVD keywordSearch CVE matching with local caching + rate-limit throttle
  risk.py          Cross-source severity aggregation (CVSS + NSE + nikto + open-port heuristics)
templates/
  index.html       Single-page dashboard (Scan view + Audit Log view)
  report.html      Standalone, printable engagement report
static/
  css/style.css    Dark UI (red/orange accent — visually distinct from a passive recon tool)
  js/app.js        Fetch-based polling + result rendering, no frameworks
tests/             unittest suite — parser/command-construction/glue tests run without the real
                   binaries installed; true end-to-end tests are gated behind an env var
config.py          All tunables in one place (tool paths, timeouts, thread counts, NVD throttle)
```

## Prerequisites

- Python 3.9+
- **nmap**, **masscan**, and **nikto** installed and on `PATH` (or point
  `NMAP_PATH`/`MASSCAN_PATH`/`NIKTO_PATH` at their locations). On
  Debian/Ubuntu: `sudo apt-get install nmap masscan nikto`.
- masscan needs raw-socket privilege. Rather than running the whole app as
  root, grant the capability once:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin+eip $(which masscan)
  ```
  nmap's `-sV -Pn` scans used here do **not** need root — nmap
  automatically falls back from a SYN scan to a TCP-connect scan when
  unprivileged. If masscan still can't run in your environment, the app
  automatically falls back to an nmap-only port sweep over a curated port
  list.
- Optionally, an [NVD API key](https://nvd.nist.gov/developers/request-an-api-key)
  set as `NVD_API_KEY` — raises the CVE-lookup rate limit from 5 to 50
  requests per 30 seconds.

## How to Install

```bash
git clone <this-repo-url>
cd Web-Application-for-Vuln-Phase
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5001**. The SQLite database is created
automatically at `data/vulnscan.db` on first run (override with
`VULNSCAN_DB_PATH`).

## Step-by-Step Instructions

1. **Scope & Authorization**: fill in the engagement record — make sure
   the scope description explicitly states that **active vulnerability
   scanning** is authorized, not just reconnaissance.
2. **Single Target**: enter a domain or IP, pick which modules to run
   (check the tool-readiness pills first), click *Start Scan*.
3. **Bulk Upload**: upload a `.csv` or `.txt` file — capped at 5 targets,
   since active scans can run many minutes per target.
4. Watch live per-module progress, then review results in the dashboard.
5. From the results panel: **View/Download Report**, or grab the raw
   **JSON**/**CSV** exports.
6. Check the **Audit Log** tab any time for the append-only history.

## Running the tests

```bash
python -m unittest discover -s tests -v
```

The default suite runs entirely without nmap/masscan/nikto installed —
parsers are tested against fixture XML/JSON, command construction is
tested for exact argv shape, and subprocess invocations are mocked. A
separate `tests/integration/` suite exercises the real binaries end to
end; it's gated behind `VULNSCAN_RUN_INTEGRATION_TESTS=1` and is not run
by default (masscan needs root/`cap_net_raw`, and none of the three tools
can be assumed present in a generic environment).

## Configuration

Everything tunable lives in `config.py`: tool binary paths, masscan
rate/port range, nmap version-intensity and timeouts, NSE script timeout
and max-ports cap, nikto per-service timeout and max-services cap, NVD API
URL/key/throttle delays, CVE cache TTL, job concurrency, and bulk-target
cap.

## Limitations

- **This tool performs genuinely active vulnerability scanning** — it is
  not a drop-in replacement for a passive recon tool, and treating it as
  such risks scanning something you weren't authorized to actively probe.
- CVE matching uses NVD's free-text `keywordSearch`, not exact CPE
  matching — **matches are candidates requiring human triage**, not
  confirmed vulnerabilities. Expect some false positives.
- NSE vuln-script and nikto severity classification is heuristic
  (keyword/verdict-based), not an authoritative vulnerability database —
  treat it as a triage aid.
- masscan requires raw-socket privilege; without it (and without
  `setcap`), the app falls back to a slower nmap-only port sweep over a
  curated port list rather than the full range.
- No authentication/multi-user support — the audit log records *what*
  happened but not authenticated *who*.
- The engagement/authorization workflow is a **documentation aid**, not a
  legal safeguard — see the Usage Policy above.

## License

MIT — see [LICENSE](LICENSE).
