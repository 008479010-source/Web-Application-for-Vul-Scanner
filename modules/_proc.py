"""Single choke point for every external-tool invocation in this app.

Every module that shells out to nmap/masscan/nikto routes through run_tool()
so there is exactly one place to review for subprocess safety: argv is
always a list (never a shell string), shell is always False, argv[0] is
always a config-defined binary path, and the scan target is always passed
as a single, already-validated argv element - never interpolated into a
larger string. Callers never accept raw CLI flags from user input.
"""

from __future__ import annotations

import os
import shutil
import subprocess


def run_tool(argv: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        shell=False,
    )


def binary_available(path: str) -> bool:
    if shutil.which(path) is not None:
        return True
    return os.path.isfile(path) and os.access(path, os.X_OK)
