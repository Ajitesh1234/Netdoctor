"""Optional path visibility via the system traceroute/tracert binary."""

from __future__ import annotations

import re
import shutil
import subprocess  # nosec B404 - argv list, never a shell; the address is a validated IP literal
import sys

from ..models import TracerouteResult

_HOP = re.compile(r"^\s*\d+\s")


def _decode(data: bytes | str | None) -> str:
    if data is None:
        return ""
    return data if isinstance(data, str) else data.decode("utf-8", "replace")


def check_traceroute(address: str, max_hops: int = 20, timeout: float = 2.0) -> TracerouteResult:
    if sys.platform == "win32":
        exe, args = shutil.which("tracert"), ["-d", "-h", str(max_hops), "-w", str(int(timeout * 1000)), address]
    else:
        exe = shutil.which("traceroute")
        args = ["-n", "-m", str(max_hops), "-q", "1", "-w", str(max(1, int(timeout))), address]
    if not exe:
        return TracerouteResult(False, available=False, error="traceroute executable not found")
    budget = max_hops * (timeout + 0.5) + 5
    truncated = False
    try:
        proc = subprocess.run(  # nosec B603 - argv list, never a shell; the address is a validated IP literal
            [exe, *args], capture_output=True, timeout=budget, check=False
        )
        out, err, rc = _decode(proc.stdout), _decode(proc.stderr), proc.returncode
    except subprocess.TimeoutExpired as exc:
        out, err, rc, truncated = _decode(exc.stdout), "", 0, True
    except OSError as exc:
        return TracerouteResult(False, available=False, error=str(exc))
    hops = [line.rstrip() for line in out.splitlines() if _HOP.match(line)]
    if rc != 0 and not hops:
        return TracerouteResult(False, error=(err.strip() or "traceroute failed")[:200])
    return TracerouteResult(bool(hops), hops=hops, truncated=truncated)
