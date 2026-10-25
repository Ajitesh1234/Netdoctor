"""ICMP echo via the system ``ping`` binary (no raw sockets, no elevated privileges)."""

from __future__ import annotations

import re
import shutil
import subprocess  # nosec B404 - argv list, never a shell; the address is a validated IP literal
import sys

from ..models import IcmpResult

_UNIX_LOSS = re.compile(r"(\d+(?:\.\d+)?)%\s+packet loss")
_UNIX_COUNTS = re.compile(r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets\s+)?received")
_UNIX_RTT = re.compile(r"(?:rtt|round-trip)[^=]*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)")
_WIN_COUNTS = re.compile(r"Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*\d+\s*\((\d+)%")
_WIN_RTT = re.compile(r"Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms")


def parse_ping(output: str) -> IcmpResult:
    """Parse Linux/macOS/BSD and Windows (English) ``ping`` summaries."""
    m = _WIN_COUNTS.search(output)
    if m:
        sent, received, loss = int(m[1]), int(m[2]), float(m[3])
        rtt = _WIN_RTT.search(output)
        return IcmpResult(
            ok=received > 0,
            sent=sent,
            received=received,
            loss_pct=loss,
            min_ms=float(rtt[1]) if rtt else None,
            max_ms=float(rtt[2]) if rtt else None,
            avg_ms=float(rtt[3]) if rtt else None,
        )
    counts, loss_m, rtt = _UNIX_COUNTS.search(output), _UNIX_LOSS.search(output), _UNIX_RTT.search(output)
    if not (counts and loss_m):
        return IcmpResult(False, error="could not parse ping output")
    sent, received = int(counts[1]), int(counts[2])
    return IcmpResult(
        ok=received > 0,
        sent=sent,
        received=received,
        loss_pct=float(loss_m[1]),
        min_ms=float(rtt[1]) if rtt else None,
        avg_ms=float(rtt[2]) if rtt else None,
        max_ms=float(rtt[3]) if rtt else None,
        jitter_ms=float(rtt[4]) if rtt else None,  # mdev / stddev
    )


def _command(address: str, count: int, timeout: float) -> list[str]:
    if sys.platform == "win32":
        return ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), address]
    if sys.platform == "darwin":
        return ["ping", "-c", str(count), "-W", str(int(timeout * 1000)), address]
    if sys.platform.startswith("linux"):
        return ["ping", "-c", str(count), "-W", str(max(1, int(timeout))), address]
    return ["ping", "-c", str(count), address]


def check_icmp(ipv4_address: str, count: int, timeout: float) -> IcmpResult:
    exe = shutil.which("ping")
    if not exe:
        return IcmpResult(False, available=False, error="ping executable not found")
    cmd = _command(ipv4_address, count, timeout)
    cmd[0] = exe
    try:
        proc = subprocess.run(  # nosec B603 - argv list, never a shell; the address is a validated IP literal
            cmd,
            capture_output=True,
            text=True,
            timeout=count * timeout + 5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return IcmpResult(False, error="ping timed out")
    except OSError as exc:
        return IcmpResult(False, available=False, error=str(exc))
    result = parse_ping(proc.stdout or "")
    if result.error and proc.stderr:
        result.error = proc.stderr.strip()[:200]
    return result
