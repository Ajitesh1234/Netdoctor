"""TCP connect probing: latency, jitter and loss from repeated handshakes."""

from __future__ import annotations

import socket
import statistics
import time

from ..models import TcpResult
from .util import classify_exception, ms, short_error


def probe(address: str, port: int, samples: int, timeout: float) -> TcpResult:
    """Open ``samples`` TCP connections and summarise handshake times.

    Jitter is the mean absolute difference between consecutive successful samples
    (the RFC 3550 notion of interarrival variation, without smoothing).
    """
    family = "ipv6" if ":" in address else "ipv4"
    times: list[float] = []
    last_exc: BaseException | None = None
    for i in range(samples):
        start = time.perf_counter()
        try:
            with socket.create_connection((address, port), timeout=timeout):
                times.append(ms(time.perf_counter() - start))
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
        if i < samples - 1:
            time.sleep(0.05)
    ok = len(times)
    jitter = round(statistics.mean(abs(b - a) for a, b in zip(times, times[1:])), 2) if len(times) >= 2 else None
    return TcpResult(
        port=port,
        address=address,
        family=family,
        attempts=samples,
        successes=ok,
        loss_pct=round(100.0 * (samples - ok) / samples, 1),
        min_ms=min(times) if times else None,
        avg_ms=round(statistics.mean(times), 2) if times else None,
        max_ms=max(times) if times else None,
        jitter_ms=jitter,
        error=short_error(last_exc) if last_exc and not ok else None,
        error_kind=classify_exception(last_exc) if last_exc and not ok else None,
    )
