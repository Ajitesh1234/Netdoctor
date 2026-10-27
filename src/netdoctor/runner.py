"""Orchestration: run all checks for each target, concurrently and fault-isolated."""

from __future__ import annotations

import logging
import platform
import time
import uuid
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from typing import TypeVar

from . import __version__, analysis
from .checks import dns as dns_check
from .checks import http as http_check
from .checks import icmp as icmp_check
from .checks import tcp as tcp_check
from .checks import tls as tls_check
from .checks import traceroute as trace_check
from .checks.util import short_error
from .config import Config
from .models import (
    HttpResult,
    IcmpResult,
    SessionReport,
    TargetReport,
    TcpResult,
    TlsResult,
    TracerouteResult,
)
from .target import Target, parse_target, parse_targets

log = logging.getLogger(__name__)
T = TypeVar("T")


def _result(future: Future[T], fallback: Callable[[str], T]) -> T:
    """Fetch a future's result; an unexpected bug in one check must not sink the run."""
    try:
        return future.result()
    except Exception as exc:
        log.exception("check crashed")
        return fallback(f"internal error: {short_error(exc)}")


def _representatives(addresses: list[str]) -> list[str]:
    """First IPv4 and first IPv6 address (one probe target per IP family)."""
    v4 = next((a for a in addresses if ":" not in a), None)
    v6 = next((a for a in addresses if ":" in a), None)
    return [a for a in (v4, v6) if a]


def diagnose(target: Target | str, cfg: Config | None = None) -> TargetReport:
    """Run every enabled check against one target and return an analysed report."""
    cfg = cfg or Config()
    if isinstance(target, str):
        target = parse_target(target)
    started = time.perf_counter()
    rep = TargetReport(target=target.raw, host=target.host)
    rep.dns = dns_check.check_dns(target, cfg)

    if rep.dns.ok:
        addresses = rep.dns.addresses
        ipv4 = next((a for a in addresses if ":" not in a), None)
        with ThreadPoolExecutor(max_workers=12, thread_name_prefix="nd-check") as pool:
            tcp_futs = [
                pool.submit(tcp_check.probe, addr, port, cfg.samples, cfg.timeout)
                for port in target.tcp_ports
                for addr in _representatives(addresses)
            ]
            tls_fut = (
                pool.submit(tls_check.check_tls, target.host, target.tls_port, cfg.timeout, cfg.ca_bundle)
                if target.tls_port
                else None
            )
            http_fut = pool.submit(http_check.check_http, target, cfg)
            icmp_fut = (
                pool.submit(icmp_check.check_icmp, ipv4, cfg.samples, cfg.timeout) if (cfg.icmp and ipv4) else None
            )
            trace_fut = pool.submit(trace_check.check_traceroute, ipv4, 20, 2.0) if (cfg.traceroute and ipv4) else None

            rep.tcp = [
                _result(f, lambda e: TcpResult(0, "?", "?", 0, 0, 100.0, error=e, error_kind="error")) for f in tcp_futs
            ]
            if tls_fut:
                rep.tls = _result(tls_fut, lambda e: TlsResult(False, error=e, error_kind="error"))
            rep.http = _result(http_fut, lambda e: HttpResult(False, error=e, error_kind="error"))
            if icmp_fut:
                rep.icmp = _result(icmp_fut, lambda e: IcmpResult(False, error=e))
            if trace_fut:
                rep.traceroute = _result(trace_fut, lambda e: TracerouteResult(False, error=e))

    analysis.analyze(rep, cfg, is_ip=target.is_ip)
    rep.duration_ms = round((time.perf_counter() - started) * 1000, 1)
    return rep


def run(targets: Iterable[str], cfg: Config | None = None) -> SessionReport:
    """Diagnose several targets concurrently, preserving input order.

    Raises ``TargetError`` up-front if any target is invalid, before any traffic is sent.
    """
    cfg = cfg or Config()
    parsed = parse_targets(targets)
    with ThreadPoolExecutor(max_workers=min(cfg.workers, max(1, len(parsed)))) as pool:
        reports = list(pool.map(lambda t: diagnose(t, cfg), parsed))
    return SessionReport(
        tool_version=__version__,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        reports=reports,
        run_id=uuid.uuid4().hex,
        environment={"python": platform.python_version(), "platform": platform.platform(terse=True)},
    )
