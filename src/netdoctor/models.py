"""Typed result models. Every check returns one of these; none raise on network failure."""

from __future__ import annotations

import dataclasses
import enum
from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = 1


class Severity(enum.IntEnum):
    OK = 0
    INFO = 1
    WARNING = 2
    CRITICAL = 3


class Status(str, enum.Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILING = "failing"


@dataclass
class ResolverAnswer:
    server: str
    ok: bool
    addresses: list[str] = field(default_factory=list)
    rcode: int | None = None
    latency_ms: float | None = None
    error: str | None = None
    error_kind: str | None = None


@dataclass
class DnsResult:
    ok: bool
    addresses: list[str] = field(default_factory=list)
    latency_ms: float | None = None
    skipped: bool = False
    error: str | None = None
    error_kind: str | None = None
    public: list[ResolverAnswer] = field(default_factory=list)


@dataclass
class TcpResult:
    port: int
    address: str
    family: str
    attempts: int
    successes: int
    loss_pct: float
    min_ms: float | None = None
    avg_ms: float | None = None
    max_ms: float | None = None
    jitter_ms: float | None = None
    error: str | None = None
    error_kind: str | None = None

    @property
    def ok(self) -> bool:
        return self.successes > 0


@dataclass
class TlsResult:
    ok: bool
    port: int = 443
    handshake_ms: float | None = None
    version: str | None = None
    cipher: str | None = None
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_to_expiry: float | None = None
    san: list[str] = field(default_factory=list)
    error: str | None = None
    error_kind: str | None = None


@dataclass
class HttpHop:
    url: str
    status: int
    reason: str
    connect_ms: float
    ttfb_ms: float
    server: str | None = None
    location: str | None = None


@dataclass
class HttpResult:
    ok: bool
    scheme: str | None = None
    final_url: str | None = None
    status: int | None = None
    reason: str | None = None
    connect_ms: float | None = None
    ttfb_ms: float | None = None
    total_ms: float | None = None
    hops: list[HttpHop] = field(default_factory=list)
    fell_back_from_https: bool = False
    https_error: str | None = None
    https_error_kind: str | None = None
    error: str | None = None
    error_kind: str | None = None


@dataclass
class IcmpResult:
    ok: bool
    available: bool = True
    sent: int | None = None
    received: int | None = None
    loss_pct: float | None = None
    min_ms: float | None = None
    avg_ms: float | None = None
    max_ms: float | None = None
    jitter_ms: float | None = None
    error: str | None = None


@dataclass
class TracerouteResult:
    ok: bool
    available: bool = True
    hops: list[str] = field(default_factory=list)
    truncated: bool = False
    error: str | None = None


@dataclass
class Finding:
    severity: Severity
    code: str
    message: str
    hint: str | None = None


@dataclass
class TargetReport:
    target: str
    host: str
    dns: DnsResult | None = None
    tcp: list[TcpResult] = field(default_factory=list)
    tls: TlsResult | None = None
    http: HttpResult | None = None
    icmp: IcmpResult | None = None
    traceroute: TracerouteResult | None = None
    findings: list[Finding] = field(default_factory=list)
    status: Status = Status.HEALTHY
    summary: str = ""
    duration_ms: float = 0.0


@dataclass
class SessionReport:
    tool_version: str
    generated_at: str
    reports: list[TargetReport] = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION

    @property
    def worst_status(self) -> Status:
        order = [Status.HEALTHY, Status.DEGRADED, Status.FAILING]
        return max((r.status for r in self.reports), key=order.index, default=Status.HEALTHY)


def to_plain(obj: Any) -> Any:
    """Convert dataclasses/enums into JSON-serialisable primitives."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_plain(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, enum.Enum):
        return obj.name.lower() if isinstance(obj, Severity) else obj.value
    if isinstance(obj, (list, tuple)):
        return [to_plain(i) for i in obj]
    if isinstance(obj, dict):
        return {str(k): to_plain(v) for k, v in obj.items()}
    return obj
