"""Runtime configuration and diagnostic thresholds."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    """All tunables for a diagnostic run. Immutable and safe to share across threads."""

    # --- probing behaviour -------------------------------------------------
    timeout: float = 5.0
    """Per-operation network timeout in seconds."""
    samples: int = 5
    """TCP connect samples per endpoint (used for latency, jitter and loss)."""
    workers: int = 4
    """Targets diagnosed concurrently."""
    max_redirects: int = 5
    icmp: bool = True
    traceroute: bool = False
    dns_compare: bool = True
    ca_bundle: str | None = None
    """PEM file of trusted CAs used *instead of* the system store (e.g. a corporate CA)."""
    resolvers: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")
    """Public resolvers used to cross-check the system resolver."""

    # --- diagnosis thresholds ---------------------------------------------
    latency_warn_ms: float = 250.0
    jitter_warn_ms: float = 30.0
    ttfb_warn_ms: float = 1500.0
    dns_warn_ms: float = 500.0
    cert_expiry_warn_days: int = 14

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            raise ValueError("timeout must be > 0")
        if not 1 <= self.samples <= 50:
            raise ValueError("samples must be between 1 and 50")
        if not 1 <= self.workers <= 32:
            raise ValueError("workers must be between 1 and 32")
        if not 0 <= self.max_redirects <= 20:
            raise ValueError("max_redirects must be between 0 and 20")
