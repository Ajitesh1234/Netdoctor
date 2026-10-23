"""NetDoctor: explain *why* a website is slow or unreachable."""

from __future__ import annotations

__version__ = "1.1.0"

from .config import Config
from .models import Finding, SessionReport, Severity, Status, TargetReport
from .runner import diagnose, run
from .watch import Watcher, WatchEvent, WatchSummary

__all__ = [
    "Config",
    "Finding",
    "SessionReport",
    "Severity",
    "Status",
    "TargetReport",
    "WatchEvent",
    "WatchSummary",
    "Watcher",
    "__version__",
    "diagnose",
    "run",
]
