"""NetDoctor: explain *why* a website is slow or unreachable."""

from __future__ import annotations

__version__ = "1.0.0"

from .config import Config
from .models import Finding, SessionReport, Severity, Status, TargetReport
from .runner import diagnose, run

__all__ = [
    "Config",
    "Finding",
    "SessionReport",
    "Severity",
    "Status",
    "TargetReport",
    "__version__",
    "diagnose",
    "run",
]
