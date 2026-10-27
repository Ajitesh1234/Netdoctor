"""Logging configuration: human-readable text or one-JSON-object-per-line for SIEM ingestion."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

_MARK = "_netdoctor_handler"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False, separators=(",", ":"))


def setup_logging(verbose: int = 0, fmt: str = "text", path: str | None = None) -> None:
    """Install (replacing any earlier call's) handler on the ``netdoctor`` logger.

    Logs go to stderr, or to ``path`` (appended, UTF-8) when given. Secrets are never logged:
    callers pass URLs through :func:`netdoctor.notify.redact_url` first.
    """
    logger = logging.getLogger("netdoctor")
    for h in [h for h in logger.handlers if getattr(h, _MARK, False)]:
        logger.removeHandler(h)
        h.close()
    handler: logging.Handler = (
        logging.FileHandler(path, encoding="utf-8") if path else logging.StreamHandler(sys.stderr)
    )
    handler.setFormatter(JsonFormatter() if fmt == "json" else logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    setattr(handler, _MARK, True)
    logger.addHandler(handler)
    logger.setLevel([logging.WARNING, logging.INFO, logging.DEBUG][max(0, min(verbose, 2))])
