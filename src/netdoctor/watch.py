"""Continuous monitoring: re-run diagnostics on an interval and report only what *changed*.

The engine (:class:`Watcher`) does no I/O of its own. The clock, the sleep function and the
diagnostic runner are injectable, so behaviour is fully deterministic under test, and callers
decide how events are rendered (text, JSON Lines, a webhook, ...).

What counts as a change
-----------------------
A target's *state* is its overall status plus the set of finding **codes** at warning level or
above. Message text is ignored on purpose: "latency 48 ms" vs "51 ms" is noise, while
``HIGH_LATENCY`` appearing or disappearing is an event.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .checks.util import short_error
from .config import Config
from .models import SCHEMA_VERSION, Finding, SessionReport, Severity, Status, TargetReport, to_plain
from .report import _ASCII, _ICONS, _STATUS_SEV, _paint
from .runner import run

log = logging.getLogger(__name__)

INITIAL, CHANGE, RECOVERED, HEARTBEAT, ERROR, SUMMARY = (
    "initial",
    "change",
    "recovered",
    "heartbeat",
    "error",
    "summary",
)

Runner = Callable[[Iterable[str], Config], SessionReport]


# --------------------------------------------------------------------------- models
@dataclass
class WatchEvent:
    """Something worth telling the operator about."""

    event: str
    timestamp: str
    target: str | None = None
    status: Status | None = None
    previous_status: Status | None = None
    summary: str = ""
    in_previous_state_s: float | None = None
    """Seconds spent in ``previous_status`` (only set when the status itself changed)."""
    added: list[Finding] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    """Codes of warning-or-worse findings that cleared."""
    error: str | None = None
    report: TargetReport | None = None
    schema_version: int = SCHEMA_VERSION


@dataclass
class TargetStats:
    target: str
    status: Status
    in_state_s: float
    checks: int
    healthy: int
    degraded: int
    failing: int
    healthy_pct: float = field(init=False)

    def __post_init__(self) -> None:
        self.healthy_pct = round(100.0 * self.healthy / self.checks, 1) if self.checks else 0.0


@dataclass
class WatchSummary:
    timestamp: str
    runs: int
    duration_s: float
    targets: list[TargetStats]
    event: str = SUMMARY
    schema_version: int = SCHEMA_VERSION


@dataclass
class _State:
    status: Status
    codes: dict[str, Finding]
    since: float
    checks: int = 0
    healthy: int = 0
    degraded: int = 0
    failing: int = 0


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sleep(seconds: float, stop: threading.Event) -> None:
    """Interruptible sleep in short slices.

    Waiting in one long ``Event.wait`` can delay Ctrl-C on Windows until the wait returns.
    """
    deadline = time.monotonic() + seconds
    while not stop.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        stop.wait(min(0.5, remaining))


# --------------------------------------------------------------------------- engine
class Watcher:
    """Tracks per-target state across diagnostic runs and emits change events."""

    def __init__(
        self,
        targets: Iterable[str],
        cfg: Config,
        *,
        interval: float = 30.0,
        heartbeat: float = 0.0,
        clock: Callable[[], float] = time.monotonic,
        stamp: Callable[[], str] = _utc_stamp,
    ) -> None:
        if interval < 1:
            raise ValueError("interval must be >= 1 second")
        if heartbeat < 0:
            raise ValueError("heartbeat must be >= 0")
        self.targets = list(dict.fromkeys(targets))  # de-duplicate, keep order
        self.cfg = cfg
        self.interval = interval
        self.heartbeat = heartbeat
        self.runs = 0
        self._clock = clock
        self._stamp = stamp
        self._states: dict[str, _State] = {}
        self._started = clock()
        self._last_beat: float | None = None

    # ------------------------------------------------------------------ pure logic
    def observe(self, session: SessionReport) -> list[WatchEvent]:
        """Compare ``session`` with the previous state and return the resulting events."""
        now, ts = self._clock(), self._stamp()
        events: list[WatchEvent] = []
        quiet: list[TargetReport] = []

        for rep in session.reports:
            significant = {f.code: f for f in rep.findings if f.severity >= Severity.WARNING}
            state = self._states.get(rep.target)
            if state is None:
                state = self._states[rep.target] = _State(rep.status, significant, now)
                events.append(
                    WatchEvent(
                        INITIAL,
                        ts,
                        rep.target,
                        rep.status,
                        summary=rep.summary,
                        added=list(significant.values()),
                        report=rep,
                    )
                )
            else:
                added = [f for code, f in significant.items() if code not in state.codes]
                removed = [code for code in state.codes if code not in significant]
                previous = state.status
                if rep.status != previous or added or removed:
                    status_changed = rep.status != previous
                    kind = RECOVERED if (rep.status is Status.HEALTHY and previous is not Status.HEALTHY) else CHANGE
                    events.append(
                        WatchEvent(
                            kind,
                            ts,
                            rep.target,
                            rep.status,
                            previous_status=previous if status_changed else None,
                            summary=rep.summary,
                            in_previous_state_s=round(now - state.since, 1) if status_changed else None,
                            added=added,
                            removed=removed,
                            report=rep,
                        )
                    )
                    if status_changed:
                        state.status, state.since = rep.status, now
                    state.codes = significant
                else:
                    quiet.append(rep)

            state.checks += 1
            if rep.status is Status.HEALTHY:
                state.healthy += 1
            elif rep.status is Status.DEGRADED:
                state.degraded += 1
            else:
                state.failing += 1

        if self.heartbeat:
            if self._last_beat is None:
                self._last_beat = now
            elif now - self._last_beat >= self.heartbeat:
                self._last_beat = now
                events += [
                    WatchEvent(HEARTBEAT, ts, rep.target, rep.status, summary=rep.summary, report=rep) for rep in quiet
                ]
        return events

    def summary(self) -> WatchSummary:
        now = self._clock()
        stats = [
            TargetStats(t, s.status, round(now - s.since, 1), s.checks, s.healthy, s.degraded, s.failing)
            for t, s in self._states.items()
        ]
        return WatchSummary(self._stamp(), self.runs, round(now - self._started, 1), stats)

    # ------------------------------------------------------------------ driver
    def loop(
        self,
        emit: Callable[[WatchEvent], None],
        *,
        max_runs: int | None = None,
        runner: Runner = run,
        stop: threading.Event | None = None,
        sleep: Callable[[float, threading.Event], None] | None = None,
    ) -> SessionReport | None:
        """Run until ``max_runs`` is reached or ``stop`` is set. Returns the last good session.

        ``KeyboardInterrupt`` is deliberately not swallowed; the caller decides how to stop.
        """
        stop = stop or threading.Event()
        sleep = sleep or _sleep  # resolved at call time so tests can patch the module attribute
        last: SessionReport | None = None
        while not stop.is_set():
            started = self._clock()
            try:
                last = runner(self.targets, self.cfg)
            except Exception as exc:
                log.exception("watch cycle failed")
                emit(WatchEvent(ERROR, self._stamp(), error=short_error(exc)))
            else:
                for event in self.observe(last):
                    emit(event)
            self.runs += 1
            if max_runs is not None and self.runs >= max_runs:
                break
            remaining = self.interval - (self._clock() - started)
            if remaining > 0:
                sleep(remaining, stop)
        return last


# --------------------------------------------------------------------------- rendering
def format_duration(seconds: float) -> str:
    s = round(seconds)
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}m {s:02d}s"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h}h {m:02d}m"
    d, h = divmod(h, 24)
    return f"{d}d {h:02d}h"


def render_event_json(event: WatchEvent | WatchSummary) -> str:
    """One compact JSON object per line (JSON Lines)."""
    return json.dumps(to_plain(event), ensure_ascii=False, separators=(",", ":"))


def render_event_text(event: WatchEvent, *, ascii_only: bool = False, color: bool = False) -> str:
    icons = _ASCII if ascii_only else _ICONS
    stamp = event.timestamp.replace("T", " ")
    if event.event == ERROR:
        return (
            f"{stamp}  {_paint(icons[Severity.CRITICAL], Severity.CRITICAL, color)} watch cycle failed: {event.error}"
        )

    assert event.status is not None and event.target is not None
    sev = _STATUS_SEV[event.status]
    badge = _paint(f"{icons[sev]} {event.status.value.upper():<8}", sev, color)
    head = f"{stamp}  {event.target}  {badge}"

    if event.event == INITIAL:
        head += f"  {event.summary}"
    elif event.event == HEARTBEAT:
        head += f"  still {event.status.value}"
    elif event.event == RECOVERED:
        head += (
            f"  recovered after {format_duration(event.in_previous_state_s or 0)} as {event.previous_status.value.upper()}"
            if event.previous_status
            else "  recovered"
        )
    elif event.previous_status is not None:
        head += f"  was {event.previous_status.value.upper()} for {format_duration(event.in_previous_state_s or 0)}"
    else:
        head += "  findings changed"

    lines = [head]
    for f in event.added:
        lines.append(f"    {_paint('+', f.severity, color)} {f.message}")
        if f.hint:
            lines.append(f"        -> {f.hint}")
    for code in event.removed:
        lines.append(f"    {_paint('-', Severity.OK, color)} {code} cleared")
    return "\n".join(lines)


def render_summary_text(summary: WatchSummary) -> str:
    lines = [
        "",
        f"Stopped after {summary.runs} run(s) over {format_duration(summary.duration_s)}.",
    ]
    width = max((len(t.target) for t in summary.targets), default=0)
    for t in summary.targets:
        lines.append(
            f"  {t.target:<{width}}  {t.status.value.upper()} for {format_duration(t.in_state_s)}"
            f"  |  checks {t.checks}: healthy {t.healthy}, degraded {t.degraded}, failing {t.failing}"
            f"  ({t.healthy_pct:g}% healthy)"
        )
    return "\n".join(lines)


__all__ = [
    "TargetStats",
    "WatchEvent",
    "WatchSummary",
    "Watcher",
    "format_duration",
    "render_event_json",
    "render_event_text",
    "render_summary_text",
]
