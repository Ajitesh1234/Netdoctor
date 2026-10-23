"""Command-line interface."""

from __future__ import annotations

import argparse
import contextlib
import logging
import os
import sys
from collections.abc import Sequence

from . import __version__, report
from .config import Config
from .models import Status
from .runner import run
from .target import TargetError, parse_target
from .watch import Watcher, WatchEvent, render_event_json, render_event_text, render_summary_text

EXIT_HEALTHY, EXIT_DEGRADED, EXIT_USAGE, EXIT_FAILING, EXIT_INTERRUPTED = 0, 1, 2, 3, 130
_EXIT_FOR = {Status.HEALTHY: EXIT_HEALTHY, Status.DEGRADED: EXIT_DEGRADED, Status.FAILING: EXIT_FAILING}
DEFAULT_INTERVAL = 30.0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netdoctor",
        description="Diagnose why a website is slow or unreachable: DNS, TCP, TLS, HTTP, ICMP, path.",
        epilog="Exit codes: 0 healthy, 1 degraded, 2 usage error, 3 failing, 130 interrupted.",
    )
    p.add_argument("targets", nargs="*", metavar="TARGET", help="host, host:port or URL (http/https)")
    p.add_argument("--sites", nargs="+", default=[], metavar="TARGET", help="alias for positional targets")
    p.add_argument(
        "-f", "--format", choices=["text", "markdown", "json"], default=None, help="output format (default: text)"
    )
    p.add_argument("--json", action="store_true", help="shortcut for --format json")
    p.add_argument("-o", "--out", metavar="FILE", help="write the report to FILE (UTF-8) instead of stdout")
    p.add_argument(
        "--timeout", type=float, default=Config.timeout, help="per-operation timeout in seconds (default: %(default)s)"
    )
    p.add_argument(
        "--samples", type=int, default=Config.samples, help="TCP/ICMP samples per endpoint (default: %(default)s)"
    )
    p.add_argument(
        "--workers", type=int, default=Config.workers, help="targets checked in parallel (default: %(default)s)"
    )
    p.add_argument("--no-icmp", action="store_true", help="skip the ping check")
    p.add_argument("--no-dns-compare", action="store_true", help="do not query public resolvers to cross-check DNS")
    p.add_argument(
        "--resolver", action="append", metavar="IP", help="public resolver for the DNS cross-check (repeatable)"
    )
    p.add_argument(
        "--ca-bundle",
        metavar="PEM",
        help="trust the CAs in this PEM file instead of the system store (e.g. a corporate proxy CA)",
    )
    p.add_argument("--traceroute", action="store_true", help="also run traceroute (slow)")
    w = p.add_argument_group("watch mode", "continuous monitoring: report only what changes")
    w.add_argument(
        "-w", "--watch", action="store_true", help="re-run forever and print only state changes (Ctrl-C to stop)"
    )
    w.add_argument(
        "--interval",
        type=float,
        metavar="SECONDS",
        help=f"seconds between runs (default: {DEFAULT_INTERVAL:g}, minimum 1)",
    )
    w.add_argument("--max-runs", type=int, metavar="N", help="stop after N runs (default: run until interrupted)")
    w.add_argument(
        "--heartbeat",
        type=float,
        metavar="SECONDS",
        help="also emit a 'still alive' event for unchanged targets every SECONDS",
    )
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    p.add_argument("--ascii", action="store_true", help="use ASCII symbols instead of Unicode")
    p.add_argument("-v", "--verbose", action="count", default=0, help="log debug information to stderr")
    p.add_argument("--version", action="version", version=f"netdoctor {__version__}")
    return p


def _can_encode(stream: object, text: str) -> bool:
    try:
        text.encode(getattr(stream, "encoding", None) or "ascii")
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def _use_color(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty() and (sys.platform != "win32" or "WT_SESSION" in os.environ)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=[logging.WARNING, logging.INFO, logging.DEBUG][min(args.verbose, 2)],
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    raw_targets = [*args.targets, *args.sites]
    if not raw_targets:
        parser.error("at least one TARGET is required")
    fmt = "json" if args.json else (args.format or "text")
    if not args.watch:
        used = [
            name
            for name, v in (
                ("--interval", args.interval),
                ("--max-runs", args.max_runs),
                ("--heartbeat", args.heartbeat),
            )
            if v is not None
        ]
        if used:
            parser.error(f"{', '.join(used)} require --watch")
    elif fmt == "markdown":
        parser.error("--watch supports --format text or json (json emits one event per line)")
    try:
        for t in raw_targets:
            parse_target(t)
        if args.ca_bundle and not os.path.isfile(args.ca_bundle):
            raise ValueError(f"--ca-bundle file not found: {args.ca_bundle}")
        cfg = Config(
            timeout=args.timeout,
            samples=args.samples,
            workers=args.workers,
            icmp=not args.no_icmp,
            traceroute=args.traceroute,
            dns_compare=not args.no_dns_compare,
            ca_bundle=args.ca_bundle,
            resolvers=tuple(args.resolver) if args.resolver else Config.resolvers,
        )
        watcher = (
            Watcher(
                raw_targets,
                cfg,
                interval=DEFAULT_INTERVAL if args.interval is None else args.interval,
                heartbeat=args.heartbeat or 0.0,
            )
            if args.watch
            else None
        )
        if args.max_runs is not None and args.max_runs < 1:
            raise ValueError("--max-runs must be >= 1")
    except (TargetError, ValueError) as exc:
        print(f"netdoctor: error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if watcher is not None:
        return _watch(args, watcher, fmt)

    try:
        session = run(raw_targets, cfg)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_INTERRUPTED

    if fmt == "json":
        text = report.render_json(session) + "\n"
    elif fmt == "markdown":
        text = report.render_markdown(session)
    else:
        to_file = bool(args.out)
        text = report.render_text(
            session,
            ascii_only=args.ascii or (not to_file and not _can_encode(sys.stdout, "✔ℹ⚠✖")),
            color=False if to_file else _use_color(args.color),
        )

    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
        except OSError as exc:
            print(f"netdoctor: error: cannot write {args.out}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        print(f"Report written to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)

    return _EXIT_FOR[session.worst_status]


def _watch(args: argparse.Namespace, watcher: Watcher, fmt: str) -> int:
    """Run watch mode. Events go to stdout (or are appended to ``--out``); chatter to stderr."""
    out_fh = None
    if args.out:
        try:
            out_fh = open(args.out, "a", encoding="utf-8", newline="\n")  # noqa: SIM115 - closed in finally
        except OSError as exc:
            print(f"netdoctor: error: cannot open {args.out}: {exc}", file=sys.stderr)
            return EXIT_USAGE
    ascii_only = args.ascii or (out_fh is None and not _can_encode(sys.stdout, "✔ℹ⚠✖"))
    color = out_fh is None and _use_color(args.color)
    stream = out_fh or sys.stdout

    def write(line: str) -> None:
        stream.write(line + "\n")
        stream.flush()

    def emit(event: WatchEvent) -> None:
        write(
            render_event_json(event) if fmt == "json" else render_event_text(event, ascii_only=ascii_only, color=color)
        )

    print(
        f"netdoctor {__version__}: watching {len(watcher.targets)} target(s) every {watcher.interval:g}s"
        + (f", appending to {args.out}" if args.out else "")
        + " (Ctrl-C to stop)",
        file=sys.stderr,
    )
    last = None
    interrupted = False
    try:
        last = watcher.loop(emit, max_runs=args.max_runs, runner=run)
    except KeyboardInterrupt:
        interrupted = True
    except BrokenPipeError:  # e.g. `netdoctor --watch ... | head`
        with contextlib.suppress(Exception):
            sys.stdout.close()
        return EXIT_INTERRUPTED
    try:
        summary = watcher.summary()
        write(render_event_json(summary) if fmt == "json" else render_summary_text(summary))
    finally:
        if out_fh:
            out_fh.close()
    if interrupted:
        return EXIT_INTERRUPTED
    return _EXIT_FOR[last.worst_status] if last else EXIT_FAILING
