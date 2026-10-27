"""Command-line interface."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import sys
from collections.abc import Callable, Sequence
from typing import TextIO

from . import __version__, report
from .fsutil import atomic_write_text, open_private
from .htmlreport import render_html
from .logsetup import setup_logging
from .metrics import MetricsServer, render_prometheus
from .models import SessionReport, Status
from .notify import WebhookConfig, WebhookNotifier, redact_url
from .runner import run
from .settings import (
    DEFAULT_METRICS_TOKEN_ENV,
    DEFAULT_WEBHOOK_SECRET_ENV,
    FORMATS,
    WATCH_FORMATS,
    WATCH_ONLY,
    Settings,
    SettingsError,
    apply_args,
    apply_file,
    load_file,
    parse_mode,
    resolve_env_ref,
    secret_from_env,
)
from .target import TargetError, parse_targets
from .watch import Watcher, WatchEvent, render_event_json, render_event_text, render_summary_text

EXIT_HEALTHY, EXIT_DEGRADED, EXIT_USAGE, EXIT_FAILING, EXIT_INTERRUPTED, EXIT_TERMINATED = 0, 1, 2, 3, 130, 143
EXIT_PIPE = 141  # 128 + SIGPIPE: the reader (e.g. `| head`) went away
_EXIT_FOR = {Status.HEALTHY: EXIT_HEALTHY, Status.DEGRADED: EXIT_DEGRADED, Status.FAILING: EXIT_FAILING}
_SYMBOLS = "✔ℹ⚠✖"


def build_parser() -> argparse.ArgumentParser:
    bool_opt = argparse.BooleanOptionalAction
    p = argparse.ArgumentParser(
        prog="netdoctor",
        description="Diagnose why a website is slow or unreachable: DNS, TCP, TLS, HTTP, ICMP, path.",
        epilog=(
            "Exit codes: 0 healthy, 1 degraded, 2 usage error, 3 failing, 130 interrupted (Ctrl-C), 143 terminated (SIGTERM). "
            "Precedence: built-in defaults < --config file < command-line flags."
        ),
    )
    p.add_argument("targets", nargs="*", metavar="TARGET", help="host, host:port or URL (http/https)")
    p.add_argument("--sites", nargs="+", default=[], metavar="TARGET", help="alias for positional targets")
    p.add_argument("--config", metavar="FILE", help="TOML config file (unknown keys are an error)")
    p.add_argument(
        "--print-config", action="store_true", help="print the effective settings (secrets redacted) and exit"
    )
    p.add_argument("-f", "--format", choices=FORMATS, help="output format (default: text)")
    p.add_argument("--json", action="store_true", help="shortcut for --format json")
    p.add_argument("-o", "--out", metavar="FILE", help="write the report to FILE (atomically, UTF-8) instead of stdout")
    p.add_argument(
        "--out-mode",
        metavar="MODE",
        help="permissions for new report files as octal, e.g. 640 (default: 600 = owner only)",
    )
    p.add_argument("--timeout", type=float, metavar="SECONDS", help="per-operation timeout (default: 5)")
    p.add_argument("--samples", type=int, metavar="N", help="TCP/ICMP samples per endpoint (default: 5)")
    p.add_argument("--workers", type=int, metavar="N", help="targets checked in parallel (default: 4)")
    p.add_argument("--icmp", action=bool_opt, default=None, help="ping check (default: on)")
    p.add_argument("--traceroute", action=bool_opt, default=None, help="traceroute (slow; default: off)")
    d = p.add_argument_group("DNS cross-checks")
    d.add_argument(
        "--dns-compare", action=bool_opt, default=None, help="query public resolvers to cross-check DNS (default: on)"
    )
    d.add_argument("--resolver", action="append", metavar="IP", help="public resolver for the cross-check (repeatable)")
    d.add_argument("--doh", action="store_true", help="also cross-check with DNS-over-HTTPS (Cloudflare and Google)")
    d.add_argument("--doh-server", action="append", metavar="URL", help="custom DoH endpoint, https:// (repeatable)")
    p.add_argument(
        "--ca-bundle", metavar="PEM", help="trust these CAs instead of the system store (corporate proxy CA)"
    )
    w = p.add_argument_group("watch mode", "continuous monitoring: report only what changes")
    w.add_argument(
        "-w", "--watch", action="store_true", help="re-run forever and print only state changes (Ctrl-C to stop)"
    )
    w.add_argument("--interval", type=float, metavar="SECONDS", help="seconds between runs (default: 30, minimum 1)")
    w.add_argument("--max-runs", type=int, metavar="N", help="stop after N runs (default: until interrupted)")
    w.add_argument(
        "--heartbeat",
        type=float,
        metavar="SECONDS",
        help="emit a 'still alive' event for unchanged targets every SECONDS",
    )
    w.add_argument(
        "--confirm",
        type=int,
        metavar="N",
        help="report a change only after N consecutive sightings (flap damping; default 1)",
    )
    n = p.add_argument_group("notifications (watch mode)")
    n.add_argument(
        "--webhook",
        metavar="URL",
        help="POST events to this https URL; use env:NAME to read it from an environment variable",
    )
    n.add_argument(
        "--webhook-format",
        dest="webhook_kind",
        choices=["generic", "slack"],
        help="payload format (default: generic JSON)",
    )
    n.add_argument(
        "--notify-on",
        metavar="EVENTS",
        help="comma-separated: initial,change,recovered,heartbeat,error (default: change,recovered,error)",
    )
    n.add_argument(
        "--webhook-secret-env",
        metavar="NAME",
        help=f"env var holding the HMAC signing key (default: {DEFAULT_WEBHOOK_SECRET_ENV} if set)",
    )
    n.add_argument(
        "--webhook-allow-private",
        action="store_true",
        help="allow private/loopback destinations (disables SSRF protection)",
    )
    n.add_argument("--webhook-allow-http", action="store_true", help="allow plain http:// webhooks")
    n.add_argument("--webhook-include-report", action="store_true", help="include the full report in generic payloads")
    m = p.add_argument_group("metrics (watch mode)")
    m.add_argument("--metrics-port", type=int, metavar="PORT", help="serve Prometheus metrics at /metrics on this port")
    m.add_argument("--metrics-bind", metavar="ADDR", help="address to bind (default: 127.0.0.1)")
    m.add_argument(
        "--metrics-token-env",
        metavar="NAME",
        help=f"env var holding a bearer token (default: {DEFAULT_METRICS_TOKEN_ENV} if set)",
    )
    o = p.add_argument_group("output and logging")
    o.add_argument("--color", choices=["auto", "always", "never"])
    o.add_argument("--ascii", action="store_true", help="use ASCII symbols instead of Unicode")
    o.add_argument("-v", "--verbose", action="count", default=None, help="log more detail to stderr (-vv for debug)")
    o.add_argument("--log-format", choices=["text", "json"], help="log line format (default: text)")
    o.add_argument("--log-file", metavar="FILE", help="append logs to FILE instead of stderr")
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


def _silence_stdout() -> None:
    """Point stdout at /dev/null so the interpreter's exit-time flush cannot raise again."""
    with contextlib.suppress(Exception):
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, sys.stdout.fileno())
        finally:
            os.close(devnull)


def _write_stdout(text: str) -> None:
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:  # legacy console code pages: degrade instead of crashing
        enc = getattr(sys.stdout, "encoding", None) or "ascii"
        sys.stdout.write(text.encode(enc, "replace").decode(enc))


def resolve_settings(args: argparse.Namespace) -> Settings:
    settings = Settings()
    if args.config:
        data, base = load_file(args.config)
        apply_file(settings, data, base, path=args.config)
    apply_args(settings, args)
    return settings


def validate_settings(settings: Settings) -> None:
    """Cross-field validation. Raises SettingsError/TargetError/ValueError before any network traffic."""
    parse_targets(settings.targets)
    parse_mode(settings.out_mode)
    if settings.ca_bundle and not os.path.isfile(settings.ca_bundle):
        raise SettingsError(f"ca_bundle file not found: {settings.ca_bundle}")
    if settings.doh_servers and not settings.dns_compare:
        raise SettingsError("DNS-over-HTTPS needs the DNS cross-check; remove --no-dns-compare or the DoH servers")
    if settings.watch:
        if settings.format not in WATCH_FORMATS:
            raise SettingsError(f"watch mode supports formats {', '.join(WATCH_FORMATS)} (got {settings.format})")
        if settings.max_runs is not None and settings.max_runs < 1:
            raise SettingsError("max-runs must be >= 1")
    else:
        stray = sorted(settings.cli_explicit & WATCH_ONLY)
        if stray:
            raise SettingsError(f"{', '.join(stray)}: only valid in watch mode (add --watch)")
    settings.to_config()  # validates every numeric range


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        settings = resolve_settings(args)
        if not settings.targets:
            parser.error("at least one TARGET is required (or set 'targets' in the config file)")
        validate_settings(settings)
        try:
            setup_logging(settings.verbose, settings.log_format, settings.log_file)
        except OSError as exc:
            raise SettingsError(f"cannot open log file {settings.log_file}: {exc}") from exc
    except (SettingsError, TargetError, ValueError, OSError) as exc:
        print(f"netdoctor: error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        if args.print_config:
            print(json.dumps(settings.redacted(), indent=2))
            return EXIT_HEALTHY
        if settings.watch:
            return _watch(settings)
        return _one_shot(settings)
    except BrokenPipeError:  # `netdoctor ... | head`: exit quietly instead of printing a traceback
        _silence_stdout()
        return EXIT_PIPE


# --------------------------------------------------------------------------- one-shot
def _render(session: SessionReport, s: Settings) -> str:
    if s.format == "json":
        return report.render_json(session) + "\n"
    if s.format == "markdown":
        return report.render_markdown(session)
    if s.format == "html":
        return render_html(session)
    if s.format == "prometheus":
        return render_prometheus(session)
    to_file = bool(s.out)
    return report.render_text(
        session,
        ascii_only=s.ascii or (not to_file and not _can_encode(sys.stdout, _SYMBOLS)),
        color=False if to_file else _use_color(s.color),
    )


def _one_shot(s: Settings) -> int:
    try:
        session = run(s.targets, s.to_config())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_INTERRUPTED
    text = _render(session, s)
    if s.out:
        try:
            atomic_write_text(s.out, text, mode=parse_mode(s.out_mode))
        except OSError as exc:
            print(f"netdoctor: error: cannot write {s.out}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        print(f"Report written to {s.out}", file=sys.stderr)
    else:
        _write_stdout(text)
    return _EXIT_FOR[session.worst_status]


# --------------------------------------------------------------------------- watch
def _install_sigterm(flag: list[bool]) -> Callable[[], None]:
    """Turn SIGTERM (docker stop, systemd, Kubernetes) into a graceful shutdown.

    The handler raises ``KeyboardInterrupt`` so the normal cleanup path runs: pending notifications
    are flushed, the summary is printed and the metrics server is stopped. Returns a restore function.
    """

    def handler(signum: int, frame: object) -> None:
        flag.append(True)
        raise KeyboardInterrupt

    try:
        previous = signal.signal(signal.SIGTERM, handler)
    except (ValueError, OSError):  # not the main thread, or the platform has no SIGTERM
        return lambda: None

    def restore() -> None:
        signal.signal(signal.SIGTERM, previous)

    return restore


def _build_notifier(s: Settings) -> WebhookNotifier | None:
    if not s.webhook_url:
        return None
    cfg = WebhookConfig(
        url=resolve_env_ref(s.webhook_url),
        secret=secret_from_env(s.webhook_secret_env, DEFAULT_WEBHOOK_SECRET_ENV),
        kind=s.webhook_kind,
        events=frozenset(s.webhook_events),
        allow_private=s.webhook_allow_private,
        allow_http=s.webhook_allow_http,
        include_report=s.webhook_include_report,
        ca_bundle=s.ca_bundle,
    )
    return WebhookNotifier(cfg)


def _watch(s: Settings) -> int:
    """Watch mode. Events go to stdout (or are appended to ``--out``); chatter goes to stderr."""
    cfg = s.to_config()
    notifier: WebhookNotifier | None = None
    metrics: MetricsServer | None = None
    out_fh: TextIO | None = None
    try:
        watcher = Watcher(s.targets, cfg, interval=s.interval, heartbeat=s.heartbeat, confirm=s.confirm)
        notifier = _build_notifier(s)
        if s.metrics_port is not None:
            token = secret_from_env(s.metrics_token_env, DEFAULT_METRICS_TOKEN_ENV)
            n = notifier
            try:
                metrics = MetricsServer(
                    lambda: render_prometheus(
                        watcher.last_session,
                        runs=watcher.runs,
                        errors=watcher.errors,
                        last_success_ts=watcher.last_success_ts,
                        notifications=(n.sent, n.failed, n.dropped) if n else None,
                    ),
                    bind=s.metrics_bind,
                    port=s.metrics_port,
                    token=token,
                )
            except OSError as exc:
                raise SettingsError(
                    f"cannot start the metrics server on {s.metrics_bind}:{s.metrics_port}: {exc}"
                ) from exc
            metrics.start()
        if s.out:
            try:
                fd = open_private(s.out, os.O_WRONLY | os.O_APPEND | os.O_CREAT, parse_mode(s.out_mode))
                out_fh = os.fdopen(fd, "a", encoding="utf-8", newline="\n")
            except OSError as exc:
                raise SettingsError(f"cannot open {s.out}: {exc}") from exc
    except (SettingsError, ValueError) as exc:
        if notifier:
            notifier.close(1.0)
        if metrics:
            metrics.stop()
        print(f"netdoctor: error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        return _watch_loop(s, watcher, notifier, metrics, out_fh)
    finally:
        if out_fh is not None:  # closed on every path, including an unexpected exception
            out_fh.close()


def _watch_loop(
    s: Settings,
    watcher: Watcher,
    notifier: WebhookNotifier | None,
    metrics: MetricsServer | None,
    out_fh: TextIO | None,
) -> int:
    ascii_only = s.ascii or (out_fh is None and not _can_encode(sys.stdout, _SYMBOLS))
    color = out_fh is None and _use_color(s.color)
    stream = out_fh or sys.stdout

    def write(line: str) -> None:
        stream.write(line + "\n")
        stream.flush()

    def emit(event: WatchEvent) -> None:
        if s.format == "json":
            write(render_event_json(event))
        else:
            write(render_event_text(event, ascii_only=ascii_only, color=color))
        if notifier is not None:
            notifier.submit(event)

    extras = []
    if s.webhook_url:
        extras.append(f"notifying {redact_url(resolve_env_ref(s.webhook_url))}")
    if metrics:
        extras.append(f"metrics on {s.metrics_bind}:{metrics.port}")
    if s.out:
        extras.append(f"appending to {s.out}")
    print(
        f"netdoctor {__version__}: watching {len(watcher.targets)} target(s) every {watcher.interval:g}s"
        + "".join(f", {e}" for e in extras)
        + " (Ctrl-C to stop)",
        file=sys.stderr,
    )
    last = None
    interrupted = False
    terminated: list[bool] = []
    restore_sigterm = _install_sigterm(terminated)
    try:
        last = watcher.loop(emit, max_runs=s.max_runs, runner=run)
    except KeyboardInterrupt:
        interrupted = True
    except BrokenPipeError:  # e.g. `netdoctor --watch ... | head`
        with contextlib.suppress(Exception):
            sys.stdout.close()
        interrupted = True
    finally:
        restore_sigterm()
        # flush pending notifications first so the final state change is not lost
        if notifier is not None:
            notifier.close()
            if notifier.failed or notifier.dropped:
                print(
                    f"netdoctor: warning: {notifier.failed} notification(s) failed, {notifier.dropped} dropped",
                    file=sys.stderr,
                )
        if metrics is not None:
            metrics.stop()
    with contextlib.suppress(BrokenPipeError, ValueError, OSError):  # stdout/out file may already be closed
        summary = watcher.summary()
        write(render_event_json(summary) if s.format == "json" else render_summary_text(summary))
    if interrupted:
        return EXIT_TERMINATED if terminated else EXIT_INTERRUPTED
    return _EXIT_FOR[last.worst_status] if last else EXIT_FAILING
