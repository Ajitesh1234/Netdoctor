"""Generate docs/CONFIGURATION.md and docs/METRICS.md from the source of truth.

python scripts/gen_docs.py            # rewrite the files
python scripts/gen_docs.py --check    # exit 1 if they are stale (also enforced by tests/test_docs.py)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from netdoctor import settings as cfg  # noqa: E402
from netdoctor.metrics import render_prometheus  # noqa: E402
from netdoctor.models import (  # noqa: E402
    DnsResult,
    Finding,
    HttpResult,
    IcmpResult,
    SessionReport,
    Severity,
    Status,
    TargetReport,
    TcpResult,
    TlsResult,
)

FLAGS = {
    "checks.timeout": "--timeout", "checks.samples": "--samples", "checks.workers": "--workers",
    "checks.icmp": "--icmp / --no-icmp", "checks.traceroute": "--traceroute / --no-traceroute",
    "checks.dns_compare": "--dns-compare / --no-dns-compare", "checks.resolvers": "--resolver (repeatable)",
    "checks.doh_servers": "--doh, --doh-server (repeatable)", "checks.ca_bundle": "--ca-bundle",
    "checks.max_redirects": "", "output.format": "-f / --format, --json", "output.color": "--color",
    "output.ascii": "--ascii", "output.file": "-o / --out", "logging.verbose": "-v / -vv",
    "logging.format": "--log-format", "logging.file": "--log-file", "watch.enabled": "-w / --watch",
    "watch.interval": "--interval", "watch.max_runs": "--max-runs", "watch.heartbeat": "--heartbeat",
    "watch.confirm": "--confirm", "webhook.url": "--webhook", "webhook.kind": "--webhook-format",
    "webhook.events": "--notify-on", "webhook.secret_env": "--webhook-secret-env",
    "webhook.allow_private": "--webhook-allow-private", "webhook.allow_http": "--webhook-allow-http",
    "webhook.include_report": "--webhook-include-report", "metrics.port": "--metrics-port",
    "metrics.bind": "--metrics-bind", "metrics.token_env": "--metrics-token-env",
    "thresholds.latency_warn_ms": "", "thresholds.jitter_warn_ms": "", "thresholds.ttfb_warn_ms": "",
    "thresholds.dns_warn_ms": "", "thresholds.cert_expiry_warn_days": "",
}  # fmt: skip

DOCS = {
    "checks.timeout": "Timeout in seconds for every individual network operation.",
    "checks.samples": "TCP connect (and ICMP) samples per endpoint, 1-50. More samples give better jitter and loss estimates.",
    "checks.workers": "Targets diagnosed in parallel, 1-32.",
    "checks.icmp": "Run the system `ping` as a secondary cross-check.",
    "checks.traceroute": "Also run traceroute (slow).",
    "checks.dns_compare": "Cross-check DNS against public resolvers. `false` disables **all** third-party lookups (UDP and DoH).",
    "checks.resolvers": "Public UDP resolvers (IP addresses) for the cross-check.",
    "checks.doh_servers": "RFC 8484 DNS-over-HTTPS endpoints (`https://` URLs) for an encrypted cross-check.",
    "checks.ca_bundle": "PEM file of trusted CAs used *instead of* the system store (corporate TLS inspection). Relative paths resolve against the config file.",
    "checks.max_redirects": "Maximum HTTP redirects followed (0-20).",
    "thresholds.latency_warn_ms": "TCP connect latency above this raises `HIGH_LATENCY`.",
    "thresholds.jitter_warn_ms": "Jitter above this raises `HIGH_JITTER`.",
    "thresholds.ttfb_warn_ms": "Time to first byte above this raises `SLOW_RESPONSE`.",
    "thresholds.dns_warn_ms": "System DNS lookup time above this raises `DNS_SLOW`.",
    "thresholds.cert_expiry_warn_days": "Certificates expiring within this many days raise `TLS_EXPIRING_SOON`.",
    "output.format": "Report format. Watch mode supports `text` and `json` (JSON Lines).",
    "output.color": "ANSI colour in text output (`NO_COLOR` is honoured).",
    "output.ascii": "ASCII symbols instead of Unicode.",
    "output.file": "Write the report here (atomically; appended in watch mode). Relative paths resolve against the config file.",
    "logging.verbose": "0 = warnings, 1 = info, 2 = debug.",
    "logging.format": "`json` emits one JSON object per log line, for SIEM ingestion.",
    "logging.file": "Append logs to this file instead of stderr.",
    "watch.enabled": "Behave as `--watch`. Other `[watch]`, `[webhook]` and `[metrics]` keys are ignored in one-shot runs.",
    "watch.interval": "Seconds between runs (minimum 1). Pick a value comfortably above `timeout`.",
    "watch.max_runs": "Stop after N runs (default: until interrupted).",
    "watch.heartbeat": "Emit a `heartbeat` event for unchanged targets every N seconds (0 = off).",
    "watch.confirm": "Report a change only after N consecutive sightings (flap damping, 1-20).",
    "webhook.url": "Destination `https://` URL, or `env:NAME` to read it from an environment variable. **The URL is a secret** (e.g. Slack tokens); prefer `env:`.",
    "webhook.kind": "`generic` (signed JSON) or `slack` (Slack-compatible text; also works with Mattermost).",
    "webhook.events": "Which events to send: `initial`, `change`, `recovered`, `heartbeat`, `error`.",
    "webhook.secret_env": "Name of the environment variable holding the HMAC-SHA256 signing key. If omitted, `NETDOCTOR_WEBHOOK_SECRET` is used when set.",
    "webhook.allow_private": "Permit private/loopback/link-local destinations. **Disables SSRF protection.**",
    "webhook.allow_http": "Permit plain `http://` destinations.",
    "webhook.include_report": "Include the full per-target report in generic payloads.",
    "metrics.port": "Serve Prometheus metrics at `/metrics` (and `/healthz`) on this port in watch mode. `0` picks a free port.",
    "metrics.bind": "Address to bind. Non-loopback addresses without a token trigger a warning.",
    "metrics.token_env": "Name of the environment variable holding a bearer token. If omitted, `NETDOCTOR_METRICS_TOKEN` is used when set.",
}  # fmt: skip

_TYPE = {
    cfg._bool: "boolean",
    cfg._int: "integer",
    cfg._num: "number",
    cfg._str: "string",
    cfg._strs: "list of strings",
}


def _type_name(validator: object) -> str:
    if validator in _TYPE:
        return _TYPE[validator]  # type: ignore[index]
    options = validator.__closure__[0].cell_contents  # type: ignore[attr-defined]
    return "one of " + ", ".join(f"`{o}`" for o in options)


def _default(value: object) -> str:
    if value is None or value == () or value == "":
        return "*(unset)*"
    if isinstance(value, bool):
        return "`true`" if value else "`false`"
    if isinstance(value, tuple):
        return "`[" + ", ".join(f'"{v}"' for v in value) + "]`"
    return f"`{value:g}`" if isinstance(value, float) else f"`{value}`"


def configuration_md() -> str:
    defaults = cfg.Settings()
    out = [
        "# Configuration reference",
        "",
        "<!-- GENERATED by scripts/gen_docs.py from netdoctor.settings; do not edit by hand. -->",
        "",
        "NetDoctor reads an optional TOML file (`--config FILE`). **Precedence:** built-in defaults < config file < command-line flags.",
        "",
        '- **Strict:** an unknown section or key is an error, with a "did you mean" hint. Nothing is silently ignored.',
        "- **Secrets:** use `env:NAME` references and `*_env` keys instead of putting secrets in the file. If a file holds an inline webhook URL and is readable by other users, NetDoctor logs a warning.",
        "- **Shared files:** `[watch]`, `[webhook]` and `[metrics]` keys are inert in one-shot runs, so one file serves both a cron job and the monitor. (A watch-only *flag* without `--watch` is an error.)",
        "- `targets = [...]` at the top level lists targets; targets given on the command line replace them.",
        "- Check the result with `netdoctor --config FILE --print-config` (inline webhook URLs are redacted).",
        "",
        "See [`examples/netdoctor.toml`](../examples/netdoctor.toml) for a complete annotated file.",
        "",
    ]
    for section, body in cfg.SCHEMA.items():
        out += [
            f"## `[{section}]`",
            "",
            "| Key | Type | Default | CLI flag | Description |",
            "| --- | --- | --- | --- | --- |",
        ]
        for key, (attr, validator) in body.items():
            full = f"{section}.{key}"
            flag = f"`{FLAGS[full]}`" if FLAGS[full] else ""
            out.append(
                f"| `{key}` | {_type_name(validator)} | {_default(getattr(defaults, attr))} | {flag} | {DOCS[full]} |"
            )
        out.append("")
    return "\n".join(out)


def _sample_session() -> SessionReport:
    rep = TargetReport(
        "example.com",
        "example.com",
        dns=DnsResult(True, ["93.184.216.34"], 12.0),
        tcp=[TcpResult(443, "93.184.216.34", "ipv4", 5, 5, 0.0, 10, 12, 15, 1)],
        tls=TlsResult(True, version="TLSv1.3", days_to_expiry=60, handshake_ms=20),
        http=HttpResult(True, "https", "https://example.com/", 200, "OK", 10, 80.0, 100),
        icmp=IcmpResult(True, sent=5, received=5, loss_pct=0.0, avg_ms=11.0),
        findings=[Finding(Severity.WARNING, "HIGH_LATENCY", "m")],
        status=Status.DEGRADED,
        duration_ms=1000,
    )
    return SessionReport("x", "now", [rep])


def metrics_md() -> str:
    text = render_prometheus(_sample_session(), runs=1, errors=0, last_success_ts=1.0, notifications=(0, 0, 0))
    help_, kind, labels = {}, {}, {}
    for line in text.splitlines():
        if line.startswith("# HELP "):
            _, _, name, desc = line.split(" ", 3)
            help_[name] = desc
        elif line.startswith("# TYPE "):
            _, _, name, k = line.split(" ", 3)
            kind[name] = k
        else:
            m = re.match(r"([a-z_:]+)(?:\{(.*)\})?\s", line)
            if m and m[2]:
                labels.setdefault(m[1], list(re.findall(r'(\w+)="', m[2])))
    out = [
        "# Metrics reference",
        "",
        "<!-- GENERATED by scripts/gen_docs.py from netdoctor.metrics; do not edit by hand. -->",
        "",
        "Exposed in the Prometheus text format (version 0.0.4) by `netdoctor --watch --metrics-port PORT` at `/metrics`,",
        "and written once per run by `netdoctor -f prometheus` (suitable for the node_exporter *textfile collector*).",
        "Durations are in **seconds** and shares are **ratios (0..1)**, following Prometheus conventions.",
        "Series are only exported for checks that actually ran.",
        "",
        "| Metric | Type | Labels | Description |",
        "| --- | --- | --- | --- |",
    ]
    for name in help_:
        lab = ", ".join(f"`{x}`" for x in labels.get(name, [])) or "*(none)*"
        out.append(f"| `{name}` | {kind[name]} | {lab} | {help_[name]} |")
    out += ["", "Ready-made alert rules: [`examples/prometheus-alerts.yml`](../examples/prometheus-alerts.yml).", ""]
    return "\n".join(out)


def cli_md() -> str:
    import argparse

    from netdoctor.cli import build_parser

    parser = build_parser()
    out = [
        "# Command-line reference",
        "",
        "<!-- GENERATED by scripts/gen_docs.py from netdoctor.cli; do not edit by hand. -->",
        "",
        "```text",
        "netdoctor [TARGET ...] [options]",
        "```",
        "",
        "`TARGET` is `host`, `host:port`, an IP literal, or an `http(s)://` URL. At most 500 targets per run.",
        "Without a scheme NetDoctor tries HTTPS first and reports whether it had to fall back to HTTP.",
        "Any option below can also be set in a [config file](CONFIGURATION.md); flags win over the file.",
        "",
        "**Exit codes:** `0` healthy, `1` degraded, `2` usage error, `3` failing, `130` interrupted (Ctrl-C), `143` terminated (SIGTERM).",
        "",
    ]

    def rows(actions: list) -> list[str]:
        lines = ["| Option | Argument | Description |", "| --- | --- | --- |"]
        for a in actions:
            if not a.option_strings or isinstance(a, argparse._HelpAction):
                continue
            flags = ", ".join(f"`{o}`" for o in a.option_strings)
            arg = ""
            if a.choices:
                arg = " \\| ".join(f"`{c}`" for c in a.choices)
            elif a.metavar:
                arg = f"`{a.metavar}`"
            desc = (a.help or "").replace("|", "\\|").replace("%(default)s", "")
            lines.append(f"| {flags} | {arg} | {desc} |")
        return lines

    own = [a for a in parser._actions if not any(a in g._group_actions for g in parser._action_groups[2:])]
    out += ["## General", "", *rows(own), ""]
    for g in parser._action_groups[2:]:
        out += (
            [f"## {g.title[:1].upper() + g.title[1:]}", ""]
            + ([g.description, ""] if g.description else [])
            + rows(g._group_actions)
            + [""]
        )
    return "\n".join(out)


FILES = {"docs/CONFIGURATION.md": configuration_md, "docs/METRICS.md": metrics_md, "docs/CLI.md": cli_md}


def main(argv: list[str]) -> int:
    stale = []
    for rel, fn in FILES.items():
        path, text = ROOT / rel, fn()
        if "--check" in argv:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                stale.append(rel)
        else:
            path.parent.mkdir(exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
            print("wrote", rel)
    if stale:
        print("stale (run: python scripts/gen_docs.py):", ", ".join(stale))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
