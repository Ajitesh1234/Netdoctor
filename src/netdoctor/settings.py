"""Effective settings: built-in defaults < config file < command-line flags.

The config file is TOML and is validated **strictly**: an unknown section or key is an error (with
a "did you mean" hint), never silently ignored. In a monitoring or security tool a setting that
quietly does not apply is worse than a loud failure.

Secrets are never read from the file by value where avoidable: use ``env:NAME`` references
(``url = "env:NETDOCTOR_WEBHOOK_URL"``) and ``*_env`` keys.
"""

from __future__ import annotations

import difflib
import logging
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import Config

log = logging.getLogger(__name__)

MAX_CONFIG_BYTES = 1_048_576
FORMATS = ("text", "markdown", "json", "html", "prometheus")
WATCH_FORMATS = ("text", "json")
WATCH_ONLY = frozenset(
    {
        "interval", "max_runs", "heartbeat", "confirm", "webhook_url", "webhook_kind", "webhook_events",
        "webhook_secret_env", "webhook_allow_private", "webhook_allow_http", "webhook_include_report",
        "metrics_port", "metrics_bind", "metrics_token_env",
    }
)  # fmt: skip
DEFAULT_DOH = ("https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query")
DEFAULT_WEBHOOK_SECRET_ENV = "NETDOCTOR_WEBHOOK_SECRET"  # noqa: S105  # nosec B105 - an env var *name*, not a secret
DEFAULT_METRICS_TOKEN_ENV = "NETDOCTOR_METRICS_TOKEN"  # noqa: S105  # nosec B105 - an env var *name*, not a secret
DEFAULT_EVENTS = ("change", "recovered", "error")
DEFAULT_OUT_MODE = "600"


class SettingsError(ValueError):
    """Invalid configuration (file, flags or environment)."""


@dataclass
class Settings:
    targets: list[str] = field(default_factory=list)
    # output
    format: str = "text"
    out: str | None = None
    out_mode: str = DEFAULT_OUT_MODE
    color: str = "auto"
    ascii: bool = False
    # logging
    verbose: int = 0
    log_format: str = "text"
    log_file: str | None = None
    # checks
    timeout: float = Config.timeout
    samples: int = Config.samples
    workers: int = Config.workers
    icmp: bool = Config.icmp
    traceroute: bool = Config.traceroute
    dns_compare: bool = Config.dns_compare
    resolvers: tuple[str, ...] = Config.resolvers
    doh_servers: tuple[str, ...] = ()
    ca_bundle: str | None = None
    max_redirects: int = Config.max_redirects
    # thresholds
    latency_warn_ms: float = Config.latency_warn_ms
    jitter_warn_ms: float = Config.jitter_warn_ms
    ttfb_warn_ms: float = Config.ttfb_warn_ms
    dns_warn_ms: float = Config.dns_warn_ms
    cert_expiry_warn_days: int = Config.cert_expiry_warn_days
    # watch
    watch: bool = False
    interval: float = 30.0
    max_runs: int | None = None
    heartbeat: float = 0.0
    confirm: int = 1
    # webhook
    webhook_url: str | None = None
    webhook_kind: str = "generic"
    webhook_events: tuple[str, ...] = DEFAULT_EVENTS
    webhook_secret_env: str | None = None
    webhook_allow_private: bool = False
    webhook_allow_http: bool = False
    webhook_include_report: bool = False
    # metrics
    metrics_port: int | None = None
    metrics_bind: str = "127.0.0.1"
    metrics_token_env: str | None = None
    # bookkeeping
    explicit: set[str] = field(default_factory=set)
    """Names of settings set by the config file or flags (not just defaults)."""
    cli_explicit: set[str] = field(default_factory=set)
    """Names of settings given as command-line flags (a config file may legitimately hold watch-only
    keys for a shared one-shot/watch setup, but a stray ``--interval`` flag is a mistake)."""

    def to_config(self) -> Config:
        return Config(
            timeout=self.timeout,
            samples=self.samples,
            workers=self.workers,
            max_redirects=self.max_redirects,
            icmp=self.icmp,
            traceroute=self.traceroute,
            dns_compare=self.dns_compare,
            resolvers=self.resolvers,
            doh_servers=self.doh_servers,
            ca_bundle=self.ca_bundle,
            latency_warn_ms=self.latency_warn_ms,
            jitter_warn_ms=self.jitter_warn_ms,
            ttfb_warn_ms=self.ttfb_warn_ms,
            dns_warn_ms=self.dns_warn_ms,
            cert_expiry_warn_days=self.cert_expiry_warn_days,
        )

    def redacted(self) -> dict[str, Any]:
        """Settings as plain data, safe to print (inline webhook URLs hold secret tokens)."""
        data = {f: getattr(self, f) for f in self.__dataclass_fields__ if f not in ("explicit", "cli_explicit")}
        url = self.webhook_url
        if url and not url.startswith("env:"):
            data["webhook_url"] = "<redacted inline URL>"
        for key, value in data.items():
            if isinstance(value, tuple):
                data[key] = list(value)
        return data


# --------------------------------------------------------------------------- validators
Validator = Callable[[str, Any], Any]


def _bool(key: str, v: Any) -> bool:
    if not isinstance(v, bool):
        raise SettingsError(f"{key}: expected true or false, got {v!r}")
    return v


def _int(key: str, v: Any) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise SettingsError(f"{key}: expected an integer, got {v!r}")
    return v


def _num(key: str, v: Any) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise SettingsError(f"{key}: expected a number, got {v!r}")
    return float(v)


def _str(key: str, v: Any) -> str:
    if not isinstance(v, str) or not v.strip():
        raise SettingsError(f"{key}: expected a non-empty string, got {v!r}")
    return v


def _strs(key: str, v: Any) -> tuple[str, ...]:
    if not isinstance(v, list) or not all(isinstance(i, str) and i.strip() for i in v):
        raise SettingsError(f"{key}: expected a list of non-empty strings")
    return tuple(v)


def parse_mode(value: str) -> int:
    """``"640"`` -> ``0o640``. Only plain permission bits; world-writable modes are refused."""
    text = str(value).strip()
    if not re.fullmatch(r"0?[0-7]{3}", text):
        raise SettingsError(f"file mode must be 3 octal digits such as 600, 640 or 644 (got {value!r})")
    mode = int(text, 8)
    if mode & 0o002:
        raise SettingsError(f"refusing world-writable report mode {text}: other users could tamper with the report")
    return mode


def _mode(key: str, v: Any) -> str:
    if not isinstance(v, str):  # NOT int: TOML turns 0o640 into 416, which would be misread as "416"
        raise SettingsError(f'{key}: expected a quoted octal string such as "640", got {v!r}')
    parse_mode(v)
    return v.strip()


def _choice(options: tuple[str, ...]) -> Validator:
    def check(key: str, v: Any) -> str:
        if v not in options:
            raise SettingsError(f"{key}: must be one of {', '.join(options)} (got {v!r})")
        return str(v)

    return check


SCHEMA: dict[str, dict[str, tuple[str, Validator]]] = {
    "checks": {
        "timeout": ("timeout", _num),
        "samples": ("samples", _int),
        "workers": ("workers", _int),
        "icmp": ("icmp", _bool),
        "traceroute": ("traceroute", _bool),
        "dns_compare": ("dns_compare", _bool),
        "resolvers": ("resolvers", _strs),
        "doh_servers": ("doh_servers", _strs),
        "ca_bundle": ("ca_bundle", _str),
        "max_redirects": ("max_redirects", _int),
    },
    "thresholds": {
        "latency_warn_ms": ("latency_warn_ms", _num),
        "jitter_warn_ms": ("jitter_warn_ms", _num),
        "ttfb_warn_ms": ("ttfb_warn_ms", _num),
        "dns_warn_ms": ("dns_warn_ms", _num),
        "cert_expiry_warn_days": ("cert_expiry_warn_days", _int),
    },
    "output": {
        "format": ("format", _choice(FORMATS)),
        "color": ("color", _choice(("auto", "always", "never"))),
        "ascii": ("ascii", _bool),
        "file": ("out", _str),
        "mode": ("out_mode", _mode),
    },
    "logging": {
        "verbose": ("verbose", _int),
        "format": ("log_format", _choice(("text", "json"))),
        "file": ("log_file", _str),
    },
    "watch": {
        "enabled": ("watch", _bool),
        "interval": ("interval", _num),
        "max_runs": ("max_runs", _int),
        "heartbeat": ("heartbeat", _num),
        "confirm": ("confirm", _int),
    },
    "webhook": {
        "url": ("webhook_url", _str),
        "kind": ("webhook_kind", _choice(("generic", "slack"))),
        "events": ("webhook_events", _strs),
        "secret_env": ("webhook_secret_env", _str),
        "allow_private": ("webhook_allow_private", _bool),
        "allow_http": ("webhook_allow_http", _bool),
        "include_report": ("webhook_include_report", _bool),
    },
    "metrics": {
        "port": ("metrics_port", _int),
        "bind": ("metrics_bind", _str),
        "token_env": ("metrics_token_env", _str),
    },
}
_PATH_FIELDS = {"ca_bundle", "out", "log_file"}


def _unknown(kind: str, name: str, valid: list[str]) -> SettingsError:
    hint = difflib.get_close_matches(name, valid, n=1)
    return SettingsError(
        f"unknown {kind} {name!r}"
        + (f" (did you mean {hint[0]!r}?)" if hint else f"; valid: {', '.join(sorted(valid))}")
    )


# --------------------------------------------------------------------------- file loading
def _toml_loads(text: str) -> dict[str, Any]:
    try:
        import tomllib  # novermin - guarded: Python < 3.11 falls back to the tomli package
    except ModuleNotFoundError:
        try:
            import tomli as tomllib  # type: ignore[import-not-found,no-redef,unused-ignore]
        except ModuleNotFoundError as exc:
            raise SettingsError(
                "reading a TOML config file needs Python 3.11+ or the 'tomli' package (pip install 'netdoctor[toml]')"
            ) from exc
    try:
        return dict(tomllib.loads(text))
    except tomllib.TOMLDecodeError as exc:
        raise SettingsError(f"invalid TOML: {exc}") from exc


def load_file(path: str) -> tuple[dict[str, Any], Path]:
    """Read and parse a config file. Returns ``(data, base_directory)``."""
    p = Path(path)
    try:
        size = p.stat().st_size
        if size > MAX_CONFIG_BYTES:
            raise SettingsError(f"config file is too large ({size} bytes; limit {MAX_CONFIG_BYTES})")
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise SettingsError(f"cannot read config file {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise SettingsError(f"config file {path} is not valid UTF-8") from exc
    return _toml_loads(text), p.resolve().parent


def apply_file(settings: Settings, data: Mapping[str, Any], base_dir: Path, *, path: str = "") -> None:
    """Merge validated file ``data`` into ``settings``. Unknown keys raise :class:`SettingsError`."""
    valid_top = ["targets", *SCHEMA]
    for name in data:
        if name not in valid_top:
            raise _unknown("section", name, valid_top)
    if "targets" in data:
        settings.targets = list(_strs("targets", data["targets"]))
    for section, body in SCHEMA.items():
        if section not in data:
            continue
        values = data[section]
        if not isinstance(values, dict):
            raise SettingsError(f"[{section}] must be a table")
        for key, raw in values.items():
            if key not in body:
                raise _unknown(f"key in [{section}]", key, list(body))
            attr, validate = body[key]
            value = validate(f"{section}.{key}", raw)
            if attr in _PATH_FIELDS and not os.path.isabs(value):
                value = str(base_dir / value)
            setattr(settings, attr, value)
            settings.explicit.add(attr)
    _warn_if_world_readable(settings, path)


def _warn_if_world_readable(settings: Settings, path: str) -> None:
    url = settings.webhook_url
    if not path or not url or url.startswith("env:") or os.name != "posix":
        return
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        log.warning(
            "config file %s holds an inline webhook URL (a secret) but is accessible to other users; chmod 600 it", path
        )


# --------------------------------------------------------------------------- CLI flags
def apply_args(settings: Settings, args: Any) -> None:
    """Overlay explicitly-given command-line flags (``None`` means "not given")."""

    def put(attr: str, value: Any) -> None:
        if value is not None:
            setattr(settings, attr, value)
            settings.explicit.add(attr)
            settings.cli_explicit.add(attr)

    cli_targets = [*(args.targets or []), *(args.sites or [])]
    if cli_targets:
        settings.targets = cli_targets
    if args.json:
        put("format", "json")
    else:
        put("format", args.format)
    for attr in (
        "out", "out_mode", "color", "timeout", "samples", "workers", "ca_bundle", "interval", "max_runs", "heartbeat", "confirm",
        "log_format", "log_file", "metrics_port", "metrics_bind", "metrics_token_env", "webhook_kind", "webhook_secret_env",
    ):  # fmt: skip
        put(attr, getattr(args, attr, None))
    put("icmp", args.icmp)
    put("dns_compare", args.dns_compare)
    put("traceroute", args.traceroute)
    put("watch", True if args.watch else None)
    put("ascii", True if args.ascii else None)
    put("verbose", args.verbose)
    if args.resolver:
        put("resolvers", tuple(args.resolver))
    doh = list(args.doh_server or [])
    if args.doh:
        doh = [*DEFAULT_DOH, *doh]
    if doh:
        put("doh_servers", tuple(dict.fromkeys(doh)))
    put("webhook_url", args.webhook)
    if args.notify_on:
        put("webhook_events", tuple(e.strip() for e in args.notify_on.split(",") if e.strip()))
    put("webhook_allow_private", True if args.webhook_allow_private else None)
    put("webhook_allow_http", True if args.webhook_allow_http else None)
    put("webhook_include_report", True if args.webhook_include_report else None)


def resolve_env_ref(value: str, environ: Mapping[str, str] | None = None) -> str:
    """``env:NAME`` -> the value of environment variable ``NAME`` (must be set and non-empty)."""
    env = os.environ if environ is None else environ
    if not value.startswith("env:"):
        return value
    name = value[4:].strip()
    got = env.get(name, "")
    if not got:
        raise SettingsError(f"environment variable {name} is not set (referenced as {value!r})")
    return got


def secret_from_env(name: str | None, default_name: str, environ: Mapping[str, str] | None = None) -> str | None:
    """Return the secret in env var ``name`` (explicit: must exist) or ``default_name`` (optional)."""
    env = os.environ if environ is None else environ
    if name:
        got = env.get(name, "")
        if not got:
            raise SettingsError(f"environment variable {name} is not set")
        return got
    return env.get(default_name) or None
