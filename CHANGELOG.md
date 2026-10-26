# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/),
and the project follows [Semantic Versioning](https://semver.org/). JSON output is versioned separately
via `schema_version`.

## [1.2.0] - 2026-10-23

Hardening and integration release: security review artefacts, alerting, metrics, richer DNS checks and a signed release pipeline.

### Added
- **DNS**: AAAA (IPv6) answers compared per family; optional **DNS-over-HTTPS** (RFC 8484) cross-check (`--doh`, `--doh-server`);
  new finding `DNS_TAMPERING_SUSPECTED` when plain and encrypted DNS disagree.
- **Webhooks** for watch mode (`--webhook`, `--webhook-format generic|slack`, `--notify-on`): HMAC-SHA256 signed, **SSRF-protected**
  (public destinations only, DNS-rebinding-resistant IP pinning, no redirects, HTTPS required), retried with backoff, non-blocking.
- **Prometheus metrics**: `-f prometheus` (textfile collector) and `--metrics-port` (loopback by default, optional bearer token) with
  monitor-health metrics; ready-made alert rules.
- **HTML report** (`-f html`): self-contained, accessible, no JavaScript, strict CSP, light/dark/print styles.
- **Config file** (`--config`, TOML) with strict validation, `env:` secret references and `--print-config`.
- **Flap damping** (`--confirm N`) for watch mode; JSON logs (`--log-format json`, `--log-file`); `run_id` and `environment` in reports.
- **Graceful shutdown**: SIGTERM (exit 143) flushes pending notifications and prints the summary, like Ctrl-C (exit 130).
- Atomic report-file writes; target-count cap (500); contextual I/O error messages.
- `docs/` (threat model, deployment guide, generated CLI/configuration/metrics references, kept in sync by tests) and `examples/`
  (annotated config, hardened systemd unit, Kubernetes manifest, Prometheus alerts).
- Supply chain: SHA-pinned GitHub Actions, `bandit` + `pip-audit` + CodeQL in CI, release workflow with Sigstore build-provenance
  attestation, SHA-256 sums and opt-in PyPI trusted publishing; hardened Dockerfile.

### Changed
- The PyPI distribution is named **`netdoctor-cli`** (the name `netdoctor` is taken by an unrelated project). The command and the
  import package remain `netdoctor`.
- Shipped code no longer uses `assert` (it is stripped under `python -O`); every `bandit` suppression is justified inline.
- CLI options default to "unset" so a config file can supply them; flags always win. A watch-only flag without `--watch` is a usage error.

### Fixed
- Atomic report writes no longer change the process-wide umask (not thread-safe) or call `chmod`: the temporary file is
  created with `O_CREAT | O_EXCL` so the kernel applies the umask atomically.
- A file descriptor was leaked when stdout was closed early (`| head`); the `--watch` output file is now closed on every path.
- A queue-overflow race in the webhook notifier no longer swallows the condition silently (logged at debug level).
- The metrics server could share its port with another process on Windows (`SO_REUSEADDR`); it no longer does.
- Console output no longer crashes on legacy code pages (non-encodable symbols degrade).

## [1.1.0] - 2026-10-23

### Added
- **Watch mode** (`-w/--watch`, `--interval`, `--max-runs`, `--heartbeat`): re-runs diagnostics on an interval and
  reports only state changes (`initial`, `change`, `recovered`, `heartbeat`, `error`) with how long each state lasted,
  plus an availability summary on exit. `--json` emits JSON Lines events that include the full report.
  Library API: `netdoctor.Watcher`, `WatchEvent`, `WatchSummary`.
- `--ca-bundle PEM` / `Config.ca_bundle`: verify TLS against a custom CA bundle (corporate proxies, private CAs).

### Fixed
- Test suite failed on Windows: TLS tests relied on `SSL_CERT_FILE` (ignored by CPython on Windows),
  closed-port tests used timeouts shorter than Windows' ~2 s connection-refused delay, one test hit the
  real internet, and TLS tests required an `openssl` binary. Tests now generate their certificate in
  Python, pass the CA explicitly, and use portable timeouts.
- Dependabot no longer raises minimum versions of Python dev tools (could break Python 3.9 support).

## [1.0.0] - 2026-10-22

Complete rewrite. The 0.1.0 prototype could not be installed or run as documented
(see "Fixed"); 1.0.0 is a ground-up, tested implementation.

### Added
- Installable `src/` package with `netdoctor` console script and `python -m netdoctor`.
- DNS cross-check against public resolvers using raw UDP (distinguishes "domain doesn't exist"
  from "blocked by your resolver"); sinkhole and resolver-mismatch detection.
- Real TCP latency / jitter / loss statistics, per port **and** per IP family (detects broken IPv6).
- TLS verification with classified failures, certificate expiry and SNI-interference detection.
- HTTP probing with manual redirect handling, per-hop timing and HTTPS→HTTP fallback detection.
- Parsed ICMP results (Linux, macOS, BSD, Windows); optional traceroute (`--traceroute`).
- Root-cause analysis engine with severities, stable finding codes and actionable hints.
- Text, Markdown and JSON output (`schema_version: 1`); `--format`, `--out`, `--color`, `--ascii`.
- Concurrency across targets and checks; hard timeouts on every operation.
- CI exit codes (0 healthy, 1 degraded, 2 usage, 3 failing).
- Test suite (no internet required), ruff, `mypy --strict`, CI matrix, Dockerfile.

### Changed
- Python requirement raised from 3.7 (EOL) to **3.9+**.
- Zero runtime dependencies (the prototype imported `requests` but declared none).
- `--json` is now a shortcut for `--format json`; `--sites` remains as an alias for positional targets.

### Fixed
- Package was uninstallable/unrunnable: modules lived at the repo root, so `find_packages()`
  found nothing and `python -m netdoctor.main` failed with `ModuleNotFoundError`.
- TCP latency was fabricated (`timeout * 100`); it is now measured.
- Ping output was never parsed, so diagnosis reported a bogus "Latency looks normal (0.0 ms)".
- README promised packet-loss, jitter and DNS-tampering detection that did not exist.
- Hostnames starting with `-` could be passed to `ping`/`traceroute` as options (argument injection).
- Missing timeouts on `ping`/`traceroute` and `getaddrinfo` could hang indefinitely.
- Default `--out` behaviour and Windows `cp1252` crashes on emoji output.
