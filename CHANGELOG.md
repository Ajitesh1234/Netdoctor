# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/),
and the project follows [Semantic Versioning](https://semver.org/). JSON output is versioned separately
via `schema_version`.

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
