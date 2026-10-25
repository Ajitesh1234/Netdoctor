# Threat model

This document states what NetDoctor defends against, how, and **what it does not**. Every control below
links to the automated test that exercises it (`tests/test_docs.py` fails if a referenced test is renamed
or removed). It is a description of design intent plus evidence, **not** a third-party audit or certification.

## 1. What NetDoctor is

A diagnostic CLI and library. It makes outbound network requests to targets you name, to public DNS
resolvers (optional), and to a webhook you configure (optional). It has **no inbound surface** except the
optional watch-mode metrics endpoint. It stores nothing, phones home nowhere, and has **zero runtime
dependencies** (Python standard library only), so there is no third-party code in the runtime to audit.

### Data that leaves the machine
| Destination | Data | When |
| --- | --- | --- |
| Each target | DNS lookups, TCP/TLS handshakes, one HTTP `GET` (`User-Agent: netdoctor/<version>`; the body is never downloaded) | always |
| Public resolvers (default `1.1.1.1`, `8.8.8.8`) | the **hostnames** you check | unless `--no-dns-compare` |
| DoH servers | the hostnames you check | only with `--doh` / `doh_servers` |
| Webhook receiver | event JSON (finding messages; the full report only with `include_report`) | only if a webhook is configured |

`--no-dns-compare` disables **all** third-party lookups (UDP and DoH) for air-gapped or sensitive environments.

## 2. Trust boundaries and assets

* **Untrusted input:** command-line targets, config-file contents, every byte received from the network
  (DNS replies, TLS certificates, HTTP headers, webhook responses), and target-controlled strings that end
  up in reports.
* **Assets:** the webhook URL (often a bearer secret), the webhook signing key, the metrics token, the
  integrity of monitoring signals (a false "healthy" is the worst outcome), and host availability.
* **Attackers considered:** a remote server or on-path attacker controlling responses; a malicious or careless
  operator supplying hostile targets/config; a local unprivileged user on the same host; a compromised
  dependency or CI action (supply chain).

## 3. Threats and controls

| # | Threat | Control | Evidence |
| --- | --- | --- | --- |
| T1 | **Option / command injection** into `ping`/`traceroute` via a crafted hostname | Strict target parser (no leading `-`, whitespace, control chars, credentials, bad ports); external binaries run with argument lists, never a shell, and receive only validated IP literals | `tests/test_target.py::test_rejected`, `tests/test_report_cli.py::test_cli_rejects_bad_targets_without_traffic` |
| T2 | **Malformed or hostile DNS packets** (crash, hang, memory) | Bounds-checked wire parser that never follows compression pointers; fuzz-tested | `tests/test_dns.py::test_parser_never_crashes_on_random_bytes`, `tests/test_dns.py::test_parser_never_crashes_on_mutated_valid_packets`, `tests/test_dns.py::test_parser_never_follows_compression_pointers` |
| T3 | **Hostile DoH server** (oversized or wrong-type response, bad TLS) | TLS verified (TLS 1.2+), 64 KiB response cap, content-type check | `tests/test_dns.py::test_doh_bad_server_behaviour_is_a_failure_not_a_crash`, `tests/test_dns.py::test_doh_requires_valid_tls` |
| T4 | **TLS impersonation** of a target | Full certificate and hostname verification; certificate problems are classified, never ignored; there is no `--insecure` flag | `tests/test_checks.py::test_tls_untrusted_self_signed`, `tests/test_checks.py::test_tls_ip_literal_is_verified_against_ip_san` |
| T5 | **SSRF through the webhook URL** (reaching internal services or cloud metadata) | Destination must resolve **only** to globally routable addresses (loopback, RFC 1918, link-local incl. 169.254.169.254, CGNAT, NAT64, multicast refused; one private answer poisons the set); explicit opt-out flag | `tests/test_notify.py::test_ssrf_policy_is_enforced_before_any_connection`, `tests/test_notify.py::test_is_public_ip`, `tests/test_notify.py::test_one_private_answer_poisons_the_whole_set` |
| T6 | **DNS rebinding** between the safety check and the connection | Resolve once, then pin the connection to the validated address(es) (tried in order, so a broken IP family does not break delivery) while verifying the certificate against the original hostname | `tests/test_notify.py::test_dns_is_resolved_once_and_the_connection_is_pinned` |
| T7 | **Redirect-based SSRF** | Webhook redirects are never followed | `tests/test_notify.py::test_status_classification_and_no_redirect_following` |
| T8 | **Forged or replayed webhooks** at the receiver | HMAC-SHA256 over `timestamp.body` with a timestamp header; verification example in `docs/DEPLOYMENT.md` | `tests/test_notify.py::test_signature_depends_on_secret_timestamp_and_body`, `tests/test_docs.py::test_the_documented_webhook_verifier_accepts_real_signatures_and_rejects_forgeries` |
| T9 | **Secret leakage** (logs, process list, reports, config dumps) | URLs logged only as `scheme://host/...`; secrets come from environment variables, never flags; `--print-config` redacts inline URLs; warning if a config file with an inline webhook URL is readable by other users | `tests/test_notify.py::test_redact_url_hides_path_and_token`, `tests/test_cli_features.py::test_webhook_receives_a_signed_event_before_the_process_exits`, `tests/test_settings.py::test_redacted_never_shows_inline_webhook_urls`, `tests/test_settings.py::test_warns_when_an_inline_webhook_url_sits_in_a_world_readable_file` |
| T10 | **Silent misconfiguration** (a typo disabling a safeguard) | Config file is validated strictly: unknown keys and wrong types are errors, with hints | `tests/test_settings.py::test_unknown_key_is_an_error_with_a_hint`, `tests/test_cli_features.py::test_a_typo_in_the_config_file_fails_loudly` |
| T11 | **Unauthorised access to metrics** | Binds to loopback by default; optional bearer token compared in constant time; `GET` only; per-connection timeout; warning when exposed without a token | `tests/test_metrics.py::test_bearer_token_protects_metrics_but_not_healthz`, `tests/test_metrics.py::test_only_get_is_allowed`, `tests/test_metrics.py::test_warns_when_exposed_without_a_token` |
| T12 | **Metric/label injection** via hostile target names | Label values fully escaped; output validated against the exposition grammar | `tests/test_metrics.py::test_hostile_target_names_cannot_break_the_format` |
| T13 | **XSS / content injection** in the HTML report | Every dynamic value HTML-escaped; no JavaScript; `default-src 'none'` CSP; output parsed for balanced markup | `tests/test_htmlreport.py::test_hostile_input_is_escaped_everywhere`, `tests/test_htmlreport.py::test_document_is_well_formed_and_self_contained` |
| T14 | **Torn or partial report files** read by collectors | Atomic write (temp file, fsync, rename) | `tests/test_settings.py::test_atomic_write_failure_keeps_the_old_file_and_cleans_up` |
| T15 | **Resource exhaustion** | Hard timeouts on every operation (including DNS); bounded thread pools; target-count cap (500); bounded notification queue that drops the oldest | `tests/test_settings.py::test_target_count_is_capped`, `tests/test_notify.py::test_queue_overflow_drops_oldest_and_keeps_newest`, `tests/test_dns.py::test_missing_aaaa_does_not_fail_the_answer` |
| T16 | **Monitor dies silently** / alert fatigue | One bad cycle or notification never stops monitoring; graceful SIGTERM/SIGINT flushes pending alerts; flap damping (`--confirm`); `netdoctor_last_success_timestamp_seconds` lets you alert on a stalled monitor | `tests/test_watch.py::test_loop_survives_a_crashing_cycle`, `tests/test_notify.py::test_worker_survives_a_crashing_transport`, `tests/test_watch_cli.py::test_real_signals_shut_down_gracefully_and_flush_the_final_notification`, `tests/test_watch.py::test_single_blip_never_alerts` |
| T17 | **Supply-chain compromise** | No runtime dependencies; CI actions pinned to commit SHAs; `bandit`, `pip-audit` and CodeQL gate CI; releases carry a Sigstore build-provenance attestation and published SHA-256 sums; PyPI publishing uses OIDC trusted publishing (no stored token) | CI workflows in `.github/workflows/` |

## 4. Known limitations and residual risk

* **Findings are heuristics.** CDN geo-DNS, bot protection and filtered ICMP all have innocent explanations;
  findings are worded accordingly. A diagnosis is evidence, not proof. Do not use a single run as forensic evidence.
* **A hostile local network can still block, delay or degrade probes.** NetDoctor detects many such
  conditions, but a determined on-path adversary can make *every* channel (system DNS, UDP, DoH, TCP) lie
  consistently. Compare from an independent network.
* **Reports are not signed.** `run_id` and timestamps help correlation, not non-repudiation. Sign or hash
  archived reports in your own pipeline if you need integrity guarantees.
* **The metrics endpoint has no TLS.** Use the bearer token on trusted networks, or a TLS-terminating reverse proxy.
* **Same-user local attackers** can read the process environment (and so the secrets in it). Run as a dedicated
  unprivileged user; use the provided hardened systemd unit or container settings.
* **`ping`/`traceroute` are the system binaries** and are only as trustworthy as the host. Both are optional.
* **The webhook secret is a shared key.** Rotate it by changing the environment variable and restarting.
* **TLS inspection proxies** make certificates look untrusted. Use `--ca-bundle` to trust your corporate CA explicitly.
* **No third-party security audit or penetration test has been performed.** If you need one for your
  environment, commission it; this document should make that cheaper.

## 5. What is *not* claimed

NetDoctor is **not** certified or accredited under FedRAMP, Common Criteria, FIPS 140, SOC 2, ISO 27001 or any
similar scheme, and makes no such claim. It performs no cryptography beyond HMAC-SHA256 (`hashlib`/`hmac`) and
TLS via the Python/OpenSSL build on the host. Whether that is acceptable for your environment is your
organisation's decision; this repository aims to give your reviewers what they need to make it.
