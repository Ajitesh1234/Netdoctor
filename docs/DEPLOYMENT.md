# Deployment and operations guide

## Install

```bash
pipx install netdoctor-cli                    # once published to PyPI (see "Releases" below)
pipx install git+https://github.com/Ajitesh1234/Netdoctor.git      # from source today
pip install "netdoctor-cli[toml]"             # Python 3.9/3.10 only: TOML config files need tomli (3.11+ has tomllib)
```

**Offline / air-gapped:** build once (`python -m build`), copy the wheel, `pip install --no-index netdoctor_cli-*.whl`.
There are no runtime dependencies to mirror. Use `--no-dns-compare` so no third-party resolvers are contacted, and
`--ca-bundle` for an internal CA.

## Verify a release before you run it

Release assets carry a SHA-256 list and a Sigstore **build-provenance attestation** produced by the release workflow:

```bash
sha256sum -c SHA256SUMS
gh attestation verify netdoctor_cli-1.2.0-py3-none-any.whl --repo Ajitesh1234/Netdoctor
```

## One-shot checks (cron, CI, scripts)

```bash
netdoctor https://api.example.com --no-icmp -f json -o /var/log/netdoctor/api.json     # exit 0/1/3
netdoctor --config /etc/netdoctor/netdoctor.toml -f html -o /var/www/status/report.html
```

Exit codes: `0` healthy, `1` degraded, `2` usage error, `3` failing, `130` interrupted, `143` terminated.
Report files are written **atomically**, so collectors never read a half-written file.

### Prometheus without a daemon (node_exporter textfile collector)

```cron
* * * * * netdoctor --config /etc/netdoctor/netdoctor.toml -f prometheus -o /var/lib/node_exporter/textfile/netdoctor.prom
```

## Continuous monitoring (watch mode)

```bash
netdoctor --config /etc/netdoctor/netdoctor.toml --watch
```

Recommended settings for production: `confirm = 2` (a single dropped probe does not page anyone),
`interval` comfortably above `timeout`, a `heartbeat` so your log pipeline can prove the monitor is alive, and
`logging.format = "json"`.

### systemd

[`examples/netdoctor.service`](../examples/netdoctor.service) is a sandboxed unit (no new privileges, read-only
system, empty capability set, restricted address families). Secrets go in a root-owned `0600` `EnvironmentFile`,
never on the command line where `ps` would show them.

### Container

```bash
docker build -t netdoctor .
docker run -d --name netdoctor --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v /etc/netdoctor:/etc/netdoctor:ro --env-file /etc/netdoctor/secrets.env \
  netdoctor --config /etc/netdoctor/netdoctor.toml --watch
```

The image runs as an unprivileged user. ICMP needs `--cap-add NET_RAW`; without it NetDoctor reports the ping
check as "not run" and carries on (TCP-based latency, jitter and loss are always measured). `docker stop`
sends SIGTERM, which triggers a graceful shutdown: pending webhooks are flushed and a summary is printed.
Pin the base image by digest in your own build for reproducibility (Dependabot proposes updates).

### Kubernetes

[`examples/kubernetes.yaml`](../examples/kubernetes.yaml): non-root, read-only root filesystem, all capabilities
dropped, no service-account token, readiness/liveness probes on `/healthz`.

## Prometheus and alerting

Scrape `/metrics` (enable with `--metrics-port`; binds to `127.0.0.1` by default). Metric names are listed in
[METRICS.md](METRICS.md); ready-made rules are in [`examples/prometheus-alerts.yml`](../examples/prometheus-alerts.yml),
including **`NetDoctorMonitorStalled`**, which tells you when the monitor itself has stopped working, and
**`NetDoctorNotificationsFailing`**, which tells you when alerts are not reaching people.

If the endpoint is reachable by anyone other than Prometheus, set a bearer token (`NETDOCTOR_METRICS_TOKEN`) and
use `authorization: {credentials_file: ...}` in the scrape config, or terminate TLS in a reverse proxy.

## Webhooks

* The destination must resolve **only to public addresses** (SSRF protection). For a trusted internal receiver
  (for example `http://alerts.corp.internal`), opt in explicitly with `--webhook-allow-private` (and
  `--webhook-allow-http` if it is not HTTPS).
* Put the URL in an environment variable and reference it as `env:NAME`; the URL is a secret.
* Delivery is asynchronous with retries (exponential backoff, `Retry-After` honoured). A failing receiver never
  stops monitoring; the failure count is exported as `netdoctor_notifications_failed_total`.
* **Generic** webhooks are signed. Verify them like this (timestamp tolerance gives replay protection):

<!-- verifier:start -->
```python
import hashlib
import hmac
import time


def verify(secret: str, headers: dict, body: bytes, tolerance: int = 300) -> bool:
    """Return True only for an authentic, recent NetDoctor webhook."""
    try:
        timestamp = headers["X-NetDoctor-Timestamp"]
        supplied = headers["X-NetDoctor-Signature"]
        if abs(time.time() - int(timestamp)) > tolerance:
            return False  # too old (or from the future): possible replay
    except (KeyError, ValueError):
        return False
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return hmac.compare_digest("sha256=" + mac.hexdigest(), supplied)
```
<!-- verifier:end -->

* **Slack-format** webhooks (`--webhook-format slack`) cannot carry a signature; Slack authenticates by keeping the URL secret.

## SIEM / log ingestion

* `--watch --json` emits **JSON Lines** events (one object per line, each with `schema_version`).
* `--log-format json` emits operational logs the same way (`ts`, `level`, `logger`, `message`).
* Every one-shot JSON report carries a random `run_id` and an `environment` block for correlation.

## Releases and upgrades

Tag `vX.Y.Z` (the tag must equal `netdoctor.__version__`). The release workflow builds the sdist and wheel,
checks them, creates `SHA256SUMS`, signs a build-provenance attestation, and creates the GitHub Release. Publishing
to PyPI is opt-in: configure a **trusted publisher** for the `netdoctor-cli` project on PyPI (workflow `release.yml`,
environment `pypi`), then set the repository variable `PUBLISH_TO_PYPI=true`. No API token is stored anywhere.

Upgrade policy: JSON output is additive within a `schema_version`; breaking changes bump it and are listed in the
[CHANGELOG](../CHANGELOG.md).
