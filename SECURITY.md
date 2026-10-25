# Security Policy

## Supported versions

Only the latest release line (currently 1.2.x) receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's
["Report a vulnerability"](https://github.com/Ajitesh1234/Netdoctor/security/advisories/new) (private advisory) on this repository.
Include a description, reproduction steps and affected versions. This is a small, maintainer-run project: expect an
acknowledgement within a few business days, and a coordinated fix and disclosure timeline agreed with you in the advisory.
Good-faith research is welcome; please avoid testing against systems you do not own.

## What is in scope

Anything that lets untrusted input (a hostile target, DNS/TLS/HTTP response, config file or webhook receiver) cause code execution, option
injection, SSRF, secret disclosure, resource exhaustion, or a **false "healthy"** result; flaws in the webhook signing, the metrics endpoint, the
HTML report escaping, or the release pipeline's integrity guarantees.

## How releases are protected

* No third-party runtime dependencies (standard library only).
* CI actions are pinned to commit SHAs; workflows use least-privilege `permissions`; `bandit`, `pip-audit` and CodeQL gate changes.
* Releases include a `SHA256SUMS` file and a Sigstore **build-provenance attestation**
  (`gh attestation verify <file> --repo Ajitesh1234/Netdoctor`); PyPI publishing, when enabled, uses OIDC trusted publishing (no stored token).

## Design documentation

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for assets, trust boundaries, each control with the test that exercises it, known limitations,
and what is explicitly **not** claimed. NetDoctor has not been independently audited and holds no compliance certification.
