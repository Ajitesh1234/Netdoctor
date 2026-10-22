# Security Policy

## Supported versions

Only the latest 1.x release receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's
["Report a vulnerability"](https://github.com/Ajitesh1234/netdoctor/security/advisories/new) (private advisory) on this repository.
Include a description, reproduction steps and affected versions. You can expect an acknowledgement within
a few days.

## Scope & design notes

- Targets are strictly validated (`netdoctor.target`) before any network activity. Hostnames cannot start
  with `-`, contain whitespace/control characters, or embed credentials.
- External binaries (`ping`, `traceroute`/`tracert`) are launched with argument lists (never a shell) and
  receive only validated IP literals, which prevents command and option injection.
- NetDoctor makes outbound connections to user-supplied targets by design. If you embed it in a service
  that accepts targets from untrusted users, add egress controls to prevent SSRF against internal networks.
- No telemetry is collected.
