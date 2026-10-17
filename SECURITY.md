# Security policy

## Supported versions

This repo publishes source only; run from the `main` branch tip or pin to a tagged release once tags exist. Older development-branch snapshots (pre-v4.1) have known interopeability and credential-posture issues and are not supported here.

## Reporting a vulnerability

**Do not file a public issue for an unpatched vulnerability.**

Use GitHub's *Report a security vulnerability* flow (the "Private vulnerability reporting" feature under **Security → Advisories**), which reaches the maintainer directly. If that feature is unavailable to your account, open an issue containing only the words "security report" and no technical detail; the maintainer will open a private channel.

Please include:
- affected commit/tag/branch,
- minimal repro (commands + sanitized config),
- impact hypothesis.

We will acknowledge as soon as possible, keep credit for reporters by default, and publish an advisory after a fix lands.

## Scope

- All code under `internal/ng/` (crypto, replay, transport), `cmd/emergency`, plus the raw-packet data plane.
- Out of scope: vulnerabilities in the Go toolchain, libpcap/Npcap, or the OS; CI infrastructure.

## Relationship to formal audits

This project's own test suites are **not** a formal cryptographic audit. Protocols v3/v4/v4.1 have been fuzzed/bench-tested by their author and reviewed phase-by-phase in the internal research log, but no external auditor has assessed them. See [docs/SECURITY.md](docs/SECURITY.md).
