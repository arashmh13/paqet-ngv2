# Paqet-NGV2

An experimental multi-transport resilience and authenticated DNS recovery layer built around Paqet's raw-packet proxy.

[![Go](https://img.shields.io/badge/go-1.27%2B-00ADD8)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)
[![CI](https://github.com/arashmh13/paqet-ngv2/actions/workflows/ci.yml/badge.svg)](https://github.com/arashmh13/paqet-ngv2/actions/workflows/ci.yml)

> [!WARNING]
> **Experimental research project.** Paqet-NGV2 is a derivative of [hanselime/paqet](https://github.com/hanselime/paqet) (MIT). The base packet tunnel is mature for its scope; the resilience, DNS-recovery and v4 cryptography layers added here are **not** independently audited and are **not** proven to bypass any specific filtering system. See [docs/SECURITY.md](docs/SECURITY.md) and [UPSTREAM.md](UPSTREAM.md).

## What problem does this solve?

A raw-packet proxy that exposes a single static endpoint has one failure domain: if that endpoint's IP is blocked, the tunnel is dead until new coordinates can be arranged *out of band*. Paqet-NGV2 adds an authenticated **emergency control plane spoken over ordinary recursive DNS**: an operator's client can receive new, cryptographically pinned server coordinates (bootstrap candidates) without a separate channel — plus stricter per-server credentialing, protocol-versioned wire framing, and deterministic replay defenses around those signals.

It does **not** currently include independently hosted recovery infrastructure, so it cannot (and does not claim to) survive loss of *every* authoritative server's IP.

## Relationship to upstream Paqet

- **Inherited** (upstream [hanselime/paqet](https://github.com/hanselime/paqet), MIT): raw-packet capture/injection, KCP + smux transport, obfuscation, SOCKS5 / port-forward data plane, YAML configuration, `run` / `ping` / `dump` / `secret` CLI commands.
- **Added in Paqet-NGV2:** emergency DNS control plane (`paqet emergency server|send|scan`), asymmetric session framing (v3 "PAQC", v4 "PAQD", v4.1), mandatory per-server credentials, authorized-server sets, bootstrap candidate advertisement/validation, an explicit recovery state machine, replay-window and replay-domain defenses, and failure-laboratory test suites.
- Provenance details: [UPSTREAM.md](UPSTREAM.md). Compatibility notes: [CHANGELOG.md](CHANGELOG.md).

## Feature status (evidence-based)

| Feature | Status | Evidence |
| --- | --- | --- |
| Raw TCP packet capture/injection, KCP+smux tunneling (upstream) | 1. Implemented, unit-tested | loopback tests in `internal/socket`, `internal/tnet/kcp`, `internal/obfs` |
| SOCKS5 / port-forward data plane | 1. Implemented, unit-tested | `internal/socks`, `internal/forward`, loopback integration tests |
| YAML config loading + validation | 1. Implemented, unit-tested | `internal/conf` validation tests |
| Authenticated DNS emergency exchange (v3 AES-GCM via DNS records) | 1.+2. unit + loopback e2e tested | `internal/ng/transport/dns_emergency.go` and test suites |
| Resolver scan (`paqet emergency scan`) | 1. Implemented, unit-tested | `internal/ng/dns/scanner_test.go` |
| v3 "PAQC" asymmetric sessions (dedicated per-server secrets, fail-closed) | 1.+2. unit + loopback e2e | phase18/19 suite |
| v4 "PAQD" / v4.1 per-session seed + per-server-session nonce/key base | 1. unit-tested, 2. loopback e2e, 3. isolated staging on separate hosts | `phase19_*`, `phase20_*` test suites |
| Multi-server authorized-servers config (CLI loader) | 1. unit-tested through the real CLI path | `cmd/emergency/phase19_client_config_test.go`, `phase20_cli_rotation_test.go` |
| Replay-after-restart isolation + replay-domain sealing | 1. unit-tested incl. concurrency (`-race`) | `internal/ng/transport/phase20_replay_domain_capacity_test.go` |
| Bootstrap candidate advertisement / client-side validation | 1. unit-tested (validation layers) | `dns_edns_truncation_test.go`, bootstrap validators |
| Recovery state machine + failover routing | 2. integration-tested on loopback | `recovery_state_machine_test.go`, `recovery_selector_integration_test.go` |
| Full-path resilience vs. loss of *all* authoritative IPs | 6. not demonstrated | requires independently hosted recovery infrastructure |
| v4 production deployment | **not attempted** | migration preflight awaits operator maintenance window |

Status legend: 1 = implemented & unit-tested, 2 = tested end-to-end in a controlled environment, 3 = tested on staging infrastructure, 4 = verified in production, 5 = experimental/partial, 6 = planned. Nothing in this project is status 4.

## Architecture overview

One binary (`paqet`), two planes:

- **Data plane** — raw TCP packets are crafted and captured via pcap (bypassing the kernel's connection tracking), carrying KCP+smux streams, optionally AES-GCM sealed and obfuscated on the wire, terminated locally by a SOCKS5 proxy or port-forward rules.
- **Control/emergency plane** — ordinary DNS queries to *any* recursive resolver carry AES-GCM-encrypted message fragments inside QNAME/TXT records; the authoritative emergency server (subcommand `paqet emergency server`, listens on :53 UDP/TCP) decrypts, checks credentials/replay windows and answers with authenticated status payloads or bootstrap candidate coordinates.

Details and diagrams: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Supported / tested platforms

- **Linux (amd64, incl. WSL2)** — full test suite runs here; deployment documented for systemd. Raw capture requires privileges (see below).
- **Windows 10/11** — code and build supported (upstream lineage + Npcap); CI runs on Ubuntu only at present.
- **macOS** — upstream supports it via BPF; **not tested by this project** — treat as unverified.

## Dependencies

Go 1.27+ (module directive `go 1.27`), [gopacket](https://github.com/gopacket/gopacket) (needs libpcap/Npcap **at runtime**), [kcp-go v5](https://github.com/xtaci/kcp-go), [smux](https://github.com/xtaci/smux), [cobra](https://github.com/spf13/cobra), [goccy/go-yaml](https://github.com/goccy/go-yaml), golang.org/x/crypto, golang.org/x/net. Exact pins: [go.mod](go.mod).

## Quick start

```bash
git clone https://github.com/arashmh13/paqet-ngv2
cd paqet-ngv2
go build -o bin/paqet ./cmd

# generate a random 32-byte shared key (client and server must share it)
./bin/paqet secret
```

Full walkthrough — a minimal tunnel first, then the optional emergency layer: [docs/QUICKSTART.md](docs/QUICKSTART.md).
Platform prerequisites and privileges: [docs/INSTALLATION.md](docs/INSTALLATION.md).

## Documentation

| Document | Contents |
| --- | --- |
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | prerequisites, build, service user, capabilities |
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | minimal tunnel, then the emergency DNS layer |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | full YAML/CLI reference |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | source tree, data/control planes, recovery state machine |
| [docs/PROTOCOLS.md](docs/PROTOCOLS.md) | wire format per generation, compatibility matrix, collision bounds |
| [docs/DNS-RECOVERY.md](docs/DNS-RECOVERY.md) | emergency channel design and trust model |
| [docs/SECURITY.md](docs/SECURITY.md) | threat model, credential hygiene, logging policy |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | systemd units and hardening |
| [docs/TESTING.md](docs/TESTING.md) | test taxonomy and exact commands |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | real failure modes, in order of likelihood |
| [UPSTREAM.md](UPSTREAM.md) | provenance, attribution, authorship split |
| [docs/PUBLICATION-AUDIT.md](docs/PUBLICATION-AUDIT.md) | exactly how this repository was created, what was excluded and why |
| [CHANGELOG.md](CHANGELOG.md) | changes relative to the source development branch |
| [SECURITY.md](SECURITY.md) | how to report a vulnerability |

## Build & test

```bash
gofmt -l .                  # expect empty output
go vet ./...
go test -count=1 ./...
go test -race ./...         # slower
go build -o bin/paqet ./cmd
```

CI runs exactly these checks (plus `-race` on Ubuntu): [.github/workflows/ci.yml](.github/workflows/ci.yml).

## Security summary (tl;dr)

- The wire protocol and crypto are custom ⇒ **do not treat this as production-secure without an independent cryptographic review.**
- Response credentials are symmetric: a client authorized for server X can forge authenticated responses *as X* to other clients (explicit, documented limitation).
- Replay defenses (per-domain windows, capacity-based session sealing, restart-isolated key basing) are implemented and tested; all collision bounds are probabilistic and published in [docs/PROTOCOLS.md](docs/PROTOCOLS.md).
- Credential hygiene (0600 files, no symlinks, exactly 32 bytes, never log key material): [docs/SECURITY.md](docs/SECURITY.md).

## Compatibility warning

Protocol generations **v2 ("PAQA") / v3 ("PAQC") / v4 ("PAQD") / v4.1 (server-session base bound into the KDF salt) are not mutually compatible** — peers must agree explicitly. v4.1 candidates are also incompatible with the earlier Phase-19-era v4 candidate (`v2.5.11-sesssalt`). The full compatibility matrix: [docs/PROTOCOLS.md](docs/PROTOCOLS.md).

## Current limitations

- Recovery adapts to blocked *candidate transport endpoints*; it does not survive loss of the authoritative resolver/zone itself.
- `data` emergency messages have no exactly-once semantics (idempotency policy: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)).
- DNS fragments are small (~250 bytes each); signaling is bounded, and bulk payload transfer over DNS is impractical by design.
- Windows/macOS deployment paths are untested in this fork — contributions welcome ([CONTRIBUTING.md](CONTRIBUTING.md)).
