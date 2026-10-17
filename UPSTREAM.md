# UPSTREAM.md — provenance & attribution

## What this project is

**Paqet-NGV2** is a derivative of [hanselime/paqet](https://github.com/hanselime/paqet), itself an active raw-packet proxy that tunnels traffic inside raw TCP packets (KCP + smux, optional obfuscation, SOCKS5/port-forward data plane).

Upstream license: **MIT** — Copyright (c) 2025 hanselime. The full license text is preserved verbatim in [`LICENSE`](LICENSE) and applies to **all** inherited code. This project's modifications are distributed under the same MIT terms.

## Authorship split

| Component | Origin |
| --- | --- |
| Raw TCP packet capture/injection (`internal/socket`), KCP + smux transport (`internal/tnet`), obfuscation (`internal/obfs`), SOCKS5 + port forwarding (`internal/socks`, `internal/forward`), baseline client/server, YAML config + validation (`internal/conf`), `run/ping/dump/secret/version` CLI | **upstream Paqet** (largely unchanged code) |
| Emergency DNS control plane (`internal/ng/transport/dns_emergency.go`, `cmd/emergency`), resolver scanner (`internal/ng/dns`) | **Paqet-NGV2** (research forks of the ideas in the source development branch — see below) |
| Asymmetric session crypto (v3 PAQC / v4 PAQD / v4.1) with per-server secrets, authorized-server sets, replay windows + domain sealing (`internal/ng/crypto`, `internal/ng/replay`, `asymmetric.go`) | **Paqet-NGV2** |
| Recovery state machine, selector, connection-identity continuity, bootstrap candidate advertisement/validation | **Paqet-NGV2** |
| Extended failure-laboratory / red-team test suites (`phase18*`–`phase20*`) | **Paqet-NGV2** |

No claim is made that the entire codebase was independently written by Paqet-NGV2 contributors. The upstream base is the majority of the data plane.

## Development lineage

- Source development repository: `https://github.com/arashmh13/paqet` (a public fork of the upstream for development purposes).
- Development branch: `research/hard-mode-rnd`.
- The snapshot this repository was seeded from corresponds to commit **`04724db`** of that branch, whose own lineage descends from the upstream repository.
- Upstream comparison point: the fork point and subsequent upstream history (`https://github.com/hanselime/paqet`).

> **Publication note:** the source branch carries an extensive internal research audit trail (`docs/research/*` and operational run records) describing live infrastructure and experiments. Those documents were deliberately **not** carried into this public repository — for context, approach, architecture, and higher-level research documentation, see the Paqet-NGV2 docs in [`docs/`](docs/) and the public source repository above.

## How to compare with upstream

```bash
git clone https://github.com/hanselime/paqet                       # upstream base
git clone https://github.com/arashmh13/paqet-ngv2                  # this project
# inspect the additions:
diff -u <upstream>/internal/conf            <ngv2>/internal/conf
diff -u <upstream>/cmd                      <ngv2>/cmd        # + emergency CLI
ls <ngv2>/internal/ng                                                        # Paqet-NGV2-only packages
```

## License

MIT, same as upstream. See [`LICENSE`](LICENSE); upstream copyright notice preserved.
