# Configuration reference

Every entry below is derived from the current parsers (`internal/conf/conf.go`, `internal/ng/transport/dns_emergency.go`, `cmd/emergency/*.go`) and was cross-checked against `--help` output during this migration. If an option is not here, it does not exist in this tree anymore.

Conventions: **C** = client-only, **S** = server-only, **B** = both. Placeholder values are always used in examples. Keys live in files, never on command lines, whenever a `*key-file` variant exists.

## 1. `paqet run` YAML configuration (`-c/--config`, default `config.yaml`)

The authoritative, fully commented fixture set is [`example/client.yaml.example`](../example/client.yaml.example) and [`example/server.yaml.example`](../example/server.yaml.example). The table is the semantic reference; the fixtures remain the copy-paste source.

### Root + logging

| Key | Type | Req | Default | Values/Range | Side | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `role` | string | yes | — | `client`, `server` | both | validated; anything else fails at load |
| `log.level` | string | no | `info` | none, debug, info, warn, error, fatal | both | production: use `info` or above |

### Client-side endpoints

| Key | Type | Req | Default | Values/Range | Side | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `server.addr` | string | C | — | `host:port` | C | the tunnel server's address+port |
| `socks5[]` | list | C | — | see below | C | local proxy listeners |
| `socks5[].listen` | string | C | — | `ip:port` | C | bind on loopback in normal use (`127.0.0.1:1080`) |
| `socks5[].username` / `.password` | string | C | `""`/`""` | any | C | optional SOCKS5 auth; store per your policy |
| `forward[]` | list | C | — | `.listen`, `.target`, `.protocol` (`tcp`/`udp`) | C | optional port-forwarding alongside/instead of SOCKS5 |

### Server-side endpoints

| Key | Type | Req | Default | Values/Range | Side | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `listen.addr` | string | S | — | `:port` | S | **must** equal the port component of `network.ipv4.addr`; upstream guidance: avoid 80/443 because NOTRACK/RST rules can interfere with other services |

### Network (raw-packet plane)

| Key | Type | Req | Default | Values/Range | Side | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `network.interface` | string | yes (raw modes) | — | OS interface name | both | e.g. `eth0`, `en0` |
| `network.guid` | string | no | — | NPF device id | both | Windows/Npcap alternative to interface name |
| `network.ipv4.addr` | string | yes (raw modes) | — | `ip:port` | both | local packet source addr; server port must match `listen.addr` |
| `network.ipv4.router_mac` | string | yes (raw modes) | — | MAC address | both | default gateway MAC — **not** the peer's MAC |
| `network.ipv6.addr` / `.router_mac` | string | no | — | `"[2001:db8::1]:0"` / MAC | both | optional IPv6 plane |
| `network.tcp.local_flag` / `.remote_flag` | []string | no | `["PA"]` | TCP flag names | both | keep symmetric unless you know why not |
| `network.pcap.sockbuf` | int | no | 4 MB client / 8 MB server | bytes | both | raise for high-throughput lossy paths |

### Transport

| Key | Type | Req | Default | Values/Range | Side | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `transport.protocol` | string | yes | `kcp` | `kcp`, `raw-kcp`, `asymmetric-spoof` | both | raw modes require pcap privileges |
| `transport.conn` | int | no | 1 | 1–256 | both | number of parallel raw connections |
| `transport.kcp.key` | string | yes | — | any secret string | both | **must match on both peers**; prefer a long random hex; stored in the YAML file, so protect its permissions |
| `transport.kcp.mode` | string | no | `fast` | normal, fast, fast2, fast3, manual | both | manual exposes the tuning knobs below |
| `transport.kcp.block` | string | no | `aes` | see list in example (`aes`, `aes-128-gcm`, `salsa20`, `none`, …) | both | stream cipher for KCP payload |
| `transport.kcp.mtu` | int | no | 1350 | 50–1500 | both | keep below path MTU 2× for encapsulation |
| `transport.kcp.rcvwnd` / `.sndwnd` | int | no | 512/128 (C), 1024/1024 (S) | packets | both | window sizes |
| `transport.kcp.nodelay` | int | manual | 1 | 0/1 | both | aggressive retransmit toggle |
| `transport.kcp.interval` | int | no | 10 | 10–5000 ms | both | lower = more responsive + more CPU |
| `transport.kcp.resend` | int | no | 2? | 0–2 | both | fast-retransmit aggressiveness |
| `transport.kcp.nocongestion` | int | no | 0 | 0/1 | both | 1 disables congestion control |
| `transport.kcp.wdelay` | bool | no | `false` | | both | write batching |
| `transport.kcp.acknodelay` | bool | no | `true` | | both | immediate ACKs |
| `transport.kcp.smuxbuf` / `.streambuf` | int | no | 4 MB / 2 MB | bytes | both | smux buffers |
| `transport.kcp.smuxkalive` / `.smuxktimeout` | int | no | 2 / 8 s | | both | keepalive |
| `transport.obfs.enabled` | bool | no | `true` | | both | randomizes packet lengths to blunt DPI fingerprinting |
| `transport.obfs.key` | string | no | `transport.kcp.key` | | both | independent obfuscation key if desired |
| `transport.obfs.maxpad` | int | no | 64 | 0–512 | both | padding window |
| `dshard` / `pshard` | int | no | disabled | — | both | FEC — currently disabled upstream feature |

## 2. Emergency control plane CLI

### `paqet emergency server` (authoritative responder)

| Flag | Type | Req | Default | Notes |
| --- | --- | --- | --- | --- |
| `--addr` | string | no | `:53` | UDP+TCP listen; <1024 needs `CAP_NET_BIND_SERVICE` |
| `--domain` | string | no | `tunnel.paqet-ngv2.example` | delegated child-zone suffix; **set explicitly** |
| `--key-file` | string | yes (non-legacy) | — | 32-byte shared PSK file (hex/base64/raw) |
| `--key` | string | discouraged | — | inline key; prefer `--key-file` or env `PAQET_EMERGENCY_KEY` to avoid argv exposure |
| `--legacy-single-server` | bool | no | off | single-server PSK-only legacy mode; mutually exclusive with multi-server flags |
| `--server-id` | string | multi-server | — | canonical identity (`[a-z0-9._-]{3,64}`; `default`/`legacy` reserved) |
| `--server-secret-file` | string | multi-server | — | dedicated 32-byte response secret **file**; symlinks rejected, ≤0640 perms required, exactly 32 bytes |
| `--protocol-v4` | bool | no | off | v4 "PAQD" framing (per-session seed + per-server-session nonce/key base) |
| `--disable-bootstrap` | bool | no | — | messaging-only: emits no bootstrap candidates (fail-closed default state) |
| `--bootstrap-ip` / `--bootstrap-port` / `--bootstrap-mode` | | conditional | —端口 `18089`, mode `aead-stream` | candidate advertisement when bootstrap is enabled |
| `--bootstrap-key-file` / `--bootstrap-cert` | string | conditional | — | fingerprint source (`SHA256:<hex>` pins) |
| `--bootstrap-pin` | string | no | — | explicit pin overriding computed fingerprint |
| `--bootstrap-config` | string | no | — | JSON file of multiple candidates (see fixture) |

Validation highlights (implemented in `dns_emergency.go`): port range checks, strict mode whitelist (`raw-kcp`, `aead-stream`, `tls-outer`, `tls-stream`), strictly-future `valid_until` expiry (`ValidUntil == now` ⇒ expired).

### `paqet emergency send` (client/query)

| Flag | Type | Req | Default | Notes |
| --- | --- | --- | --- | --- |
| `--resolver` | string | no | `8.8.8.8:53` | any recursive resolver `ip[:port]` |
| `--domain` | string | no | placeholder | must match the server |
| `--key-file` | string | yes (non-legacy) | — | shared PSK |
| `--legacy-single-server` | bool | no | off | legacy mode |
| `--server-id` + `--server-secret-file` | | convenience | — | single named server |
| `--authorized-servers-config` | string | multi-server | — | JSON: `version`(=1), `protocol`(`"v4"`), `generation`, `authorized_servers[{server_id, secret_file}]`; parser rejects inline secrets, missing/short files, symlinked files, dupes, reserved IDs, **and any ambiguous flag combination** |
| `--protocol-v4` (send) | — use config | | | protocol selection comes from `authorized-servers-config` (`protocol: "v4"`) |
| `--client-id` | string | no | `c01` | max 4 chars |
| `-m/--message` | string | no | `EMERGENCY_PING` | application payload |
| `--timeout` | int | no | 5 | seconds |

> Env var `PAQET_EMERGENCY_KEY` — alternative to `--key`; only used when the inline flag is absent.

### `paqet emergency scan`

`--cache` (default `/tmp/resolver_cache.json`), `--domain`, `--resolvers` (CSV), `--timeout` (sec). Probes candidate resolvers for the ability to carry the delegated zone (electric DNS tunnel checks) and writes a cache file — keep the default path off multi-user systems or point it at a private directory.

## 3. Other subcommands

- `paqet secret` — prints a fresh random 32-byte hex key. nothing else.
- `paqet version`, `paqet ping [--config, --payload]`, `paqet dump [--config]` — as `--help` output.

## 4. Environment variables

| Var | Purpose |
| --- | --- |
| `PAQET_EMERGENCY_KEY` | inline shared-key alternative for the emergency plane |

No other environment variables are consumed by the binary.

## 5. Compatibility notes

- The `--authorized-servers-config` file is strict: `version` **must** be `1`, `protocol` **must** be `"v4"`, list must be non-empty, each `secret_file` must resolve to exactly 32 bytes.
- Flag equivalence: `--legacy-single-server` ↔ `--server-id/--server-secret-file` ↔ `--authorized-servers-config` are **three mutually exclusive selection modes** (multi-authoritative builds reject mixtures at construction).
- Duplicated instructions deliberately live only here and in the fixture comments; other docs link back.
