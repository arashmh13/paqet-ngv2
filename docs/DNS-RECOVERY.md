# DNS emergency recovery plane

Purpose, implementation references and testing status. **Do not confuse this emergency signaling channel with the bulk data plane** — it is a low-bandwidth, authenticated signaling channel over ordinary DNS.

## What it is

Layer 2 of the project: an authenticated message exchange carried inside normal DNS traffic between any recursive resolver on the client side and the `paqet emergency server` authoritative responder. It solves one narrow problem: *how do I receive new, pinned tunnel coordinates when the tunnel itself is down and I have no other channel?*

Implementation: `internal/ng/transport/dns_emergency.go` (transport), `asymmetric.go` (crypto), `internal/ng/dns` (resolver scan tooling), `cmd/emergency` (CLI).

## Message flow

1. **Fragment:** the client JSON payload (`EmergencyMessage`) is AEAD-sealed, framed (protocol v3/v4, [PROTOCOLS.md](PROTOCOLS.md)) and split into ≤250-byte DNS-safe labels.
2. **Egress:** a recursive DNS query is built (QNAME encoding and/or TXT), EDNS0 sizing negotiated, then dispatch to the next resolver in the fallback list; retries are bounded per attempt (`PerAttemptTimeout`, `MaxRetries`).
3. **Authoritative side:** the `emergency server` answers either:
   - a small **status/AUTHCFGPROBE** payload, or
   - an authenticated **bootstrap response** carrying candidate endpoint records (JSON `{server_ip, transport_port, transport_mode, identity_type, identity_value, validity_sec, request_id, …}`).
4. **Client verification:** response tag authenticated with the per-server response key; the replay-domain window is consulted; identity pins are validated (`SHA256:<hex>`); validity windows must be strictly future (`ValidUntil <= now` ⇒ expired); then the candidate is accepted into the recovery state machine.

## Authentication / encryption

- AES-256-GCM over every fragment; DNS is only a container.
- v4+ uses per-session seeds and per-server-session base keys ([PROTOCOLS.md](PROTOCOLS.md)); v3 is the currently default server generation.
- Replay state is per `(serverID, server-session base)` and capped at 32 domains per connection; exceeding capacity **seals the session** rather than silently evicting history ([PROTOCOLS.md#replay-defense](PROTOCOLS.md)).

## Limits (measured/realistic)

- **Throughput:** this is a *signaling* channel: tens of bytes per query response. Bulk payload transfer is impractical by construction.
- **Resolvers:** any recursive resolver must route the delegated child zone to :53 of the emergency host — `paqet emergency scan` probes whether a resolver passes the needed query formats.
- **Opacity:** DNS payloads are DNS-shaped; no other data types are tunneled.

## How to test it yourself

Loopback check from [docs/TESTING.md](TESTING.md) is reproducible anywhere:

```bash
./bin/paqet emergency server --addr 127.0.0.1:5399 --domain test.tunnel.paqet-ngv2.example \
  --key-file /etc/paqet/transport.key --legacy-single-server --disable-bootstrap &
./bin/paqet emergency send --resolver 127.0.0.1:5399 --domain test.tunnel.paqet-ngv2.example \
  --key-file /etc/paqet/transport.key --legacy-single-server --message "PING-1"
```

Wrong-credential (fail-closed) probe: run `send` with a *different* `key-file` and observe the explicit error (never a silent success).

## Honest scope

- Proven (tests + isolated staging): message exchange, credential fail-closed behavior, restart replay isolation, resolver scanning, fragment retry behavior.
- **Not demonstrated:** surviving loss of the authoritative DNS host itself, or live fire on a fully blocked network. Those require infrastructure this repository does not assemble; deploy only after reading [DEPLOYMENT.md](DEPLOYMENT.md) and [SECURITY.md](SECURITY.md).
