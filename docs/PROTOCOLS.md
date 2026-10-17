# Protocols & wire compatibility

> **This document describes a custom research protocol.** It has not received an independent cryptographic review. Probabilistic bounds are labeled as bounds — they are not protocol invariants.

## Protocol generations

| Name | Magic | Status | Keying | Nonce domain | Introduced |
| --- | --- | --- | --- | --- | --- |
| v2 "PAQA" | `0x50415141` | legacy/disabled by default | PSK only | `sessionID‖seq` | upstream lineage |
| v3 "PAQC" | `0x50415143` | active (server default today) | PSK→c2s; per-server secret→s2c (HKDF) | `sessionID‖seq` (+role XOR) | phase 17–18 |
| v4 "PAQD" | `0x50415144` | active (opt-in `--protocol-v4`) | v3 keys + per-session 128-bit random seed in HKDF salt | server→client uses per-server-session 8-byte base ‖ seq | phase 19 |
| v4.1 | same v4 magic | **current canonical v4** | v4 + **base bound into the s2c HKDF salt** (wire layout unchanged) | same | this migration (change note: spec Rev 2) |

**All generations are mutually incompatible on the wire.** A frame intended for one path fails auth (or is explicitly rejected) on a peer speaking another; the implementations reject mixed-version frames *explicitly* rather than guessing (`ErrProtocolVersionSignature`, `ErrLegacyProtocolDisabled`). Never assume numeric-similar versions interoperate.

### v4.1 migration note

The Phase 19 candidate (`v2.5.11-sesssalt` era v4.0) derived s2c keys **without** the base in the salt. v4.1 includes it. v4.0 clients cannot authenticate v4.1 servers and vice versa. There was never a production v4 deployment, so the migration cost is nil; the divergence is nonetheless explicit and tested.

## Asymmetric frame format (server→client, v4/v4.1)

```
Magic(4)|SessionID(8)|Seq(4)|Ack(4)|SeedLen(1)=16|Seed(16)|ServerIDLen(1)|ServerID|RNBLen(1)=8|ServerSessionBase(8)|ciphertext|tag(16)
```

Client→server frames omit the ServerID and base fields (`ServerIDLen=0`). The entire cleartext prefix is AEAD associated data — tampering with identities, seeds, sequences, or the base fails the tag. Minimum frame length: 38 bytes upstream (client), 47+ downstream (server, 1-byte ServerID).

## Key derivation (current v4.1)

```
c2s = HKDF-SHA256(ikm=c2sPSK,        salt="paqet-v4-"‖seed‖sessionID, info="paqet-v4-c2s")
s2c = HKDF-SHA256(ikm=serverSecret,  salt=V4Salt(seed,sessionID) ‖ ServerSessionBase, info="paqet-v4-s2c:"+serverID)
```

- Server session base is generated exactly **once per server-session reconstruction** (`NewServerAsymmetricSessionWithIDV4`) from crypto/rand — not per process, not per connection. Reconnects, session eviction, and restarts each produce a fresh base.
- Response-key lifecycle is immutable after construction.
- Nonce (12 B): server role XORs `[base(8)‖seq(4)]`; client role uses `[sessionID(8)‖seq(4)]`.
- Sequence exhaustion is fail-closed at `MaxSafeSequenceNumber = 0xFFFFFFF0`; sealing never wraps.

## Replay defense

| Layer | Scope | Behavior |
| --- | --- | --- |
| In-flight fingerprint | same (seq, authed ciphertext) | retransmission returns the **cached ciphertext byte-identically** (tested) |
| Per-domain window | (serverID, base) | ordered window filter (30 s), one per authenticated domain |
| Domain capacity | per client connection | max **32** domains; exceeding ⇒ **session sealed** (`ErrReplayDomainCapacity`), no eviction ⇒ an accepted response can never become acceptable again |
| Post-restart | — | fresh base ⇒ fresh domain; old-domain replays hit the *old* filter (per-domain isolation) |

Construction (12-byte GCM nonce) is bounded by the 8-byte base for accidental collisions: across `n` reconstructions of the **same** session tuple, `P(collision) ≈ n²/2⁶⁵` (≈2.7×10⁻⁸ at n=10⁶; ≈0.027 at n=10⁹). These are **probabilistic bounds**, not guarantees. Deliberate tuple replay is not a collision — it is defeated by the client window + domain sealing, not by entropy. A future v5 with a wider (e.g. 32-byte) epoch field remains an open option; no silent wire changes are accepted in this project.

## Credentials & trust model

- Shared PSK (c2s) and per-server response secrets are **independent 32-byte values**; the fallback "response secret = PSK" was removed in the Phase 18 hardening and is rejected at construction.
- Server→client authenticity is guaranteed *only* against peers lacking that server's response secret. **A client authorized for server X can forge authenticated responses as X to other clients** (symmetric trust model). Asymmetric (Ed25519-style) server authentication is future work.
- Client construction is fail-closed: empty allowlist, unknown IDs, short/missing secrets, symlinked or weakly-permissioned secret files, ambiguous CLI flag combinations, legacy frames with `AllowLegacyV2=false` ⇒ immediate rejection. Malformed frames and unauthorized IDs consume **no** replay-domain capacity.

## Emergency control-plane protocol (DNS)

- Client→server: AES-GCM payload fragmented into ≤250-byte DNS labels (QNAME and/or TXT), with EDNS0 size negotiation, deduplication, retries across resolver fallbacks.
- Server→client: TXT response, authenticated, carrying JSON (`{id, status, server_id, reply, timestamp}`), with fresh validity windows for bootstrap candidates.
- Message types and their duplicate-processing policy:

| Type | Class | On duplicate |
| --- | --- | --- |
| `ping`, `status` | read-only | harmless |
| `bootstrap_request` / `bootstrap_response` | idempotent | fresh validity window; same semantics |
| `alert` | idempotent | re-notify, no durable state |
| `data` | state-changing | re-execution possible — **no exactly-once**; never claim one |
| unknown | unsupported | rejected before any handler |

Bootstrap candidate records are validated for: whitelisted `transport_mode`, strictly-future `valid_until` (`== now` counts as expired), optional explicit pin `SHA256:<64hex>` overriding computed fingerprints, generation tokens.

## Compatibility matrix

| Client \ Server | v2 | v3 | v4.0 | v4.1 |
| --- | --- | --- | --- | --- |
| v2 client | ✓ (legacy mode only) | ✗ explicit reject | ✗ | ✗ |
| v3 client | ✗ (unless legacy allowed) | ✓ | ✗ explicit reject | ✗ |
| v4.0 client | ✗ | ✗ | ✓ | ✗ (salt mismatch) |
| v4.1 client (this repo) | ✗ | ✗ | ✗ | ✓ |

"✗ explicit reject" = the frame fails divinely at the magic/seed-length/credential layer; testing covers the cross-version matrix (`phase19_session_and_v4_test.go` cross-version tests). The v4/v4.1 split is enforced purely by key derivation parity (same magic) — hence the hard warning above.
