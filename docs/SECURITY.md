# Security

> **Status: research-grade.** No formal, independent audit has been performed on Paqet-NGV2's custom protocol or cryptography. Treat every claim below as engineering diligence, not proof.

## Threat model

| Adversary | Covered | Notes |
| --- | --- | --- |
| Passive network observer (DPI fingerprinting) | partially | obfuscation randomizes packet length, AEAD hides payload; *traffic shape analysis* remains open — stated openly, not solved |
| Active tamperer (bit-flip, injection) | yes | AES-256-GCM on every frame; tampering fails the tag |
| Credential-holder impersonating a server to *other* clients | **NO** (known, architectural) | see below |
| Replay (same-flow, cross-restart, cross-domain) | yes | tested invariants — see [PROTOCOLS.md](PROTOCOLS.md) |
| Protocol downgrade | yes | all cross-generation frames rejected fail-closed; legacy v2 requires explicit enablement |
| Malicious/compromised recursive resolver | mitigated | resolver cannot produce a valid AEAD tag for your traffic |
| Kernel/route-level countermeasures | operator's job | iptables NOTRACK/RST rules, port selection |
| Compromised *client* host | out of scope | endpoint compromise is a loss |

## Known limitations

1. **Symmetric response credentials:** the response-verification secret for server X is shared symmetric. Any client that legitimately holds it (those authorized to *verify* X) can **forge** authenticated responses *as X* to other clients of this architecture. This means the trust graph is not transitive-safe: only hand the configured client secret set to hosts you fully control. Asymmetric server authentication (e.g., Ed25519 signatures) is a planned, unimplemented direction.
2. **Session-ID collision bounds are probabilistic:** 64-bit IDs give `≈ n²/2⁶⁵` birthday bound; the current v4.1 128-bit seed reduces concern but does not make anything "mathematically unique." Everything random here is bounded, not guaranteed.
3. **No durable dedup:** all replay/cache state is in memory. Duplicates after restart re-execute handlers — safe classes only (see [ARCHITECTURE.md](ARCHITECTURE.md)); `data` messages are unsupported for exactly-once semantics without additional durable machinery.
4. **The emergency responder answers who it can authenticate** — not identity-level OAuth. An unexpected peer that guesses your delegated zone would still fail credential checks (empty allowlist ⇒ fail-closed) but enumeration of your zone is a passive-observer observable if you use a guessable name.
5. **Custom protocol + custom framing** — deviation from reviewed standards is your responsibility to audit; never use in safety-critical paths.

## Credential generation, storage & rotation

```bash
# shared 32-byte PSK (both tunnel peers)
./bin/paqet secret                          # or: openssl rand -hex 32
umask 077 && printf '%s' "<HEX>" > /etc/paqet/transport.key && chmod 600 /etc/paqet/transport.key

# dedicated per-server response secret (independent from the PSK above)
openssl rand -hex 32 | sudo tee /etc/paqet/srv-a-01.response.key >/dev/null
chmod 600 /etc/paqet/srv-a-01.response.key
```

Enforced rules (implemented, not just advice):

- secret files: **0600/0400 only**; group/world bits are rejected.
- symlinks to secret files are rejected (anti-swap attacks).
- decoded secret must be exactly 32 bytes — no silent padding/truncation.
- inline `--key` is accepted but discouraged (argv exposure); prefer `--key-file`, or `PAQET_EMERGENCY_KEY` when the file is genuinely impractical.
- the loader deep-copies secrets: mutating the parsed slice after load cannot alter a live session's credentials.
- **never** log key material; the code does not print credentials, and tests assert normalized outputs contain `[REDACTED]` in place of anything sensitive.

**Rotation:** replacing a response secret is destructive to prior sessions deliberately: clients carrying the *old* secret fail closed against the rotated server (tested), and the domain/credential epoch resets. Rotate during a maintenance window, update both sides atomically, and expect the client config's `generation` to be honored by your operational process.

## Server authorization & fail-closed posture

- Empty/malformed allowlist, empty secret, duplicate/unknown server IDs, uploaded-but-unverifiable states all fail construction before any socket binds.
- `--legacy-single-server` is a *visibly separate* constructor; it is unreachable by accident from multi-server code paths.
- The current server-posture default (`--legacy-single-server`, no dedicated secrets) is explicitly legacy; production-grade multi-server mode demands `--server-id` + `--server-secret-file` (+ `--protocol-v4`) on the server and `--authorized-servers-config` on the client.

## Logging policy

- No secret bytes, no decrypted payloads, no key hashes in logs; internal phases use `[REDACTED]` placeholders in evidence artifacts.
- Command-line argv may leak `--key`; prefer file/env as noted.

## Incident response (project-local, not a formal CA)

1. Rotate the exposed credential(s) (above).
2. Restart emergency endpoints; the fresh server-session base immediately invalidates replay attacks that depended on the old domain.
3. Verify logs for the affected timeframe; do not reuse the old key material for any purpose.
4. If a client host's config (or a secret file) leaked, treat every peer identity as exposed and rotate **both** PSK and response secrets.

## Reporting

Vulnerabilities: begin a private conversation with the maintainer via GitHub (open a **private** discussion/issue titled "security" and do not post details publicly) — see [../SECURITY.md](../SECURITY.md) at the repository root. Do NOT use the public issue tracker for unpatched vulnerabilities.
