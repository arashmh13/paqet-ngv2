# Changelog

All notable changes to Paqet-NGV2 are documented here. Format based on [Keep a Changelog](https://keepachangelog.com) (adoption by this repo starts at its first published version).

## [Unreleased]

### Added (initial publication of this repository)
- Independent, sanitized public repository seeded from the `research/hard-mode-rnd` development branch (snapshot `04724db`) of `arashmh13/paqet`, itself a derivative of `hanselime/paqet` (MIT).
- Documentation set: README, INSTALLATION, QUICKSTART, CONFIGURATION, ARCHITECTURE, PROTOCOLS, DNS-RECOVERY, SECURITY, DEPLOYMENT, TESTING, TROUBLESHOOTING, UPSTREAM, CONTRIBUTING.
- GitHub Actions CI (format check, `go vet`, `go test -count=1`, `go test -race`, build).

### Changed vs. the source development branch
- **Go module path:** `module paqet` → `module github.com/arashmh13/paqet-ngv2`; all internal import paths updated by tooling (184 references) — **no protocol identifiers or dependency code** were touched by this rename.
- **Default delegated domain placeholder** in emergency CLI flags: a personal production domain is replaced by `tunnel.paqet-ngv2.example` (safe RFC 2606 placeholder). Operators configure `--domain` explicitly. Wire behavior unchanged (domain is configuration, not protocol).
- **Environment scrubbing (privacy):** internal research documents, production IPs, hostnames, tokens, and infrastructure run records were **not imported** into this public repository. Source code comments/test fixtures now use reserved documentation IP ranges (TEST-NET-1/2/3). No functional code change.
- Internal `gofmt` cleanups in `internal/conf/conf.go`, `internal/ng/transport/sni_assisted.go` (formatting only).

### Compatibility
- Protocol generation compatibility matrix: [docs/PROTOCOLS.md](docs/PROTOCOLS.md#compatibility-matrix).
- **v4.0 (Phase 19 candidate) ↔ v4.1 (this repo): incompatible by key derivation** (server-session base bound into the s2c HKDF salt). Mixed-generation v4 peers fail authentication; upgrade or roll back *both* ends.
- v2/v3/v4 generations remain mutually incompatible exactly as before (explicit rejections; no silent reinterpretation).
