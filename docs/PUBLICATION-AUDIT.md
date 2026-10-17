# Publication audit — how this repository was created

This document records exactly how `arashmh13/paqet-ngv2` was derived from the development fork, what was intentionally left out, and the evidence collected for each verification step. It exists so the import is auditable and so nobody has to guess why a file is missing.

## Provenance

| Item | Value |
| --- | --- |
| Upstream base | `https://github.com/hanselime/paqet` (MIT) |
| Development repository | `https://github.com/arashmh13/paqet` (public fork, development only) |
| Source branch | `research/hard-mode-rnd` |
| Source snapshot | commit `04724db16335f673ee49945f63a3c7c0281c1596` |
| Method | `git archive` of the source snapshot into a **new empty repository** — not GitHub's *Fork* action, not a branch rename |
| Default branch | `main` |

The source fork was verified untouched after publication: its branch head remained `04724db16335f673ee49945f63a3c7c0281c1596`, no new commits, no rewritten history, no force-push.

## Why the original commit history was not published

The source branch's history contains an internal research audit trail under `docs/research/` plus operator run records. Those documents embed **live production infrastructure details** — public host IPs, a personal domain, tunnel endpoints, staging secrets, and experiment logs. Publishing that history as-is would have exposed live infrastructure and operational credentials, so the branch history was **not** carried over. Instead the verified working-tree snapshot was imported as a fresh, single-root history, with provenance and attribution recorded in [`UPSTREAM.md`](../UPSTREAM.md).

Everything excluded was excluded for privacy only. No functionality was dropped from the working tree: the import is the complete snapshot minus `docs/research/`, `bin/`, and the operational scratch scripts listed below.

## Sanitization applied to the imported snapshot

| Change | Detail |
| --- | --- |
| Go module path | `module paqet` → `module github.com/arashmh13/paqet-ngv2` (184 import references updated mechanically; no protocol identifiers touched) |
| Production IPs | replaced with reserved documentation ranges (RFC 5737): `77.37.65.2` → `203.0.113.7`, `185.18.215.124` → `198.51.100.7`, `185.18.215.45` → `198.51.100.9` |
| Personal domain | replaced with the RFC 2606 placeholder `paqet-ngv2.example` (default `--domain` flag text only; the domain is operator configuration, not protocol) |
| SOCKS5 credentials in failure-lab scripts | `arash:arash@127.0.0.1:1090` → `USER:PASSWORD@127.0.0.1:1090` in `scripts/phase13|14|16|17_recovery/main.go` |
| `docs/research/*` | not imported (research audit trail with live infrastructure) |
| `bin/` build output | not imported (`.gitignore` covers it) |
| `.github/workflows/build-selfhosted.yml` | removed — self-hosted runners on a public repository are a known supply-chain risk and no runner is registered here |
| Formatting | `gofmt -w` applied to the two files the rename touched; no logic changes |

## Verification evidence

Collected on the published tree at the commit referenced in the repo's `main` history:

- `gofmt -l .` → empty
- `go vet ./...` → clean
- `go test -count=1 ./...` → pass (all packages)
- `go test -race ./...` → pass
- `go build -o bin/paqet ./cmd` → success
- Example fixtures `example/client.yaml.example`, `example/server.yaml.example` loaded through the **real** parser (`internal/conf.LoadFromFile`, interface/port values retargeted to the local box) → `role: client` / `role: server`, validated OK
- GitHub Actions `CI` (gofmt+vet, test incl. `-race`, build incl. CLI smoke check) → green on `main`
- GitHub API on the published repo → `owner=arashmh13`, `fork=false`, `private=false`, `default_branch=main`, license MIT

Known, reported honestly: one concurrency test (`TestConcurrentDuplicatesWithHandlerDelay`) fails intermittently when the full suite and the race suite run concurrently on one machine (resource contention, handler-delay assertions). It passes in isolation, 3/3 consecutive runs. CI runs it serially and is green.

## Not published / not deployed

- No production service was touched: the Iran-side SOCKS5 proxy remained on `127.0.0.1:1090` and the Germany-side emergency server daemon was left running its existing binary generation. This repository contains source and documentation only.
- No tags or releases were published. `build-release.yml` is tag-triggered and stays dormant until a tag is pushed deliberately.
- No CI secrets are configured; every workflow uses the default read-only `GITHUB_TOKEN`.

## Maintenance posture

`dependabot.yml` was inherited from upstream and is active. Dependency PRs are merged only while CI is green (verified evidence, not assumption). `github.com/xtaci/smux` was **pinned at 1.5.53**: the `v2.0.1+incompatible` bump removes `smux.Config.Version` and `smux.Config.MaxStreamBuffer`, which the transport layer sets — adopting smux 2.x is a transport migration, not a dependency bump (see closed PR #3).
