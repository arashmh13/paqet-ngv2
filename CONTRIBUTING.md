# Contributing

Thanks for helping improve Paqet-NGV2. Keep contributions reviewable and evidence-based.

## Ground rules

- **Go 1.27+**; keep the code gofmt-clean.
- **Never add test failures or weaken existing assertions** to make a build pass. A green build obtained by deleting security checks will be rejected.
- **Never commit** real credentials, key files, operator IPs/domains, or environment-specific values. Use the repo's placeholder hoards (`example.invalid`, RFC 5737 TEST-NET IPs, fixture JSONs).
- **Never change the wire format** in a way that makes previously compatible peers fail silently; protocol changes require a version bump, matrix updates in [docs/PROTOCOLS.md](docs/PROTOCOLS.md), and tests on both sides.

## Workflow

1. Fork work on one branch per change; don't mix unrelated changes.
2. Ensure these exactly match CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)):
   ```bash
   gofmt -w .        && gofmt -l .  # empty
   go vet ./...
   go test -count=1 ./...
   go test -race ./...
   go build -o bin/paqet ./cmd
   ```
3. Add regression tests **next to** the bug: a named test is required for any security/lifecycle fix (existing suites: `phase18*`..`phase20*`; follow that naming style for a numbered protocol-lifecycle change).
4. Update the relevant docs — one authoritative copy, cross-linked from elsewhere:
   - protocol behavior → [docs/PROTOCOLS.md](docs/PROTOCOLS.md) and [docs/architecture.md](docs/ARCHITECTURE.md)
   - config surface → [docs/CONFIGURATION.md](docs/CONFIGURATION.md) (and regenerate both `example/*.yaml.example` fixtures)
   - security posture → [docs/SECURITY.md](docs/SECURITY.md) and [CHANGELOG.md](CHANGELOG.md) (compatibility notes)
5. PR checklist: diff review, all tests green (your own run), doc update links, no secrets in `git diff` output.

## Review expectations

- Any change touching `internal/ng/crypto`, `internal/ng/replay`, or `internal/ng/transport/asymmetric.go` requires **two-reviewer review** and a cryptographic-impact note in the PR body.
- New CLI flags need: parsing, validation, `--help` text update, a doc row in [docs/CONFIGURATION.md](docs/CONFIGURATION.md), and at least one positive + one negative (fail-closed) test.
- Security-sensitive paths (credential loading, replay, session construction) must cite the existing tests they extend rather than starting from scratch.

## Communication

Open a GitHub issue/discussion first for: protocol/format changes, new transports, anything you would claim "resilience" from. Experimental claims must include the exact test/command you ran to justify them.
