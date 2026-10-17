# Testing

## Test taxonomy in this repository

| Kind | Scope | Run | Evidence |
| --- | --- | --- | --- |
| Unit | packages: crypto, replay, conf, obfs, protocol, dns scanner, socks/forward | `go test ./internal/...` | standard Go tests throughout |
| Deterministic protocol/safety suites | asymmetric sessions (v2/v3/v4/v4.1), credential fail-closed, replay windows, domain capacity sealing, rotation/revocation | `go test ./internal/ng/transport/...` | `phase18*`, `phase19_*`, `phase20_*` named test files |
| Loopback integration | full `EmergencyDNSServer`↔`EmergencyDNSClient` exchange over UDP retransmission, restart isolation, cross-server duplicates | same | `phase19_session_and_v4_test.go`, `recovery_state_machine_test.go` |
| Concurrency | domain-capacity exhaustion under concurrent frames | `go test -race ./internal/ng/transport/...` | `phase20_replay_domain_capacity_test.go` (TestPhase20_DomainCapacity_ConcurrentExhaustionDeterministic) |
| CLI path | real `--authorized-servers-config` loader, atomic replacement, rotation, legacy-frame rejection | `go test ./cmd/emergency/...` | `phase19_client_config_test.go`, `phase20_cli_rotation_test.go` |
| Failure-lab (simulated) | port-block via local iptables in lab scripts (explicitly operator-run, not a Go test) | manual | scripts/phase13–17 |

The Phase 13–17 failure-laboratory scripts reconstruct blocked-network experiments; they are integration stages, not automated regression tests.

## Standard commands (verified during this migration)

```bash
gofmt -l .                        # expect empty
go vet ./...
go test -count=1 ./...            # full tree
go test -race ./...               # races on supported platforms
go build -o bin/paqet ./cmd       # the intended executable
```

Current results (verified): all pass, no `FAIL` lines; race build covered the entire tree without warnings.

## Reproducing the failure-lab

- Port-blocking/labr simulation scripts are under `scripts/phase13*..phase17*` (Go harnesses + helper scripts). They create/tear down small local-only `iptables` rules on lab machines only. Read the file you are about to run; run only on disposable nodes.
- The Go tests themselves never modify firewall state.

## DNS emergency-loopback west (prereq: none beyond Go)

```bash
(key gen with `paqet secret`, then:)
paqet emergency server --addr 127.0.0.1:5399 --domain test.tunnel.paqet-ngv2.example \
   --key-file ./transport.key --legacy-single-server --disable-bootstrap &
paqet emergency send --resolver 127.0.0.1:5399 --domain test.tunnel.paqet-ngv2.example \
   --key-file ./transport.key --legacy-single-server --message "PING-1"
expected: {"status":"OK", "id":"…"}
```

## What testing does *not* show

- Packet-level performance vs real-loss networks (not benchmarked here).
- macOS/Windows CI coverage (only Linux CI).
- Zone-level destruction (the failure case "authoritative DNS host is also down") — architecture supports downstream replacement but this repo ships no independently hosted infrastructure.

## Benchmarks

None are committed in this repo yet; do not run `make benchmark` — there is no such target.
