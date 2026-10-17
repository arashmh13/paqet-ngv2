# Installation

Paqet-NGV2 is a single Go binary (`paqet`). Everything below was verified on **Linux amd64 (WSL2, Ubuntu)** and **Windows 11 (git-bash toolchain)**; macOS and bare-metal Linux follow the same steps but are not covered by this project's test run.

## Prerequisites

| Requirement | Version | Notes |
| --- | --- | --- |
| Go toolchain | 1.27 or newer | module directive is `go 1 27*` — see `go.mod`; any recent 1.27+ works |
| Git | any recent | to clone / verify |
| libpcap (Linux/macOS) or Npcap (Windows) | current | **runtime** dependency of raw-packet capture (`network.*` modes). Install *Npcap with "Install Npcap in WinPcap API-compatible Mode"* checked on Windows |
| iproute2 / iptables | Linux only | optional, used for local port-block simulation and operator firewall control |
| systemd | Linux servers only | only needed for the service deployment style in [DEPLOYMENT.md](DEPLOYMENT.md) |

Check your toolchain:

```bash
go version      # expect go1.27.x or newer
gcc --version   # kcp-go compiles pure Go; CGO is used only for the pcap-linked
                # paths when features that need gopacket's libpcap binding are used
```

## Build from source

```bash
git clone https://github.com/arashmh13/paqet-ngv2
cd paqet-ngv2
go build -o bin/paqet ./cmd
./bin/paqet version
```

A successful build prints module version information. To verify the toolchain end-to-end instead of trusting `version` output, run the test suite (below) or check that `./bin/paqet --help` lists the subcommands `run`, `emergency`, `ping`, `dump`, `secret`, `version`.

Recommended self-verification before any deployment:

```bash
gofmt -l .            # expect no output
go vet ./...
go test -count=1 ./...   # ~30 s
go test -race ./...      # ~2 min, requires no extra setup
```

## Install the binary

```bash
sudo install -m 0755 bin/paqet /usr/local/bin/paqet
paqet version && paqet --help
```

The binary is self-contained; only libpcap needs to exist at runtime when raw-packet transports (`kcp`, `raw-kcp`, `asymmetric-spoof` in `transport.protocol`) are used. The emergency DNS control plane and SOCKS5-only client modes do **not** need pcap.

## Privileges and privilege minimization

| Feature | Privilege needed | Minimize by |
| --- | --- | --- |
| `network.*` raw transports (client/server data plane) | `CAP_NET_RAW` + `CAP_NET_ADMIN` (or run as root) | run under a dedicated user with `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` in systemd (see [DEPLOYMENT.md](DEPLOYMENT.md)); never run the *emergency server* as root unless it owns port 53 |
| `paqet emergency server --addr :53` | `CAP_NET_BIND_SERVICE` (ports <1024) or run unprivileged on a high port | prefer `--addr 127.0.0.1:5300` behind a tiny forwarder, or use `AmbientCapabilities=CAP_NET_BIND_SERVICE` |
| SOCKS5 client on `127.0.0.1:*` | none | bind loopback by default |

**Never** grant `root` to anything that does not strictly need it, and never share credential files (see [SECURITY.md](SECURITY.md)).

## Network interfaces

The data plane needs the name of the real outbound interface and the gateway MAC:

```bash
# Linux
ip -4 route show default          # e.g. "default via 192.168.1.1 dev eth0"
ip link show eth0                 # read "link/ether" => router_mac for the EXAMPLE below
# Windows (Npcap)
# device name: run  Get-NetAdapter   or use the NPF GUID via "npcap" --list-adapters
```

```bash
# The client config must match reality:
network.ipv4.addr      -> local IP + ephemeral port (port 0)
network.ipv4.router_mac -> default gateway MAC found above
```

## Firewall / kernel behavior

- Because the tunnel reuses TCP payloads over packets the kernel never sees as a flow, the kernel may emit **RST packets** for unsolicited inbound payload traffic. Upstream handles this by matching `local_flag`/`remote_flag` and by firewalling RST responses; on Linux both hosts usually need:
  ```bash
  # placeholder ports — replace with your configured ports
  sudo iptables -I INPUT  -p tcp --sport <PORT> -j DROP   # silence kernel RSTs to crafted inbound
  sudo iptables -I OUTPUT -p tcp --dport <PORT> --tcp-flags RST RST -j DROP
  ```
  > This is deliberately shown as an operator-driven action. These rules are **not** applied automatically by any Paqet-NGV2 binary. See [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
- The emergency DNS plane needs only outbound UDP/TCP 53 to *any* recursive resolver, and inbound :53 (or your chosen port) on the emergency server host.

## Platform-specific limitations

- **Windows:** validated by upstream lineage but **not re-tested by this fork**; Npcap GUID interface selection is used as in the upstream example config (`network.guid`).
- **macOS:** untested by this fork; BPF device permissions differ (`/dev/bpf*`).
- **IPv6:** supported in configuration (`network.ipv6`); exercised in tests to a limited degree — treat as partially verified.

## Uninstall (leaves nothing behind)

```bash
sudo rm -f /usr/local/bin/paqet
sudo systemctl disable --now paqet paqet-emergency 2>/dev/null
sudo rm -f /etc/systemd/system/paqet*.service /etc/systemd/system/paqet*.service.d/* 2>/dev/null
sudo systemctl daemon-reload
# manually review and remove any iptables rules you added (they were manual actions):
sudo iptables -S | grep -i paqet
```

Credential and key files your operator created (e.g. under `/etc/paqet/`) are intentionally **not** auto-deleted; remove them yourself after confirming rotation.
