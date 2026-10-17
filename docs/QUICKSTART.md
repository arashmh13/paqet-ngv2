# Quick start

Two independent layers — start with the **base tunnel** (layer 1), then add the **emergency DNS control plane** (layer 2). All values below use placeholders (`example.invalid`, TEST-NET IPs, generated keys); replace them with your own.

## 0. Build and generate credentials

```bash
git clone https://github.com/arashmh13/paqet-ngv2
cd paqet-ngv2
go build -o bin/paqet ./cmd
./bin/paqet secret            # prints a random 32-byte hex key — copy it
```

Write the key to files on both machines instead of putting it on a command line:

```bash
umask 077 && echo "<KEY-HEX>" > /etc/paqet/transport.key && chmod 600 /etc/paqet/transport.key
```

## Layer 1 — minimal base tunnel (raw TCP + KCP)

**Prereqs (both sides):** libpcap/Npcap, root/`CAP_NET_RAW`+`CAP_NET_ADMIN`, the outbound interface name and gateway MAC ([more detail](INSTALLATION.md#network-interfaces)).

`server.yaml` (see the fully commented template: [`example/server.yaml.example`](../example/server.yaml.example)):

```yaml
role: "server"
log:
  level: "info"
listen:
  addr: ":19999"                     # placeholder port — avoid 80/443
network:
  interface: "eth0"                  # CHANGE ME
  ipv4:
    addr: "0.0.0.0:19999"            # CHANGE ME: server's real IPv4 + same port as listen.addr
    router_mac: "aa:bb:cc:dd:ee:ff"  # CHANGE ME: server's gateway MAC
transport:
  protocol: "kcp"
  conn: 1
  obfs:
    enabled: true                    # both peers must use the same obfs key
    key: ""                          # defaults to transport.kcp.key
  kcp:
    mode: "fast"
  kcp:
    key: "<KEY-HEX>"                 # see example config for exact nesting
```

> The full fixture with every key in its correct nesting position is [`example/server.yaml.example`](../example/server.yaml.example) — copy it and edit the `CHANGE ME` markers rather than typing the above fragments by hand.

`client.yaml` ([[template](../example/client.yaml.example)]) similarly needs `role: "client"`, a `socks5.listen` address, the interface/IP/gateway-MAC block, and the same `transport` section (same key, same port as the server).

Start:

```bash
# server (VPS):
sudo ./bin/paqet run -c server.yaml

# client (workstation):
sudo ./bin/paqet run -c client.yaml
```

Verify (client side; SOCKS5 listen address from your client.yaml, here `127.0.0.1:1080`):

```bash
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me     # expect the SERVER's egress IP
curl --socks5-hostname 127.0.0.1:1080 http://example.invalid  # expect a NXDOMAIN-style failure,
                                                             # proving the proxy path works
```

Common failures → [TROUBLESHOOTING.md](TROUBLESHOOTING.md) (wrong interface/MAC, kernel RSTs, firewall rules, port mismatch between `listen.addr` and `network.ipv4.addr`).

> Note: commands were verified as written on Linux; on Windows replace `sudo`/`iptables` steps with an administrator shell and Npcap rules.

## Layer 2 — emergency DNS control plane (optional)

This is the Paqet-NGV2 addition; it is **independent of layer 1** and can be run/exercised alone.

### A. Minimal messaging-only loop (single server, legacy mode, no bootstrap)

On the control station (any host with a :53 listener):

```bash
# console A — authoritative emergency server
sudo ./bin/paqet emergency server \
  --addr 127.0.0.1:5399 \
  --domain test.tunnel.paqet-ngv2.example \
  --key-file /etc/paqet/transport.key \
  --legacy-single-server      \
  --disable-bootstrap          # messaging-only: fail-closed, no bootstrap candidates
```

```bash
# console B — client query through a real recursive resolver
./bin/paqet emergency send \
  --resolver 127.0.0.1:5399 \
  --domain test.tunnel.paqet-ngv2.example \
  --key-file /etc/paqet/transport.key \
  --legacy-single-server \
  --message "PING-1"
```

Expected: the client prints a small JSON `{"status":"OK", ...}` within seconds. `--resolver` accepts an IP[:port] of any recursive resolver (`--help` shows the default list).

### B. Multi-server, credentialed v4 (recommended posture)

The modern mode uses a **dedicated per-server response secret** and explicit client-side authorization. Generate the server secret *separately* from the shared PSK ([why](SECURITY.md)):

```bash
openssl rand -hex 32 | sudo tee /etc/paqet/srv1.response.key   # keep 0600
```

Client-side: point `--authorized-servers-config` at a JSON file using **secret files, never inline secrets** (documented JSON schema; parser rejects inline secret content, symlinks and loose permissions):

```json
{
  "version": 1,
  "protocol": "v4",
  "generation": 1,
  "authorized_servers": [
    { "server_id": "srv-a-01", "secret_file": "/etc/paqet/srv-a-01.response.key" }
  ]
}
```

Server side: run the emergency server with `--server-id srv-a-01 --server-secret-file /etc/paqet/srv-a-01.response.key --protocol-v4` (see [DEPLOYMENT.md](DEPLOYMENT.md) for a systemd unit). Client side uses `--authorized-servers-config` **instead of** `--server-id/--server-secret-file/--legacy-single-server` — flag sets are mutually exclusive and mixing them fails closed at startup.

### C. Bootstrap coordinates (the reason this layer exists)

On the emergency server, do **not** pass `--disable-bootstrap` and instead advertise a candidate:

```bash
--bootstrap-ip 203.0.113.7 --bootstrap-port 18088 --bootstrap-mode aead-stream \
--bootstrap-key-file /etc/paqet/transport.key
```

(Multiple candidates come from `--bootstrap-config`, an array of `{server_ip, transport_port, transport_mode, identity_type, identity_value, validity_sec}` records — see [`example/bootstrap-candidates.json.example`](../example/bootstrap-candidates.json.example).)

The `send` client then receives an authenticated, validity-windowed endpoint record it can use to rebuild the data tunnel ([DNS-RECOVERY.md](DNS-RECOVERY.md)).

## What still needs setup to be *useful*

1. A live data tunnel (layer 1) pointing at the candidate endpoint.
2. An independently reachable authoritative DNS zone for your delegated child domain if you want the emergency path to work when the primary server IP AND the primary zone are unreachable (not yet part of this repo — see limitations).
3. Placeholders above are intentionally conservative: no production IPs/domains/credentials appear anywhere in this repository.

## Diagnostics

```bash
paqet emergency scan --domain test.tunnel.paqet-ngv2.example   # probe recursive resolvers for tunnel capability
paqet dump --port 19999                                       # raw-packet visibility (needs privileges)
```
