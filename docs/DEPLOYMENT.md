# Deployment (Linux)

Templates only — **replace every placeholder**. This repo ships no scripts that touch live firewall rules or production hosts without explicit operator action.

## Layout

```
/etc/paqet/
  transport.key            # 0640 root:paqet — shared c2s PSK
  srv-a-01.response.key    # 0600 root:paqet — dedicated per-server response secret
  authorized-servers.json  # 0600 root:paqet — client-side multi-server authorization (v4)
  paqet-client.yaml        # 0640 root:paqet
  paqet-server.yaml        # 0640 root:paqet
  bootstrap-candidates.json
/usr/local/bin/paqet
```

```bash
sudo useradd -r -s /usr/sbin/nologin paqet
sudo mkdir -m 0750 -p /etc/paqet && sudo chown root:paqet /etc/paqet
```

## Systemd service — client (tunnel + SOCKS5)

Template (`/etc/systemd/system/paqet-client.service`):

```ini
[Unit]
Description=Paqet-NGV2 raw-packet tunnel (client)
After=network.target

[Service]
Type=simple
User=paqet
Group=paqet
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ExecStart=/usr/local/bin/paqet run -c /etc/paqet/paqet-client.yaml
# raw transport needs these two caps:
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

## Systemd service — emergency DNS responder (port 53)

Template (`/etc/systemd/system/paqet-emergency.service`):

```ini
[Unit]
Description=Paqet-NGV2 authoritative emergency DNS responder
After=network.target

[Service]
Type=simple
User=paqet
Group=paqet
NoNewPrivileges=true
ProtectSystem=strict
ExecStart=/usr/local/bin/paqet emergency server \
  --addr 0.0.0.0:53 \
  --domain tunnel.paqet-ngv2.example \
  --key-file /etc/paqet/transport.key \
  --server-id srv-a-01 \
  --server-secret-file /etc/paqet/srv-a-01.response.key \
  --protocol-v4 \
  --bootstrap-ip 203.0.113.7 --bootstrap-port 18088 --bootstrap-mode aead-stream \
  --bootstrap-key-file /etc/paqet/transport.key
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Legacy/single-server variant — `drop` `--server-id --server-secret-file --protocol-v4`, add `--legacy-single-server`; but the credentialed multi-server posture is the recommended one ([SECURITY.md](SECURITY.md)).

## Firewall & kernel behavior (operator-driven)

```bash
# run ONLY after you understand them; NOT automated by this project
PORT=19999   # your tunnel port
sudo iptables -t raw    -A PREROUTING -p tcp --dport "$PORT" -j NOTRACK
sudo iptables -t raw    -A OUTPUT     -p tcp --sport "$PORT" -j NOTRACK
sudo iptables -t mangle -A OUTPUT     -p tcp --sport "$PORT" --tcp-flags RST RST -j DROP
# DNS egress for the client:
sudo ufw allow out 53/udp && sudo ufw allow out 53/tcp
# emergency server inbound:
sudo ufw allow 53/udp && sudo ufw allow 53/tcp
```

Record your rules; rollback = delete what you added (exact reverse of each line).

## Lifecycle

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now paqet-client
sudo systemctl enable --now paqet-emergency

# health
systemctl is-active paqet-client paqet-emergency
ss -ulnp | grep ':53 '                     # emergency responder bound
ss -tlnp | grep ':1090'                    # client SOCKS5 (placeholder)
journalctl -u paqet-emergency -f           # live logs

# stop / restart
sudo systemctl restart paqet-emergency
sudo systemctl stop paqet-client

# upgrade (safe replacement of one binary)
sudo cp /usr/local/bin/paqet /usr/local/bin/paqet.prev
sudo install -m 0755 ./bin/paqet /usr/local/bin/paqet
sudo systemctl restart paqet-client paqet-emergency

# rollback
sudo install -m 0755 /usr/local/bin/paqet.prev /usr/local/bin/paqet
sudo systemctl restart paqet-client paqet-emergency

# uninstall
sudo systemctl disable --now paqet-client paqet-emergency
sudo rm -f /etc/systemd/system/paqet-{client,emergency}.service
sudo systemctl daemon-reload
```

## Upgrade safety & staging first

1. Build the candidate binary and **shakedown on a staging host/port** (e.g. `--addr 127.0.0.1:15353`) before touching :53.
2. Keep `paqet.prev` alongside as the rollback artifact; checksum both (`sha256sum`) before/after.
3. Verify version handshake: `emergency send` must succeed against the staged responder before promoting the systemd unit.
4. The default fail-closed posture (`--disable-bootstrap`) is always safe — `SYSTEMD_SERVICES SHOULD NOT open production listeners before credentialed staging passes`.

## Do not run unattended admin actions

The scripts shipped in `scripts/` are *harnesses* (phase13–17 lab programs). Some of them hard-code environment-specific IPs/ports *as placeholders after sanitization* and include local `iptables -A/-D` port-block simulations for controlled experiments — run only on disposable lab nodes, never on a production gateway. There is **no** script in this repository that flushes or rewrites firewall policy wholesale.
