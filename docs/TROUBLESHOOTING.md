# Troubleshooting

Real failure modes of this implementation, ordered by likelihood of operator contact.

## 1. Interface selection / MAC address wrong

Symptom: nothing leaves the box; `pcap write` errors or silence on `tcpdump`.
Diagnose:

```bash
ip -4 route show default     # interface + gateway IP
ip link show <iface>         # 'link/ether aa:bb:cc:dd:ee:ff' must equal your config's router_mac
tcpdump -ee -i <iface> -n port 19999     # do you see your crafted packets?
```

Windows: `network.guid` needs the exact NPF device id, and Npcap must be in WinPcap-compatible mode.
Meaning of output: crafted packets visible at the NIC but not answered ⇒ MAC/interface mismatch is *not* the cause — go to #2.

## 2. Packet injection works but tunnel is silent

Check both sides configured the **same** `transport.kcp` key/`block`; run `paqet version` on both; validate `listen.addr` port == the port component of `network.ipv4.addr` on the server — this exact mismatch is the most common startup quit.

## 3. Kernel-generated RSTs kill flows (Linux)

Symptom: server sees inbound crafted packets but its responses are RSTs; client emerges with `connection reset`.
Check:

```bash
sudo iptables -t raw -S | grep -E 'dport|sport'
sudo iptables -t mangle -S | grep RST
```

Expected (straight from the upstream README rule set): NOTRACK on both client and server side of your traffic port plus the mangle DROP for outgoing RSTs. Their absence is the usual cause; add them exactly as in [DEPLOYMENT.md](DEPLOYMENT.md).

## 4. Firewall blocks the *first* crafted packets

Many VPS default firewalls (ufw, firewalld, cloud SGs) DROP on `eth0` before NOTRACK becomes effective; verify with a five-packet test and `conntrack -L` (should show nothing when NOTRACK works).

## 5. Credential file rejected at startup

Messages are raised directly by the loader. Causes (all fail-closed):
- `secret must be exactly 32 bytes` — hex/base64/raw mismatch in the file.
- `insecure/loose permissions on secret file` — chmod 600 (or 0400) the file.
- `symlink to key file is not allowed` — the file must exist at the literal path; do not symlink.
- Ambiguous flag combination (`--authorized-servers-config` together with `--server-id/--server-secret-file` or `--legacy-single-server`): choose one mode.

## 6. Wrong emergency peer / resolver returns garbage

- Confirm the delegated child zone actually routes to your :53 (`dig +short lambda1.<child>.<suffix> @<resolver>`), and that the resolver you called can recurse into it.
- A wrong *response secret* manifests as a fast client-side error (tag failure), never a timeout-till-success.

## 7. "notification dropped"/"replay-domain capacity exhausted"

Expected protection behavior: >32 distinct authenticated response domains within one client connection ⇒ session sealed (fail-closed); build a new connection instead of reusing it. If you see this in a normal operating environment (not an attack drill), an unauthorized party with a valid credential is likely flooding — rotate the response secret as per [SECURITY.md](SECURITY.md).

## 8. Incompatible peers after upgrade

A v4.0 (pre-v4.1 salt) peer cannot elevate to v4.1 or vice versa: keys mismatch with the *same* magic. Evidence of the failure mode: tag verification failures right after binary upgrade on one side only. Fix: upgrade both ends to the same generation (`04724db` or newer source) or roll back both.

## 9. `paqet run` exits at startup: YAML validation errors

Its messages list the offending field; common ones:
- `role must be 'client' or 'server'`
- `listen.addr` port mismatch with `network.ipv4.addr`
- unsupported `transport.protocol`

## 10. Emergency server never answers (loopback test fails)

Check (in order): port actually bound (`ss -ulnp | grep 5399`), both sides use the *same* `--domain`, key file identical, and no firewall dropping loopback UDP. For real resolver tests, confirm the zone's public delegation exists first — the client queries *any* recursive resolver, so propagation delay also costs ~TTL time.

## 11. Diagnostics tooling edge: `paquet dump`

`paqet dump` never logs credentials; it only prints raw TCP payload bytes of a port, which are encrypted anyway ([privacy note](SECURITY.md#logging-policy)).

## When everything fails

Open an issue with: `paqet version`, the failing command, sanitized log tail (no keys!), and the exact config file **commented out of secrets**; reproduce against the example fixtures if the diff is non-trivial ([CONTRIBUTING.md](CONTRIBUTING.md)).
