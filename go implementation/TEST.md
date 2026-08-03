# gfk real-network smoke test

Goal: prove the fake-TCP carrier passes traffic over your real ISP → VPS, then
run real xray traffic through it.

Fill in three values everywhere they appear:
- `VPS_IP`     — your VPS public IP (must be the IP on the VPS's interface)
- `SHARED_KEY` — any long random string; identical on both sides
- `XRAY_PORT`  — the TCP port your existing xray inbound listens on (on the VPS)

---

## 1. Server (VPS, Ubuntu/Debian, as root)

Copy `dist/gfk` to the VPS (e.g. `scp dist/gfk user@VPS_IP:~/`), then create
`server.yaml`:

```yaml
mode: server
transport: kcp
carrier:
  vps_ip: ""          # optional on the server: empty = auto-derive reply source.
                      # If it won't come up, set it to VPS_IP to rule out NIC
                      # auto-detection (see debug ladder).
  server_port: 45000
  client_port: 40000
  mtu: 1400
auth:
  key: "SHARED_KEY"
server:
  backend_ip: "127.0.0.1"
log_level: debug
```

Run it in the foreground so we see logs:

```sh
chmod +x gfk
sudo ./gfk -config server.yaml -dropRST
```

Expect:
```
firewall RST-suppression rules applied  port=45000
server starting  transport=kcp backend=127.0.0.1 ...
```

## 2. Client (this Windows PC, Administrator terminal)

`client.yaml` next to `gfk.exe`:

```yaml
mode: client
transport: kcp
carrier:
  vps_ip: "VPS_IP"
  server_port: 45000
  client_port: 40000
  mtu: 1400
auth:
  key: "SHARED_KEY"
client:
  forwards:
    - {proto: tcp, listen: "127.0.0.1:14000", target_port: XRAY_PORT}
log_level: debug
```

In an **Administrator** PowerShell:

```powershell
.\gfk.exe -config client.yaml -dropRST
```

Expect:
```
firewall RST-suppression rules applied  port=40000
client starting  transport=kcp vps=VPS_IP
tcp forward listening  listen=127.0.0.1:14000 target_port=XRAY_PORT
tunnel up  peer=VPS_IP:45000
```

---

## Checkpoint 1 — carrier + transport is alive (the critical proof)

On the **server**, when the client connects you should see:
```
client session up  peer=<your home public IP>:40000
```
On the **client**: `tunnel up`, and it should **stay up** (no repeating
`tunnel down; reconnecting`). If the session survives >30s, KCP/smux keepalives
are flowing **both directions** → the fake-TCP carrier works end to end.

## Checkpoint 2 — real traffic

Point your normal xray **client** config at `127.0.0.1:14000` (instead of the
VPS directly) and load a website. If pages load, the full path works:
`your app → gfk client → fake-TCP → gfk server → xray:XRAY_PORT → internet`.

---

## If it does NOT come up — debug ladder

**A. Are the fake-TCP packets even reaching the VPS?**
On the VPS, in another shell:
```sh
sudo tcpdump -ni any 'tcp port 45000'
```
- You see packets **inbound** (dst .45000) from your home IP **and outbound**
  (src .45000) back → carrier is bidirectional; problem is higher up (key/MTU).
- Inbound only, no outbound → server isn't injecting replies (check server logs,
  try setting `carrier.interface: eth0`).
- **Nothing inbound** → your ISP is dropping the handshake-less packets on egress,
  or `vps_ip`/interface is wrong. This is the ISP-dependent part the project is
  about; try from the fixed-line/ADSL connection (not mobile/4G/CGNAT).

**B. Client side**
- Must run as Administrator; Npcap installed. A gateway-ARP failure logs
  `resolve gateway MAC: timeout` → set `carrier.interface` to your real NIC, or
  check you're on the expected network.
- Both sides log `firewall ... applied`? If not, RSTs will kill the flow.

**C. Common fixes**
- Lower `mtu` to `1200` on **both** sides.
- Make sure `server_port`/`client_port` aren't used by anything else.
- Try `transport: quic` on both sides to compare.
- Set `carrier.interface` explicitly if auto-detect picked the wrong NIC
  (Linux: `eth0`; the client logs which local IP it chose).

Report back what the server `tcpdump` shows and the client log — that pinpoints
the layer immediately.
