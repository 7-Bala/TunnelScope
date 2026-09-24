# TunnelScope — Demo Script (~6 min, updated 2026-09-20 for T-083)

Record from the repo root. Each step: what to run or click, and the point it proves. Every capture
named here is in the repo (traffic sessions: `testbed/captures/exp15/traffic/`, local only; run
`testbed/scripts/run_exp15_traffic.sh` to recreate).

## 0 · Start (15s)
```bash
./start.sh
```
**Point:** one command checks the tools, builds what's missing, starts the local engine (127.0.0.1
only) and opens the dashboard. Let the intro play.

## 1 · Upload a batch (45s)
Drop onto the page: `testbed/captures/cloud/c-w.pcap`, `testbed/captures/exp15/a-tra-sha1.pcap`,
`testbed/captures/synthetic/replay-attack.pcap`, `testbed/captures/exp15/s-3des.pcap`,
`testbed/captures/exp15/traffic/exp15-tun-messaging-rep4.pcap`, `testbed/captures/cs-transport-aes256gcm16.pcap`.
**Point:** the "Highest risk" figure, the fleet **Threat matrix** card and the per-tunnel risk numbers:
PS e) risk score and threat matrix, computed from cited verdicts.

## 2 · Traffic type inside the tunnel (45s) — PS c)
Open `exp15-tun-messaging-rep4.pcap` → **Traffic & exposure**.
**Point:** "Messaging (WhatsApp-like), 98% model confidence" with the next alternatives, from packet
sizes and timing only, through AES-GCM. Our own Random Forest, trained on our lab traffic plus real public VPN traffic (MIT VNAT)
(macro-F1 0.995 on held-out lab runs, 0.741 on real VPN captures it never saw). Say the limit out loud: shapes, not apps; mixed traffic names the dominant
one; video+interactive is misread as web, and the tool says so.

## 3 · Mode, AH and the handshake-vs-data cipher (45s) — PS c)
- `a-tra-sha1.pcap` → **Evidence**: IPsec protocol **AH**, mode **transport** read from AH's
  plaintext header, integrity narrowed from the ICV length. **Threats**: "No confidentiality" high.
- `cs-transport-aes256gcm16.pcap` → Evidence: mode **transport**, proven: a packet smaller than any
  tunnel-mode packet can be.
- Point at the two labels: **Handshake (IKE SA) encryption** is read exactly; **Data (ESP) cipher** is a
  candidate set, because it's negotiated inside the encrypted handshake.

## 4 · Replay (20s) — PS d)
`replay-attack.pcap` → **Verdicts**: RFC4303-SEQ **FAIL**, "a sequence number was used twice".
**Point:** and a same-moment duplicate from a second tap is *not* called a replay.

## 5 · Live stream with a downgrade (90s) — PS "live network streams"
```bash
./start.sh stop && ./start.sh --live-follow testbed/captures/live --window 15
testbed/scripts/run_live_demo.sh 15 75 45      # Docker lab: strong tunnel, then the same tunnel downgraded
```
Open the **Live** tab. **Point:** a window is analysed every 15 s; when the tunnel re-negotiates with
MODP-1024 / AES-128 / SHA-1, it turns **changed** with the three downgrades named and the risk jumps
(95 in our run). The anomaly model learned this tunnel's normal from its own earlier windows.

## 6 · Reports (30s) — PS e)
```bash
tunnelscope report testbed/captures/exp15/a-tra-sha1.pcap --level exec
tunnelscope report testbed/captures/cloud/c-w.pcap --level tech | less    # threat matrix table
```
**Point:** executive report leads with risk score, evidence confidence, mode, protocol, traffic;
technical report has the full threat matrix, every finding with status and vantage, the Indian
regulatory context.

## 7 · Honesty close (15s)
Open any tunnel → **Not visible from here**. **Point:** what the capture cannot show is listed, never
scored as fine.
