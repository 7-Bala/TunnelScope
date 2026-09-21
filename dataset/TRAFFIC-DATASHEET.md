# TunnelScope Traffic Dataset — Datasheet

## Contents

- Total sessions: 300
- Total packets: 2464991

### By source

| Source | Sessions |
|---|---|
| EXP-05 | 52 |
| EXP-15 | 184 |
| EXP-16 | 64 |

### By arm

| Arm | Sessions |
|---|---|
| base | 20 |
| cbc | 16 |
| lsw | 32 |
| mux | 36 |
| real | 32 |
| tfc | 68 |
| tra | 48 |
| tun | 48 |

### By class

| Class | Sessions |
|---|---|
| bulk | 36 |
| bulk+icmp | 6 |
| bulk+voip | 4 |
| email | 28 |
| email+messaging | 6 |
| icmp | 28 |
| interactive | 36 |
| messaging | 28 |
| video | 36 |
| video+interactive | 10 |
| voip | 36 |
| voip+web | 10 |
| web | 36 |

### By repetition

| Repetition | Sessions |
|---|---|
| 1 | 65 |
| 2 | 65 |
| 3 | 57 |
| 4 | 57 |
| 5 | 28 |
| 6 | 28 |

### Class by arm

| Class | base | cbc | lsw | mux | real | tfc | tra | tun |
|---|---|---|---|---|---|---|---|---|
| bulk | 4 | 2 | 4 | 0 | 4 | 10 | 6 | 6 |
| bulk+icmp | 0 | 0 | 0 | 6 | 0 | 0 | 0 | 0 |
| bulk+voip | 0 | 0 | 0 | 4 | 0 | 0 | 0 | 0 |
| email | 0 | 2 | 4 | 0 | 4 | 6 | 6 | 6 |
| email+messaging | 0 | 0 | 0 | 6 | 0 | 0 | 0 | 0 |
| icmp | 0 | 2 | 4 | 0 | 4 | 6 | 6 | 6 |
| interactive | 4 | 2 | 4 | 0 | 4 | 10 | 6 | 6 |
| messaging | 0 | 2 | 4 | 0 | 4 | 6 | 6 | 6 |
| video | 4 | 2 | 4 | 0 | 4 | 10 | 6 | 6 |
| video+interactive | 0 | 0 | 0 | 10 | 0 | 0 | 0 | 0 |
| voip | 4 | 2 | 4 | 0 | 4 | 10 | 6 | 6 |
| voip+web | 0 | 0 | 0 | 10 | 0 | 0 | 0 | 0 |
| web | 4 | 2 | 4 | 0 | 4 | 10 | 6 | 6 |

## How it was made

Sessions were recorded at a keyless router between two IPsec gateways, headers only, so what the file holds is what a passive observer sees. EXP-05 and EXP-15 use a seeded traffic generator (testbed/scripts/tgen.py) that imitates eight traffic shapes: voip, web, bulk (file transfer), interactive (SSH-like), video, email (SMTP-like), messaging (WhatsApp-like) and icmp. EXP-16 adds real software (headless Chromium, OpenSSH and SFTP, Postfix with swaks, an XMPP client and server, ffmpeg RTP, ping) talking to lab servers through the tunnel, and the generator's traffic carried by Libreswan instead of strongSwan. Arms: tun/base tunnel mode AES-GCM-256; tfc traffic-flow-confidentiality padding to the MTU; tra transport mode; cbc AES-CBC-128 with HMAC-SHA-256; mux two traffic types at once; real real applications; lsw Libreswan.

## Files and format

each session is one <tag>.pkts.csv.gz (columns t seconds since first packet, dir out|in, len outer IP length in bytes) plus a row in the source's manifest.csv with the SHA-256 of the original capture. The original .pcap files are not committed (large); they are hashed.

## Known limits

One lab network with no internet delay or packet loss. Two IPsec implementations. Traffic is generated against our own servers, so it is not representative of any organisation's real traffic. A classifier trained only on the synthetic sessions scored 0.461 on the real-application sessions (EXP-16), so synthetic and real sessions should not be treated as interchangeable. Class labels describe traffic shapes, not the applications named in them.

## Licence

TBD (owner decision)

## Citation

TBD (owner decision)

## Discrepancies

none
