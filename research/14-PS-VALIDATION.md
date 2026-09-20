# 14 — Validation against the SIH26160 problem statement (2026-09-20)

Every line of the PS checked against the repo on 2026-09-20, with evidence. Legend: ✅ met ·
⚠️ partial · ❌ not met · ⛔ deliberately refused by an earlier project decision (conflicts with the PS).

## a) Testbed
| PS item | Status | Evidence |
|---|---|---|
| Tunnel / Transport mode | ✅ | `cs-aes256gcm16`, `cs-transport-aes256gcm16` (+ a7 pair) |
| AES-128, AES-256, AES-GCM, AES-CBC+HMAC | ✅ | `cs-aes128cbc-sha256`, `cs-aes256cbc-sha256`, `cs-aes128gcm16`, `cs-aes256gcm16` (+ CTR, ChaCha20) |
| Different DH groups | ⚠️ | Main arms all MODP-2048; variation only in EXP-13 cloud arms (MODP-1024 / 2048 / ECP-384) and PQ (ML-KEM-768) |
| PFS on/off | ✅ | `cs-pfs-on/off`, `rekey-cs-pfs-on/off` |
| IPv4 / IPv6 | ✅ | `encap/ipv6-*` (2 captures only) |
| Traffic types (VoIP, WhatsApp, e-mail, web, ICMP, video) | ⚠️ | `testbed/scripts/tgen.py`: synthetic *shape models* of voip/web/bulk/interactive/video + ICMP probes. No e-mail, no messaging/WhatsApp, no real applications |
| (beyond PS) 3 implementations | ✅ | strongSwan 5.9/6.x, Libreswan 5.4, OpenBSD iked |

## b) Capture
| IKE / ESP | ✅ | 87 tracked pcaps with ground truth (`dataset/`) |
| AH (optional) | ❌ | no AH arm, no AH parsing |
| tcpdump / Wireshark | ✅ | router-vantage tcpdump, tshark ingest |
| **Live network streams** (Description) | ❌ | pcap files only |

## c) "AI-Based" protocol identification
| IPsec protocol, IKE version | ✅ | deterministic parsing (tshark), not AI; IKEv1 suites not extracted |
| Tunnel / Transport | ❌ | always NOT_OBSERVABLE (EXP-08). See finding below: this is weaker than it needs to be |
| Encryption algorithm | ⚠️ | IKE SA: OBSERVED exactly. **ESP (the data)**: a 4–6-member candidate set (EXP-01); AES-128 vs 256 provably indistinguishable (EXP-02). In the lab every arm shares the IKE SA suite, so `cs-aes128cbc-sha256` reports "AES-CBC-256" (the IKE SA): a demo trap |
| Authentication algorithm | ⚠️ | IKE integrity OBSERVED; ESP integrity only within the candidate set; peer auth (PSK/cert) NOT_OBSERVABLE (EXP-11) |
| Key exchange | ✅ | incl. post-quantum ML-KEM and PQ downgrade (strongest area) |
| SA characteristics | ✅ | SPIs, exchanges, lifecycle, failure diagnosis |
| **Predict type of traffic inside ESP** | ⛔ | model exists (EXP-05 RF, F1 0.995–1.0 on lab data) but its label is suppressed (DEC-021) |

## d) Security assessment
| Crypto / cipher-suite strength, compliance, SA parameters | ✅ | 4 baselines (DISA SRG, RFC 8247, DST/NQM PQ, CVE watch), each verdict cited |
| Key lifetime | ⚠️ | only measured rekey intervals when ≥2 rekeys are in the capture (EXP-12); configured lifetime is invisible |
| **Replay protection** | ❌ | no finding at all (README: NOT_OBSERVABLE). ESP sequence-number behaviour *is* observable and unbuilt |
| Forward secrecy | ⚠️ | INFERRED only if a CREATE_CHILD_SA rekey is in the capture (EXP-03); otherwise NOT_OBSERVABLE |
| Metadata exposure | ✅ | size/timing bits + live RF attacker (T-082) |

## e) Outputs
| Executive + technical report | ✅ | `tunnelscope report` |
| Comprehensive security score / risk score | ⚠️⛔ | per-baseline scores only; a single number refused (DEC-007) |
| Traffic analysis, metadata inference | ✅ | leakage bits, attacker exposure |
| **Threat matrix** | ❌ | none |
| **AI confidence score** | ⚠️ | evidence tiers + attacker confidence; no labelled per-finding score |

## Deliverables
| Prototype, dashboard, report, technical docs, dataset | ✅ |
| AI classification engine | ⚠️ weakest item: identification is parsing; the ML (RF attacker, Isolation Forest) measures and detects, it doesn't classify for the user |
| Demonstration video | ❌ not recorded |

## Finding made during this validation: transport mode is sometimes provable
EXP-08 concluded mode is NOT_OBSERVABLE because, without a paired baseline, "every ESP length is
valid in both modes". That holds for large packets, not small ones. A tunnel-mode ESP packet carries
a whole inner IP header, so its content has a floor. For AES-GCM over IPv4 that floor is 56 B:
8 B IV + 20 B inner IPv4 + 8 B minimal ICMP + 2 B trailer, padded to 4, + 16 B ICV. Our captures:
tunnel minimum **56**, transport minimum **36** (both pairs). One packet below the tunnel floor for
every candidate cipher proves transport mode, with one caveat: TFC dummy packets (next header 59)
can be tiny in either mode. The inference is one-way: a packet at or above the floor proves nothing.
Worth a pre-registered experiment; would turn a ❌ into "INFERRED when provable, else UNKNOWN".

Also: `experiments/RESULTS.md` line 197 still lists mode inference as "untested"; stale since EXP-08.


## Status after T-083 (2026-09-20, same day)
Built from `build/08-PS-GAP-CLOSURE-PLAN.md`, each item with tests and an end-to-end run.

| PS item | Before | Now | Evidence |
|---|---|---|---|
| Traffic types (VoIP, WhatsApp, e-mail, web, ICMP, video) | ⚠️ 5 shapes | ✅ 8 shapes incl. e-mail, messaging (WhatsApp-like), ICMP; still shape models, not real apps | `testbed/scripts/tgen.py`, EXP-15 (152 sessions) |
| Different DH groups | ⚠️ | ✅ MODP-1024/1536/2048/3072/4096, ECP-256/384, Curve25519, +ML-KEM-768 | EXP-15 part B, 9/9 match swanctl |
| AH | ❌ | ✅ lab arms + parsing: mode and integrity from the plaintext header, AH-only fails confidentiality | EXP-15 part C, 5/5 |
| Live network streams | ❌ | ✅ `tunnelscope live` / `serve --live-*`: capture windows; dashboard Live tab; Docker downgrade run flagged | `tunnelscope/live/`, `testbed/scripts/run_live_demo.sh` |
| Tunnel / transport mode | ❌ | ⚠️→✅ AH: observed; ESP: transport proven below the size floor, else an ACK-size model (44/64 held-out sessions answered, 100% correct) for TCP over AEAD; else unknown. Never for UDP/ICMP-only or CBC tunnels | EXP-14 |
| Encryption algorithm (demo trap) | ⚠️ | ⚠️ labelled apart: "Handshake (IKE SA) encryption" vs "Data (ESP) cipher: candidates". The data cipher is still a candidate set (wire limit) | `tunnelscope/report/labels.py` |
| Predict traffic type | ⛔ | ✅ shown with probability + alternatives (macro-F1 0.995, TFC 0.958); abstains when windows disagree; known weakness stated with the answer (mixed video+interactive reads as web) | EXP-15 part A, DEC-027 |
| Replay protection | ❌ | ✅ per-SPI sequence analysis + RFC4303-SEQ rule; capture duplicates not called replays; receiver enforcement still not visible | `tunnelscope/evidence/protocol.py` |
| Threat matrix | ❌ | ✅ 12 threats × likelihood/impact, each citing its evidence | `tunnelscope/risk/risk.py` |
| Risk score | ⛔ | ✅ one 0–100 risk score with drivers + coverage; per-baseline scores still shown | DEC-028 |
| AI confidence score | ⚠️ | ✅ model confidence on every model output; evidence confidence per tunnel; confidence column in Evidence | |
| Cipher strength (3DES) | — | ✅ RFC 8221 baseline: 3DES, AH integrity, confidentiality | `rules/rfc8221-4303-ipsec.yaml` |
| Demo video | ❌ | ❌ user records it; script updated (`build/sih/DEMO-SCRIPT.md`) | |

Still true after T-083: the AI identifies the traffic type, mode (partly) and anomalies; the IKE
fields are still read by parsing, which is the correct method for plaintext. Key length on the ESP
side is still impossible from outside (EXP-02). Only one IPsec stack (strongSwan 6.1) produced the
new captures.


## After EXP-16 (2026-09-20): what the generalisation tests changed
- **Traffic types:** the dataset now includes **real applications** (Chromium over HTTPS, OpenSSH
  shell and SFTP, Postfix/swaks e-mail, XMPP messaging, ffmpeg RTP, ping) captured through the
  tunnel, alongside the synthetic shapes: 216 sessions in total.
- **A second IPsec implementation:** the same classes captured through **Libreswan 5.4**. The
  strongSwan-trained model scored **1.000** on them, so nothing in the method depends on the stack.
- **The honest finding:** a model trained only on the synthetic shapes scored **0.461** on real
  applications (file transfer 0.00). Accuracy in this task is set by how much the training traffic
  resembles the traffic in front of it — not by model tuning, and not by more repetitions (adding
  two more moved the score by 0.000).
- **Mixed traffic**, EXP-15's failed prediction, is now caught by a second-stage detector (92.9% of
  mixed sessions, 8.3% of single ones wrongly flagged, and 100% of the video+interactive case).
