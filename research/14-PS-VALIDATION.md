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
