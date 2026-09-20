# 15 — Public datasets and open-source alternatives (survey, 2026-09-20)

Asked for: external data to train/validate on, and existing open-source work worth using. Searched
2026-09-20. Everything below is recorded with its licence, because a dataset we cannot redistribute
is a dataset we cannot ship with the project.

## 1. Public datasets

| Dataset | What it is | Tunnel technology | Licence / access | Verdict |
|---|---|---|---|---|
| **ISCX VPN-nonVPN (ISCXVPN2016)**, UNB CIC | 28 GB pcap + flow CSVs, 14 classes (browsing, e-mail, chat, streaming, file transfer, VoIP, P2P — VPN and non-VPN) | **OpenVPN over UDP**, not IPsec | Free for research, citation required (Draper-Gil et al., ICISSP 2016). Direct download is now behind a browser form on cicresearch.ca; mirrors on Kaggle need an account | **Useful as an external benchmark for the traffic classifier** — its class list is close to ours. Not usable as IPsec data: OpenVPN's framing shifts every packet size. Needs a human to fetch it (account/form), so not automated here |
| **VNAT**, MIT Lincoln Laboratory | 36 GB pcap, 33,711 connections, 5 classes (streaming, VoIP, chat, command-and-control, file transfer) | VPN-tunnelled; the technology is not stated on the dataset page | **No licence stated**; the page directs licensing questions to their Technology Transfer Office | **Not used.** Unclear licence, and the tunnel technology is unconfirmed. Ask them before touching it |
| CESNET-TLS22 / QUIC22, CIC-Darknet2020, USTC-TFC2016 | large labelled traffic sets | TLS / QUIC / mixed — no VPN tunnel | CC-BY (CESNET) or research use | Not relevant: no IPsec, and the encapsulation is what our features measure |
| **Wireshark wiki IPsec sample captures** | small third-party IKEv2/ESP captures (2006–2021), several shipping their own `esp_sa` keys and readme stating the algorithms and mode | **Real IPsec**, other people's equipment | Public wiki samples; we download them on demand and redistribute nothing | **USED.** `build/validate_external.py`. See §3 — they found a real bug |

**The important finding: there is no public labelled IPsec/ESP traffic dataset.** Searches across
Zenodo, Kaggle, IMPACT, GitHub and the literature turned up VPN datasets built on OpenVPN, and IPsec
*sample captures* (a handful of packets), but nothing labelled for IPsec traffic analysis. Our own
EXP-15/16 tables (216 labelled sessions, 8 classes, two implementations, synthetic + real
applications, with per-session ground truth) appear to be the first of their kind, which is a reason
to publish them as a dataset alongside the tool.

## 2. Open-source alternatives and neighbours

| Project | What it does | Overlap with TunnelScope |
|---|---|---|
| **ike-scan** (royhills, GPL) | active IKE scanner: sends IKE_SA_INIT proposals and fingerprints the responder | Complementary and *deliberately out of scope* (DEC-005: active probing is T4, authorization-gated). It answers "what would this gateway accept", which we can only see when the peer offers it |
| **iker**, **ikepoke**, **IKEv3Analytica** | wrappers/testers around active IKE probing, PSK acceptance tests | Same: active, not passive assessment |
| **Zeek + zeek-spicy-ipsec** (Corelight) | a Zeek protocol analyzer for IKE/ESP: logs IKE transforms and ESP flows on a live sensor | The closest real alternative for the *ingest* half. Worth considering as a second front-end for continuous monitoring (Zeek logs → TunnelScope assessment); it has no baselines, verdicts, scoring or PQ analysis |
| **nDPI / NFStream** (LGPL) | deep packet inspection and flow metadata, with ML-friendly features | Could replace our feature extraction for the classifier. Their strength is breadth of protocols; ours is IPsec-specific arithmetic (ESP overhead, inner-header sizes) they do not model |
| **Other SIH 2026 PS-26160 entries** (`ipsecAnalyzer-SIH26`, `ALLAN-KJ/SIH-2026`, `sentinel-ipsec`, `InnovAuraz/ESPect`) | same problem statement: IKE dissection, a posture/risk score, claims of ML/XGBoost/LLM remediation | Same surface. None publishes validation metrics, a dataset, or a held-out evaluation; ESPect describes a labelled testbed but releases no data. We read their READMEs only — no code was taken |

**What we would adopt:** Zeek's analyzer as an optional live-sensor front-end (it is designed for
exactly the deployment our live mode targets), and ISCXVPN2016 as an external classifier benchmark
once someone fetches it. Nothing else changes a decision we have already made.

## 3. What the third-party captures found (T-085)

Running our pipeline over the Wireshark captures exposed a bug that 103 of our own captures never
could: **an ICMP error quotes the header of the packet that caused it**, so tshark's `esp` / `ah` /
`isakmp` display filters also match ESP/AH/ISAKMP headers *inside* ICMP errors. With
`occurrence=a` the quoted packet's `ip.len` was read instead of the real one. In
`ipsec_esp_capture_2`, 312 of 624 matching frames were quoted headers, and the resulting wrong
lengths made the cipher sieve **exclude the true cipher** — the one thing EXP-01 claimed it never
does.

The first fix (drop every frame containing ICMP) was wrong and our own tests caught it: AH does not
encrypt, so a genuine AH packet carrying a ping legitimately contains an ICMP layer. The shipped fix
reads `frame.protocols` and keeps a row only when the IPsec layer comes **before** any ICMP layer
(`ip:ah:ip:icmp` is real, `ip:icmp:ip:esp` is quoted).

Also widened the ESP cipher sieve with the families those captures used (DES-CBC, Blowfish, Twofish,
CAST, NULL encryption, AES-CTR with SHA-1) and made the finding state the table's scope, since ESP
with no integrity at all is not modelled.

**Lesson recorded:** every previous validation used traffic we generated ourselves. One afternoon
against other people's captures found a correctness bug. Third-party captures are now a standing
check (`build/validate_external.py`).
