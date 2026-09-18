# EXP-13 — Cloud-VPN-style proposal sets (mentor follow-up C1) — PRE-REGISTRATION

**Written 2026-09-18, before any EXP-13 capture.** Committed on its own so the git history shows the
predictions came first.

## Question
Office-to-cloud links are usually IPsec site-to-site VPNs. Does TunnelScope assess them correctly when
the cloud side accepts a provider's default proposal set, which includes weak options?

## What is being emulated (and what is not)
The **AWS Site-to-Site VPN default tunnel options**, from AWS's documentation
(`docs.aws.amazon.com/vpn/latest/s2svpn/tunnel-configure.html`, read 2026-09-18):
IKE versions ikev1 + ikev2; phase 1 encryption AES128, AES256, AES128-GCM-16, AES256-GCM-16; phase 1
integrity SHA1, SHA2-256/384/512; phase 1 DH 2, 14–24; phase 2 DH 2, 5, 14–24 (no "none", so PFS is
required); startup action default `Add` (the customer gateway initiates), optional `Start` (AWS
initiates).

The "cloud" peer is **strongSwan configured to accept exactly that set**. This tests TunnelScope
against the cloud provider's *policy*, not AWS's own IKE implementation, whose on-wire quirks (vendor
IDs, fragmentation, notify order) may differ (EXP-07/10 showed such details are
implementation-dependent). The only claim this experiment can support is "assesses cloud-style
proposal sets correctly", not "tested against AWS". A real AWS tunnel is follow-up C2 (needs an AWS
account).

Deviations from a real AWS tunnel, fixed in advance: traffic selectors are host /32s, not AWS's
0.0.0.0/0 (a 0/0 policy inside a container captures its own IKE traffic; TS are inside encrypted
IKE_AUTH and invisible to TunnelScope either way); NAT traversal is forced with strongSwan
`encap = yes` rather than a real NAT box (identical on the wire: UDP 4500, non-ESP marker).

## Arms (customer gateway = alice, "cloud" = bob; strongSwan 5.9.8; keyless router vantage)
| Arm | Who initiates | Customer proposal | NAT-T |
|---|---|---|---|
| C-W "legacy branch router" | customer | IKEv2 aes128-sha1-modp1024 (DH 2); ESP aes128-sha1-modp1024 | yes |
| C-M "common default" | customer | IKEv2 aes256-sha256-modp2048; ESP aes256-sha256-modp2048 | no |
| C-S "hardened" | customer | IKEv2 aes256gcm16-prfsha384-ecp384; ESP aes256gcm16-ecp384 | yes |
| C-V1 "IKEv1 legacy" | customer | IKEv1 main mode aes128-sha1-modp1024 | no |
| A-START "cloud initiates" | cloud (`Start`) | cloud offers its full default set; customer accepts aes256-sha256-modp2048 | no |

Ground truth (T2): `swanctl --list-sas` on both peers, recorded with each capture.

## Predictions
- **P1 (IKEv2 arms C-W, C-M, C-S, A-START):** `ike_version` IKEv2, and `ike_encr` / `ike_dh_group`
  OBSERVED and equal to T2. For C-W and C-M, `ike_integ` equals T2 too.
- **P2 (verdicts), exactly:**
  - C-W: RFC8247-DH-MUST **FAIL** (group 2 < 14), V-207193 **FAIL**, V-207223 **FAIL** (SHA-1),
    V-207205 PASS, RFC8247-ENCR PASS.
  - C-M: RFC8247-DH-MUST PASS, V-207193 **FAIL** (14 < 16), V-207223 **FAIL** (SHA2-256).
  - C-S: RFC8247-DH-MUST PASS, V-207193 PASS (ECP-384 = 20), RFC8247-ENCR PASS.
  - A-START: same verdicts as C-M (the *selected* suite is what is assessed).
- **P3 (C-S, AEAD):** AES-GCM carries no separate INTEG transform, so `ike_integ` has no value.
  Prediction: TunnelScope reports it UNKNOWN with the note "no IKE SA suite selected", which is
  **wrong wording** (a suite was selected; it has no integrity transform), and V-207223 comes out
  UNKNOWN. Expected to be a real, fixable gap.
- **P4 (C-V1):** `ike_version` IKEv1 OBSERVED and DISA V-207205 **FAIL**. The IKEv1 phase-1 suite is
  not extracted (known, plan §5 P2 item 11), so DH/integrity rules are UNKNOWN, **never PASS**.
- **P5 (A-START, offer exposure):** the cloud's IKE_SA_INIT request offers DH 2 and SHA-1 in
  plaintext. Prediction: TunnelScope does **not** currently report weak algorithms *offered* (only
  the selected suite), so the fact that this endpoint *would accept* DH 2 / SHA-1 from any peer is
  invisible in the report. Expected gap.
- **P6 (NAT-T arms C-W, C-S):** ESP is parsed (T-057 offsets) and the cipher-family sieve keeps the
  true family (C-W: AES-CBC; C-S: AES-GCM with CBC excluded).
- **P7:** no finding on any arm contradicts T2.

## Falsification
Any P1/P6/P7 mismatch with T2 is a correctness bug and is reported as such. P2 verdict mismatches
are bugs in either the extractor or the rules and are reported before any fix. P3/P5 are predicted
*gaps*: if TunnelScope already handles them, the prediction was wrong and is recorded as wrong.
