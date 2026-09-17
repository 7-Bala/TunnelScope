# TunnelScope — Jury Q&A Prep

Hard questions a technical jury will ask, with evidence-backed answers. The weak spots are here on
purpose — answering them first is stronger than being caught by them.

## On the AI / "it's not AI-driven enough"

**Q: The PS says AI-driven. You only use ML in one place. Isn't that under-delivering?**
The PS title says AI-driven; the PS *goal* is a correct security assessment. We use ML exactly where
it measurably beats a non-AI baseline — leakage measurement, where a depth-2 rule captures only ~half
the exposure (EXP-05: F1 0.51 vs 0.995). Four capabilities we *expected* to need ML — PFS, failure
diagnosis, fingerprinting, mode — we tested and found are exact structural signatures needing none
(EXP-03/06/07/08). Decorative ML on a problem that's actually deterministic is what loses credibility,
and the encrypted-traffic-ML literature is in a documented reproducibility crisis (research doc 04).

**Q: So could you have just trained a classifier for the traffic type, like the PS asks?**
We tested it. On mixed traffic it gives **confident wrong answers** — a tunnel carrying video +
interactive was labelled "web" 100% of the time (EXP-05). Reporting that as fact would be false
assurance. We reframed it to *measured leakage in bits*, which is honest and actionable.

## On rigor / "how do we trust your numbers"

**Q: How do we know you didn't tune this to look good?**
Every experiment is **pre-registered** — predictions written and committed to git *before* the data
existed (see EXPERIMENT-REGISTER and git timestamps). The DEVELOP scoring weights were committed
before any concept was scored. 18/18 predictions held; where our own earlier claims were wrong
(e.g. "Wireshark can't decode PQ IKE"), we corrected them on the record.

**Q: Ground truth — isn't it circular to validate against your own tool?**
No. Ground truth is **causal**: the configuration we set, confirmed by the endpoint's own
`swanctl`/`pluto` log (T2). The analyzer's inference (T0/T1) is checked against that, never against
itself. 69/69 captures match.

## On the downgrade / PQ claim

**Q: Wireshark can already parse ML-KEM. What's new?**
Parsing ≠ assessment. Wireshark shows you `ADDKE1`. It doesn't tell you the tunnel was **offered PQ
but negotiated classical**, or map that to the DST mandate, or do it across a fleet — and the tools
SOCs actually run (Suricata, Zeek, nDPI) can't even parse the field. We proved the downgrade detector
on a dedicated arm and confirmed the ML-KEM identity across four independent sources (IANA, Wireshark
master, tshark, strongSwan). And we say plainly what we can't tell: the responder's selection is
plaintext, but *why* it picked classical — configured policy or an attacker-induced retry — isn't
attributable passively without private keys or endpoint telemetry.

**Q: Would your PQ detector work on Cisco/Palo Alto?**
The decisive signals (IKE_INTERMEDIATE presence, the ADDKE transform) are protocol-defined, so they
should — but we've validated on strongSwan and Libreswan only, and EXP-07 showed the *notify*-based
signal is implementation-specific (it would false-positive on Libreswan), which is exactly why we
made the deterministic exchange-type signal the decisive one, not the notify.

## On limits (say these before they ask)

**Q: Your leakage accuracy is ~100% — real traffic isn't that separable.**
Correct, and we say so. The five classes were synthetic and deliberately distinct; the ~100% is a
property of those shapes, not real traffic. What transfers is the **method** and the **relative**
result (padding kills the size channel but not timing). In deployment the tool reports measured
leakage on the operator's *own* traffic, inheriting no synthetic number.

**Q: Can it assess anti-replay enforcement (DISA V-207212)?**
Passively, no — and it says NOT-OBSERVABLE rather than guessing. Receiver-side enforcement is only
visible with endpoint telemetry (T2) or an authorized active test (T4). That honesty is the point.

**Q: Two implementations is a small sample.**
Agreed; it's stated as the scope of every claim. Protocol-fact signals held identically on both
(the PFS gap is 256 bytes on each). Vendor appliances are the clear next step.

## On deployment

**Q: Does it need cloud / internet / decryption?**
No. Offline by default (air-gap-friendly for NTRO), no decryption for the core assessment — it works
on plaintext IKE structure and ESP metadata. Endpoint telemetry (T2) and keys (T3) are optional
escalations that unlock more, with each finding declaring which tier produced it.

## The one-sentence close
"We built the assessment layer that's missing: it tells you what your IPsec actually negotiated,
whether it's post-quantum or fell back to classical, against which standard it complies — and it tells you
plainly what it cannot see, so you never act on a confident guess."
