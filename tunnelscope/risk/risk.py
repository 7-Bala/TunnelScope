"""Threat matrix, risk score and evidence confidence (T-083, PS e).

Built only from verdicts and findings the pipeline already produced (I8).
Each threat names the evidence that raised or cleared it; a threat whose
evidence is UNKNOWN is "not assessable" and is never counted as mitigated.

Risk score (DEC-028): noisy-OR over present threats,
    risk = 100 * (1 - prod(1 - 0.6 * likelihood * impact / 9)),
likelihood and impact on 1..3. One critical threat (3x3) gives 60, two give
84; adding a present threat never lowers the score; 0 means no threat was
seen, which is NOT the same as safe: coverage is always shown next to it.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

LEVEL = {1: "low", 2: "medium", 3: "high"}


@dataclass
class Threat:
    id: str
    name: str
    impact: int
    description: str
    status: str = "not_assessable"     # present | not_seen | mitigated | not_assessable
    likelihood: int = 0
    evidence: list = field(default_factory=list)
    reason: str = ""

    def as_dict(self):
        d = asdict(self)
        d["likelihood_label"] = LEVEL.get(self.likelihood, "-")
        d["impact_label"] = LEVEL[self.impact]
        return d


def _v(verdicts, rid):
    return next((v for v in verdicts if v.rule_id == rid), None)


def _f(findings, name):
    f = findings.get(name)
    return f if f is not None and f.status.value not in ("UNKNOWN", "NOT_OBSERVABLE") else None


def threats(record, verdicts, anomaly: dict | None = None) -> list[Threat]:
    F = record.findings
    out = []

    def rule_threat(t: Threat, rules: list[tuple[str, int]]):
        """present if any listed rule FAILs (likelihood = the highest given);
        mitigated if all that were judged PASS and at least one was judged."""
        judged = [(rid, lk, _v(verdicts, rid)) for rid, lk in rules]
        fails = [(rid, lk, v) for rid, lk, v in judged if v and v.verdict == "FAIL"]
        passes = [rid for rid, lk, v in judged if v and v.verdict == "PASS"]
        if fails:
            t.status, t.likelihood = "present", max(lk for _, lk, _ in fails)
            t.evidence = [rid for rid, _, _ in fails]
            t.reason = "; ".join(v.message or v.title for _, _, v in fails)
        elif passes and len(passes) == len([1 for _, _, v in judged if v and v.verdict in ("PASS", "FAIL")]) and passes:
            t.status, t.evidence, t.reason = "mitigated", passes, "the rules that test for it pass"
        else:
            t.reason = "the evidence for this threat is not visible in this capture"
        out.append(t)

    rule_threat(Threat("TH-01", "Key exchange broken by cryptanalysis", 3,
                       "a weak Diffie-Hellman group lets a capable attacker recover the keys and decrypt all traffic"),
                [("RFC8247-DH-MUST", 3), ("V-207193", 1)])   # DISA's group>=16 is stricter policy than a practical break
    rule_threat(Threat("TH-02", "Harvest now, decrypt later (quantum)", 3,
                       "recorded traffic is decrypted once a large quantum computer exists; classical key exchange only"),
                [("DST-PQ-KE", 1), ("DST-PQ-DOWNGRADE", 3)])   # a future capability: low today unless a PQ offer was downgraded
    t = Threat("TH-03", "Downgrade attack", 3,
               "an attacker in the path steers the peers to the weakest option both still accept")
    rule_threat(t, [("DST-PQ-DOWNGRADE", 3), ("RFC8247-DH-OFFER", 2)])
    if anomaly and any(a.get("kind") == "downgrade" for a in anomaly.get("anomalies", [])):
        # Only a rule that FAILED is evidence of the threat: if the rules had cleared it (or could not
        # judge it), their ids and reason must not be presented as support for "present".
        by_rules = t.status == "present"
        t.status, t.likelihood = "present", 3
        t.evidence = (t.evidence if by_rules else []) + ["anomaly: downgrade from this tunnel's usual crypto"]
        t.reason = (t.reason + "; " if by_rules and t.reason else "") + "this tunnel was stronger before"
    rule_threat(Threat("TH-04", "Weak or legacy cipher", 2,
                       "an outdated or non-recommended cipher weakens confidentiality"),
                [("RFC8247-ENCR", 2), ("RFC8221-ESP-3DES", 2)])
    rule_threat(Threat("TH-05", "Tampering via weak integrity", 2,
                       "a weak integrity algorithm makes forging or altering protected messages easier"),
                [("V-207223", 1), ("RFC8221-AH-INTEG", 3), ("RFC8221-AH-LEGACY", 1)])
    rule_threat(Threat("TH-06", "Legacy protocol (IKEv1)", 3,
                       "IKEv1 is retired and has known weaknesses (e.g. aggressive-mode PSK cracking)"),
                [("V-207205", 2)])
    rule_threat(Threat("TH-07", "No confidentiality (plaintext payload)", 3,
                       "AH authenticates but does not encrypt: anyone on the path reads the content"),
                [("RFC4301-CONFIDENTIALITY", 3)])
    rule_threat(Threat("TH-08", "Replay of captured packets", 2,
                       "an attacker re-sends recorded packets; only the receiver's anti-replay window stops them"),
                [("RFC4303-SEQ", 3)])
    for tt in out:
        if tt.id == "TH-08" and tt.status == "mitigated":
            tt.status, tt.reason = "not_seen", ("no sequence number repeated on the wire; whether the receiver "
                                                "would drop a replay (anti-replay window) is not visible passively")
    rule_threat(Threat("TH-09", "Pre-authentication exploitation (CVE-2026-78135)", 3,
                       "a Child SA created before IKE_AUTH completes on vulnerable software"),
                [("CVE-2026-78135", 3)])

    # TH-10 traffic analysis: from the measured attacker exposure
    t = Threat("TH-10", "Traffic analysis (metadata exposure)", 1,
               "sizes and timing reveal what kind of traffic is inside, without breaking encryption")
    ax = _f(F, "attacker_exposure")
    if ax and isinstance(ax.value, dict):
        lk = {"high": 3, "medium": 2, "low": 1}[ax.value["level"]]
        t.status, t.likelihood = ("present" if lk >= 2 else "not_seen"), lk
        t.evidence, t.reason = ["attacker_exposure"], ax.note
    elif _f(F, "metadata_exposure"):
        mx = F["metadata_exposure"].value
        t.status, t.likelihood = "present", 1
        t.evidence = ["metadata_exposure"]
        t.reason = f"size channel {mx.get('size_bits')} bits, timing {mx.get('timing_bits')} bits per packet exposed"
    else:
        t.reason = "too little ESP traffic to measure"
    out.append(t)

    # TH-11 no forward secrecy
    t = Threat("TH-11", "No forward secrecy on rekey", 2,
               "one stolen key decrypts past and future child SAs derived without a fresh key exchange")
    pf = _f(F, "pfs")
    if pf is not None:
        if pf.value is False:
            t.status, t.likelihood, t.reason = "present", 1, pf.note or "rekey without a fresh key exchange"
        else:
            t.status, t.reason = "mitigated", "rekeys carry a fresh key exchange"
        t.evidence = ["pfs"]
    else:
        t.reason = "no rekey in the capture, so PFS cannot be told"
    out.append(t)

    # TH-12 configuration drift
    t = Threat("TH-12", "Configuration drift", 2, "the tunnel's crypto or behaviour changed from what it usually is")
    if anomaly and anomaly.get("status") == "anomalous":
        real = [a for a in anomaly["anomalies"] if a["severity"] != "informational"]
        t.status, t.likelihood = "present", 3 if any(a["severity"] == "high" for a in real) else 2
        t.evidence, t.reason = ["anomaly"], "; ".join(a["message"] for a in real[:3])
    elif anomaly and anomaly.get("status") == "normal":
        t.status, t.reason, t.evidence = "mitigated", "matches this tunnel's learned normal", ["anomaly"]
    else:
        t.reason = ("still learning this tunnel's normal" if anomaly else
                    "anomaly history is off (start the engine with --history)")
    out.append(t)
    return out


def risk_score(ts: list[Threat]) -> dict:
    present = [t for t in ts if t.status == "present"]
    keep = 1.0
    for t in present:
        keep *= 1 - 0.6 * t.likelihood * t.impact / 9
    score = round(100 * (1 - keep))
    band = ("critical" if score >= 70 else "high" if score >= 45 else "medium" if score >= 20
            else "low" if score > 0 else "none observed")
    assessable = [t for t in ts if t.status != "not_assessable"]
    top = sorted(present, key=lambda t: -t.likelihood * t.impact)[:3]
    return {"score": score, "band": band, "present": len(present),
            "assessable": len(assessable), "total": len(ts),
            "coverage": round(len(assessable) / len(ts), 2),
            "top": [{"id": t.id, "name": t.name, "likelihood": t.likelihood, "impact": t.impact} for t in top],
            "note": ("0 means no threat was seen in what could be assessed, not that the tunnel is safe"
                     if score == 0 else f"driven by {', '.join(t.name.lower() for t in top)}")}


def evidence_confidence(record) -> dict:
    """How much of the assessment rests on what was seen, vs inferred, vs not
    visible. OBSERVED/MEASURED count 1.0; INFERRED counts its own confidence."""
    obs = inf = none = 0
    total_conf = 0.0
    for f in record.findings.values():
        s = f.status.value
        if s in ("OBSERVED", "MEASURED"):
            obs += 1; total_conf += 1.0
        elif s == "INFERRED":
            inf += 1; total_conf += float(f.confidence or 0.0)
        elif s != "CONTRADICTORY":
            none += 1
    n = obs + inf + none
    return {"score": round(100 * total_conf / n) if n else 0, "observed": obs, "inferred": inf,
            "not_visible": none, "attributes": n,
            "note": "share of the attributes TunnelScope assesses that this capture supports, weighted by how "
                    "directly each was established (observed 1.0, inferred at its stated confidence, unknown 0)"}


def assess_risk(record, verdicts, anomaly: dict | None = None) -> dict:
    ts = threats(record, verdicts, anomaly)
    return {"threats": [t.as_dict() for t in ts], "risk": risk_score(ts),
            "confidence": evidence_confidence(record)}
