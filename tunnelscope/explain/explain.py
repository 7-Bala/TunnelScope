"""Plain-English explanations of a tunnel's verdicts (T-082), for non-experts.

Deterministic and fully offline: every FAIL, every UNKNOWN/not-observable gap,
the attacker-exposure and anomaly results, each rendered from the verdict data
plus a fixed glossary of what the rule means and what to do. No language model
of any kind, by decision (2026-09-20: every model in TunnelScope is trained by
the project on its own data; text generation is not a modelling problem here).
Invariant I8 holds by construction: the only facts are the evidence graph's.
"""
from __future__ import annotations

# What each rule means, in plain words, and what to do about a FAIL.
GLOSSARY = {
    "V-207205": ("the tunnel uses the old IKEv1 handshake instead of IKEv2",
                 "IKEv1 has known weaknesses and is retired by current standards",
                 "move the tunnel to IKEv2"),
    "V-207193": ("the key exchange uses a Diffie-Hellman group below what the US DoD requires (group 16 or higher)",
                 "a weaker key exchange is easier for a well-funded attacker to break later",
                 "configure a stronger group, such as ECP-384 or MODP-4096"),
    "V-207223": ("the handshake's integrity check is weaker than SHA-384",
                 "the integrity check is what stops tampering with the handshake",
                 "use a SHA-384 or SHA-512 based integrity setting"),
    "RFC8247-DH-MUST": ("the tunnel agreed on a key-exchange group that the IPsec standard (RFC 8247) says must not or should not be used",
                        "these groups are too weak today",
                        "remove that group from both ends and use MODP-2048 or stronger, or an elliptic-curve group"),
    "RFC8247-DH-OFFER": ("one side still OFFERS key-exchange groups that RFC 8247 forbids, even if this tunnel did not pick one",
                         "any peer (or an attacker in the middle) that asks for the weak group can get it",
                         "delete the weak groups from that endpoint's proposal list"),
    "RFC8247-ENCR": ("the handshake is not encrypted with AES",
                     "RFC 8247 recommends AES, preferably AES-GCM",
                     "switch the handshake cipher to AES-GCM or AES-CBC"),
    "CVE-2026-78135": ("the handshake shows the pattern of a known attack: a tunnel request sent before the peers finished proving who they are",
                       "on vulnerable software this lets an unauthenticated party act before authentication",
                       "patch the VPN software and check its logs for the peer that did this"),
    "DST-PQ-KE": ("the key exchange is classical only, with no post-quantum part",
                  "traffic recorded today could be decrypted later by a large quantum computer",
                  "plan a move to a hybrid post-quantum key exchange (ML-KEM added to the classical one)"),
    "DST-PQ-DOWNGRADE": ("a post-quantum key exchange was offered but the tunnel fell back to classical only",
                         "that fallback is exactly what a downgrade attack would cause",
                         "find out why the peer refused ML-KEM, and stop allowing the classical-only fallback"),
}

# what a status means, for gaps
_GAP = {"UNKNOWN": "could not be determined from this capture",
        "NOT_OBSERVABLE": "cannot be seen from a passive capture at all (it needs endpoint data)"}


def _posture_line(sa: dict) -> str:
    p = sa.get("posture") or "unknown"
    return f"Post-quantum posture: {p}."


def explain_sa(sa: dict, anomaly: dict | None = None) -> dict:
    """Stage 1. `sa` is one entry of api.server.analysis_json()['sas']."""
    fails = [v for v in sa["verdicts"] if v["verdict"] == "FAIL"]
    passes = [v for v in sa["verdicts"] if v["verdict"] == "PASS"]
    highs = [v for v in fails if v["severity"] == "high"]
    head = (f"This tunnel between {sa['src']} and {sa['dst']} was checked against {len(sa['verdicts'])} rules: "
            f"{len(passes)} passed, {len(fails)} failed"
            + (f", {len(highs)} of them high severity" if highs else "")
            + ", and the rest could not be judged from this capture.")
    points = []
    for v in sorted(fails, key=lambda v: ({"high": 0, "medium": 1}.get(v["severity"], 2), v["rule_id"])):
        g = GLOSSARY.get(v["rule_id"])
        ob = v.get("observed")
        ob = ", ".join(map(str, ob)) if isinstance(ob, list) else ob
        seen = f" (seen: {ob})" if ob not in (None, "") else ""
        if g:
            points.append({"kind": "fail", "rule_id": v["rule_id"], "severity": v["severity"],
                           "text": f"{v['rule_id']} ({v['severity']}): {g[0]}{seen}. Why it matters: {g[1]}. "
                                   f"What to do: {g[2]}."})
        else:
            points.append({"kind": "fail", "rule_id": v["rule_id"], "severity": v["severity"],
                           "text": f"{v['rule_id']} ({v['severity']}): {v['title']}{seen}."})
    f = {x["attribute"]: x for x in sa.get("findings", [])}
    ax = f.get("attacker_exposure")
    if ax and ax["status"] == "MEASURED":
        points.append({"kind": "exposure", "text": f"Traffic shape: {ax['note']}"})
    unseen = [f"{x['attribute'].replace('_', ' ')} {_GAP[x['status']]}"
              for x in sa.get("findings", []) if x["status"] in _GAP]
    if anomaly and anomaly.get("status") == "anomalous":
        for a in anomaly["anomalies"]:
            if a["severity"] != "informational":
                points.append({"kind": "anomaly", "text": f"Change from this tunnel's usual behaviour: {a['message']}."})
    elif anomaly and anomaly.get("status") == "learning":
        points.append({"kind": "anomaly", "text": f"Still learning this tunnel's normal behaviour "
                                                  f"({anomaly['observations']} of {anomaly['needed']} observations)."})
    if not fails:
        points.insert(0, {"kind": "ok", "text": "No rule failed. That is not the same as secure: "
                                                "some checks could not be made from this capture (listed below)."})
    return {"summary": head + " " + _posture_line(sa), "points": points, "unseen": unseen, "source": "template"}


def as_text(e: dict) -> str:
    L = [e["summary"], ""] + [f"- {p['text']}" for p in e["points"]]
    if e["unseen"]:
        L += ["", "Not visible in this capture:"] + [f"- {u}" for u in e["unseen"]]
    return "\n".join(L)
