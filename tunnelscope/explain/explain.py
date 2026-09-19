"""Plain-English explanations of a tunnel's verdicts (T-082), for non-experts.

Two stages, and the first is always the source of truth (invariant I8: nothing
here may add a fact the evidence graph doesn't hold):

1. TEMPLATE (always, offline, deterministic): every FAIL, every UNKNOWN/not-
   observable gap, the attacker-exposure and anomaly results, each rendered from
   the verdict data plus a fixed glossary of what the rule means and what to do.
2. LLM REWRITE (optional, off by default): an LLM rewrites stage 1 into flowing
   prose. It is given ONLY stage 1's text, and its output is checked before
   use: every rule ID, algorithm name and number in it must already appear in
   stage 1, and it must not say "compliant". If the check fails, stage 1 is
   returned with the reason. So an LLM can change the wording, never the facts.

Providers (TUNNELSCOPE_LLM or --llm): none (default: I9, offline by default),
ollama (a local open-weight model at 127.0.0.1:11434, works air-gapped;
TUNNELSCOPE_OLLAMA_MODEL, default llama3.2), claude (Claude Opus 5 through the
Anthropic API; needs network, the `anthropic` package and credentials).
"""
from __future__ import annotations

import json
import os
import re
import urllib.request

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


# ---------------------------------------------------------------- LLM stage ---

SYSTEM = ("You rewrite a network-security finding for a manager who is not a network engineer. "
          "Use ONLY the facts in the text you are given. Do not add any rule, algorithm, number, cause, "
          "risk or recommendation that is not in it. Keep every rule ID exactly as written. "
          "Never say the tunnel is compliant or secure. Write 1 short paragraph, then the actions as a short "
          "list, then one sentence on what the capture could not show. Plain text, no headings.")

_TOKENS = [re.compile(r"\b(?:V-\d{6}|RFC ?\d{4}(?:-[A-Z]+)*|CVE-\d{4}-\d+|DST-[A-Z-]+)\b"),
           re.compile(r"\b(?:AES|MODP|ECP|SHA|HMAC|3DES|DES|MD5|ML-KEM|Curve|ChaCha|IKEv)[\w-]*", re.I),
           re.compile(r"\d+(?:\.\d+)?")]
_BANNED = re.compile(r"\b(complian(?:t|ce)|compl(?:y|ies))\b", re.I)


def check_rewrite(source: str, rewrite: str) -> str | None:
    """None if `rewrite` introduces no new fact-bearing token; else the reason."""
    norm = lambda s: re.sub(r"\s+", "", s).lower()
    src = norm(source)
    for rx in _TOKENS:
        for tok in rx.findall(rewrite):
            if norm(tok) not in src:
                return f"introduced '{tok}', which is not in the evidence"
    m = _BANNED.search(rewrite)
    if m:
        return f"used '{m.group(0)}' (a capture shows evidence, never compliance)"
    return None


def _claude(text: str) -> tuple[str, str]:
    import anthropic
    client = anthropic.Anthropic()
    # Server-side refusal fallback on (Opus 5 default in the Claude API skill):
    # a declined request is re-run on a fallback model inside the same call.
    msg = client.beta.messages.create(
        model="claude-opus-5", max_tokens=16000,
        betas=["server-side-fallback-2026-07-01"], fallbacks="default",
        output_config={"effort": "medium"},
        system=SYSTEM, messages=[{"role": "user", "content": text}])
    if msg.stop_reason == "refusal":
        raise RuntimeError("the model declined")
    return "".join(b.text for b in msg.content if b.type == "text").strip(), msg.model


def _ollama(text: str) -> tuple[str, str]:
    model = os.environ.get("TUNNELSCOPE_OLLAMA_MODEL", "llama3.2")
    body = json.dumps({"model": model, "stream": False, "options": {"temperature": 0},
                       "messages": [{"role": "system", "content": SYSTEM},
                                    {"role": "user", "content": text}]}).encode()
    req = urllib.request.Request("http://127.0.0.1:11434/api/chat", body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)["message"]["content"].strip(), model


PROVIDERS = {"claude": _claude, "ollama": _ollama}


def llm_provider() -> str:
    return (os.environ.get("TUNNELSCOPE_LLM") or "none").lower()


def explain_with_llm(sa: dict, anomaly: dict | None = None, provider: str | None = None) -> dict:
    """Stage 1, then (if a provider is set) stage 2 with the fact check.
    Always returns something usable; `source` says which stage it is."""
    base = explain_sa(sa, anomaly)
    text = as_text(base)
    provider = (provider or llm_provider()).lower()
    if provider in ("", "none"):
        return {**base, "text": text}
    fn = PROVIDERS.get(provider)
    if fn is None:
        return {**base, "text": text, "llm_error": f"unknown LLM provider '{provider}' (use none, ollama or claude)"}
    try:
        out, model = fn(text)
    except Exception as e:     # no network, no model, no key: the template still stands
        return {**base, "text": text, "llm_error": f"{provider}: {type(e).__name__}: {e}"[:300]}
    bad = check_rewrite(text, out)
    if bad:
        return {**base, "text": text, "llm_rejected": f"{provider} ({model}) {bad}; showing the evidence text instead"}
    return {**base, "text": out, "source": provider, "model": model}
