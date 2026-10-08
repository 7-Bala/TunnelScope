"""T-121 / EXP-28: does the traffic match the configuration?

A configuration OFFERS (proposal lists); the wire shows what was SELECTED. So a field "matches" when the wire
value is within what the config allows, is a "mismatch" when it is not, and is "not comparable" whenever the
wire cannot see it (UNKNOWN / NOT_OBSERVABLE, e.g. ESP key length, F-05) or the field only has meaning for the
other role. "not configured" means the config relies on the implementation's default, which TunnelScope does not
claim to know. An unobservable field is never reported as a match.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from ..evidence.record import EvidenceRecord, Status

MATCH, MISMATCH, NOT_COMPARABLE, NOT_CONFIGURED = "match", "mismatch", "not comparable", "not configured"
# EXP-28 (post-result, disclosed): when the wire finding is only INFERRED (the ESP sieve's candidate set, the
# size-based PFS inference) agreement means "not ruled out", not "confirmed": CONSISTENT, never MATCH.
CONSISTENT = "consistent"

# configured ESP (encr family, integ) -> the T0 sieve's family names (tunnelscope/evidence/extract.py _SIEVE)
_SIEVE_INTEG = {"HMAC-SHA2-256-128": "HMAC-SHA256-128", "HMAC-SHA1-96": "HMAC-SHA1-96",
                "HMAC-SHA2-384-192": "HMAC-SHA384-192", "HMAC-SHA2-512-256": "HMAC-SHA512-256"}


@dataclass
class Comparison:
    field: str
    outcome: str
    config: object
    wire: object
    note: str


def esp_family(encr: str, integ: str | None) -> str | None:
    """The sieve family a configured ESP suite belongs to, or None if the sieve has no family for it."""
    if encr.startswith("AES-GCM-16"):
        return "AES-GCM-16"
    if encr.startswith("AES-CCM-16"):
        return "AES-CCM-16"
    if encr == "ChaCha20-Poly1305":
        return "ChaCha20-Poly1305"
    fam = {"AES-CBC": "AES-CBC", "AES-CTR": "AES-CTR", "3DES": "3DES-CBC"}.get(
        next((k for k in ("AES-CBC", "AES-CTR", "3DES") if encr.startswith(k)), ""))
    if fam and integ in _SIEVE_INTEG:
        return f"{fam}+{_SIEVE_INTEG[integ]}"
    return None


def _wire(rec: EvidenceRecord, attr: str):
    f = rec.findings.get(attr)
    if f is None or f.status in (Status.UNKNOWN, Status.NOT_OBSERVABLE):
        return None, (f.status.value if f else "absent")
    return f.value, f.status.value


def role(tunnel: dict, rec: EvidenceRecord) -> str | None:
    """'initiator' | 'responder' from the config's local address vs the IKE_SA_INIT request's sender."""
    req = next((m for m in getattr(rec, "_ike", []) if m["exchange"] == 34 and not m["is_response"]), None)
    local = {a.strip() for a in (tunnel.get("local_addrs") or "").split(",") if a.strip()}
    if req is None or not local:
        return None
    return "initiator" if req["src"] in local else "responder" if req["dst"] in local else None


def reconcile(tunnel: dict, rec: EvidenceRecord) -> list[Comparison]:
    out: list[Comparison] = []
    me = role(tunnel, rec)

    def cmp_in(field, attr, offered, what):
        wv, st = _wire(rec, attr)
        if not offered:
            out.append(Comparison(field, NOT_CONFIGURED, None, wv, f"no {what} in the config (implementation default)"))
        elif wv is None:
            out.append(Comparison(field, NOT_COMPARABLE, sorted(offered), None, f"wire finding is {st}"))
        elif wv in offered:
            out.append(Comparison(field, MATCH, sorted(offered), wv, f"the wire's {wv} is offered by the config"))
        else:
            out.append(Comparison(field, MISMATCH, sorted(offered), wv,
                                  f"the wire shows {wv}, which this config does not offer {sorted(offered)}"))

    # IKE version
    wv, st = _wire(rec, "ike_version")
    cv = tunnel.get("ike_version")
    out.append(Comparison("ike_version", NOT_CONFIGURED if cv is None else NOT_COMPARABLE if wv is None
                          else MATCH if wv == cv else MISMATCH, cv, wv,
                          "version not set in config" if cv is None else f"wire {wv or st}"))
    props = tunnel.get("ike_proposals") or []
    for field, attr, key, what in (("ike_encr", "ike_encr", "encr", "IKE encryption"),
                                   ("ike_integ", "ike_integ", "integ", "IKE integrity"),
                                   ("ike_prf", "ike_prf", "prf", "IKE PRF"),
                                   ("ike_dh_group", "ike_dh_group", "ke", "IKE key-exchange group")):
        cmp_in(field, attr, {v for p in props for v in p[key]}, what)

    # what the initiator offered: only this config's own offer if it is the initiator
    wv, st = _wire(rec, "ike_offered_dh")
    groups = sorted({v for p in props for v in p["ke"]})
    if me != "initiator":
        out.append(Comparison("ike_offered_dh", NOT_COMPARABLE, groups or None, wv,
                              "the offered list is the initiator's; this config is " + (me or "of unknown role")))
    elif not groups:
        out.append(Comparison("ike_offered_dh", NOT_CONFIGURED, None, wv, "no groups in the config"))
    elif wv is None:
        out.append(Comparison("ike_offered_dh", NOT_COMPARABLE, groups, None, f"wire finding is {st}"))
    else:
        extra = sorted(set(wv) - set(groups))
        out.append(Comparison("ike_offered_dh", MISMATCH if extra else MATCH, groups, sorted(wv),
                              f"the wire offered {extra}, not in this config" if extra else "offer matches the config"))

    # RFC 9370 additional key exchange
    addke = sorted({v for p in props for vs in p["addke"].values() for v in vs})
    wv, st = _wire(rec, "pq_key_exchange")
    if not props:
        out.append(Comparison("pq_key_exchange", NOT_CONFIGURED, None, wv, "no IKE proposals in the config"))
    elif wv is None:
        out.append(Comparison("pq_key_exchange", NOT_COMPARABLE, addke, None, f"wire finding is {st}"))
    elif isinstance(wv, list):
        bad = sorted(set(wv) - set(addke))
        out.append(Comparison("pq_key_exchange", MISMATCH if bad else MATCH, addke, wv,
                              f"selected {bad}, which this config does not offer" if bad else "selected ADDKE is offered"))
    elif me == "initiator":
        offered_on_wire = wv == "offered-but-not-used"
        ok = offered_on_wire == bool(addke)
        out.append(Comparison("pq_key_exchange", MATCH if ok else MISMATCH, addke, wv,
                              "consistent with the config's offer" if ok else
                              ("the config offers ADDKE but the wire's offer had none" if addke else
                               "the wire's offer carried ADDKE; this config has none")))
    else:
        out.append(Comparison("pq_key_exchange", MATCH if not addke or wv == "offered-but-not-used" else NOT_COMPARABLE,
                              addke, wv, "no ADDKE selected" + ("" if not addke else
                              "; a responder config that offers ADDKE may still accept a classical proposal")))

    # RFC 8784 PPK: USE_PPK in the request is the initiator's own configuration
    wv, st = _wire(rec, "pq_ppk")
    ppk = tunnel.get("ppk")
    if me != "initiator":
        out.append(Comparison("pq_ppk", NOT_COMPARABLE, ppk, wv, "a responder answers USE_PPK if ANY of its connections "
                              "has a PPK (EXP-27), so its reply says nothing about this connection"))
    elif wv is None:
        out.append(Comparison("pq_ppk", NOT_COMPARABLE, ppk, None, f"wire finding is {st}"))
    else:
        ok = (wv != "not-offered") == bool(ppk)
        out.append(Comparison("pq_ppk", MATCH if ok else MISMATCH, ppk, wv,
                              "consistent (whether the PPK was USED is never visible)" if ok else
                              ("the config sets a PPK but the wire's request carried no USE_PPK" if ppk else
                               "the wire's request announced PPK; this config sets none")))

    # per child: ESP family, key length (never observable), PFS, mode
    children = tunnel.get("children") or []
    child = children[0] if len(children) == 1 else None
    if child is None:
        out.append(Comparison("child", NOT_COMPARABLE, [c["name"] for c in children], None,
                              "several or no children; pick one with --conn/--child (not yet supported)"))
        return out
    esp = child["esp_proposals"]
    fams = {esp_family(e, (p["integ"] or [None])[0]) for p in esp for e in p["encr"]}
    wv, st = _wire(rec, "esp_cipher_family")
    if not esp:
        out.append(Comparison("esp_cipher_family", NOT_CONFIGURED, None, wv, "no esp_proposals (default, or AH only)"))
    elif None in fams:
        out.append(Comparison("esp_cipher_family", NOT_COMPARABLE, sorted(f for f in fams if f), wv,
                              "a configured ESP suite has no family in the T0 sieve"))
    elif wv is None:
        out.append(Comparison("esp_cipher_family", NOT_COMPARABLE, sorted(fams), None, f"wire finding is {st}"))
    else:
        cands = wv if isinstance(wv, list) else [wv]
        hit = sorted(fams & set(cands))
        agree = MATCH if (st != "INFERRED" and len(cands) == 1) else CONSISTENT
        out.append(Comparison("esp_cipher_family", agree if hit else MISMATCH, sorted(fams), cands,
                              f"configured family {hit} is not ruled out by the wire's {len(cands)} candidate(s)" if hit else
                              "no configured ESP family is possible given the wire's packet geometry"))
    keylens = sorted({e.rsplit("-", 1)[-1] for p in esp for e in p["encr"] if e.rsplit("-", 1)[-1].isdigit()})
    out.append(Comparison("esp_key_length", NOT_COMPARABLE, keylens or None, None,
                          "ESP key length is not observable on the wire (F-05: same block size, IV, ICV, alignment)"))
    wv, st = _wire(rec, "pfs")
    cp = child.get("pfs")
    agree = CONSISTENT if st == "INFERRED" else MATCH
    out.append(Comparison("pfs", NOT_CONFIGURED if cp is None else NOT_COMPARABLE if wv is None
                          else agree if wv == cp else MISMATCH, cp, wv,
                          "PFS not set in config" if cp is None else f"wire {st}" if wv is None else
                          ("consistent" if wv == cp else f"the config says PFS {'on' if cp else 'off'}, the wire's rekey says {'on' if wv else 'off'}")))
    wv, st = _wire(rec, "mode")
    cm = child.get("mode")
    if cm == "iptfs":
        cm = "tunnel"
    out.append(Comparison("mode", NOT_COMPARABLE if wv is None else MATCH if wv == cm else MISMATCH, child.get("mode"), wv,
                          f"wire {st}" if wv is None else ("consistent" if wv == cm else "mode differs")))
    return out


def pick_tunnel(tunnels: list[dict], rec: EvidenceRecord, name: str | None = None) -> tuple[dict | None, str]:
    """The config connection this capture's SA belongs to: by name, else by the IKE addresses (either role)."""
    if name:
        t = next((t for t in tunnels if t["name"] == name), None)
        return t, ("" if t else f"no connection named {name!r}")
    req = next((m for m in getattr(rec, "_ike", []) if m["exchange"] == 34 and not m["is_response"]), None)
    if req is None:
        return None, "no IKE_SA_INIT request in the capture to match a connection by address"
    ends = {req["src"], req["dst"]}
    hits = [t for t in tunnels if {t.get("local_addrs"), t.get("remote_addrs")} == ends]
    if len(hits) == 1:
        return hits[0], ""
    return None, (f"{len(hits)} connections use these addresses; choose one with --conn" if hits else
                  f"no connection uses {sorted(ends)}")


def as_dicts(comps: list[Comparison]) -> list[dict]:
    return [asdict(c) for c in comps]
