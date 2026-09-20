"""Deterministic extractors: turn ingested IKE/ESP records into Findings.

Each extractor implements exactly one validated method from the experiments and
tags every Finding with its vantage, method and evidence. Extractors NEVER
return a bare value — an absence is a Finding with status NOT_OBSERVABLE/UNKNOWN.
"""
from __future__ import annotations

from collections import defaultdict

from .record import EvidenceRecord, Finding, Status, Vantage, EvidencePtr
from ..ingest import tshark
from ..leakage.leakage import extract_leakage
from ..leakage.attacker import extract_attacker
from .protocol import extract_ah, extract_ipsec_protocols, extract_mode, extract_sequence


# --------------------------------------------------------------------------- #
# SA grouping: one EvidenceRecord per IKE SPI pair.                            #
# --------------------------------------------------------------------------- #
def group_sas(pcap: str) -> list[EvidenceRecord]:
    ike = tshark.ike_messages(pcap)
    esp = tshark.esp_packets(pcap)
    recs: dict[tuple, EvidenceRecord] = {}

    for m in ike:
        # Key on the INITIATOR SPI: it is constant across the whole exchange,
        # whereas the responder SPI is zero in the IKE_SA_INIT request and only
        # set from the response onward. Keying on the pair would split a single
        # negotiation's request and response into two records.
        key = m["ispi"] or tuple(sorted([m["ispi"], m["rspi"]]))
        r = recs.get(key)
        if r is None:
            r = EvidenceRecord(ike_spi_i=m["ispi"], ike_spi_r=("" if m["rspi"]=="0000000000000000" else m["rspi"]),
                               src=m["src"], dst=m["dst"], source_pcap=pcap)
            recs[key] = r
        if m["rspi"] and m["rspi"] != "0000000000000000" and (not r.ike_spi_r or r.ike_spi_r == "0000000000000000"):
            r.ike_spi_r = m["rspi"]
        r._ike = getattr(r, "_ike", [])
        r._ike.append(m)

    # Attach ESP packets by address pair. Child SA SPIs are negotiated inside the
    # encrypted IKE_AUTH/CREATE_CHILD_SA, so the IKE SA <-> ESP SPI link is never
    # plaintext: attribution is by address pair and time, never by SPI proof.
    for r in recs.values():
        r._esp = []
    all_esp_by_pair = defaultdict(list)
    for p in esp:
        all_esp_by_pair[tuple(sorted([p["src"], p["dst"]]))].append(p)

    sas_by_pair = defaultdict(list)
    for r in recs.values():
        sas_by_pair[tuple(sorted([r.src, r.dst]))].append(r)

    for pair, sa_list in sas_by_pair.items():
        pair_esp = all_esp_by_pair.get(pair, [])
        if not pair_esp:
            continue
        if len(sa_list) == 1:
            sa_list[0]._esp = pair_esp
        else:
            # T-051: several IKE SAs between one host pair. An SA owns the SPIs that
            # carry traffic between its first IKE message and the next SA's, so ESP
            # that only starts after a later negotiation is not credited to an
            # earlier, failed one. Known limit (T-052 stress case): an SA negotiated
            # while an older tunnel is still carrying traffic also sees that traffic.
            sa_list.sort(key=lambda s: min((m["t"] for m in s._ike), default=0.0))
            for i, sa in enumerate(sa_list):
                t_start = min((m["t"] for m in sa._ike), default=0.0)
                t_end = (min((m["t"] for m in sa_list[i + 1]._ike), default=float("inf"))
                         if i + 1 < len(sa_list) else float("inf"))
                window_spis = {p["spi"] for p in pair_esp if t_start <= p["t"] < t_end and p.get("spi")}
                sa._esp = [p for p in pair_esp if p.get("spi") in window_spis]
        for sa in sa_list:
            _set_child_spis(sa)

    # ESP-only flows (T0: the SA predates the capture, no IKE visible) still get a
    # record so size/timing leakage and the cipher sieve can run on them. One
    # record per host pair ACROSS SPI changes: a new SPI pair between the same
    # hosts is read as a rekey of the same tunnel (T-053 decision), because
    # splitting per SPI turned one rekeying tunnel into one-way fragments and
    # collapsed its measured timing leakage (T-052: 1.97 -> 0.0-0.58 bits).
    ike_pairs = {tuple(sorted([r.src, r.dst])) for r in recs.values()}
    for pair, pkts in all_esp_by_pair.items():
        if pair in ike_pairs:
            continue
        esp_r = EvidenceRecord(src=pkts[0]["src"], dst=pkts[0]["dst"], source_pcap=pcap)
        esp_r._ike = []
        esp_r._esp = pkts
        esp_r._esp_only = True
        _set_child_spis(esp_r)
        recs[("esp", pair)] = esp_r

    # AH (T-083): attached by address pair exactly like ESP. An AH-only flow with
    # no IKE in the capture gets its own record, as ESP-only flows do.
    ah_by_pair = defaultdict(list)
    for p in tshark.ah_packets(pcap):
        ah_by_pair[tuple(sorted([p["src"], p["dst"]]))].append(p)
    for r in recs.values():
        r._ah = ah_by_pair.get(tuple(sorted([r.src, r.dst])), [])
    have = {tuple(sorted([r.src, r.dst])) for r in recs.values()}
    for pair, pkts in ah_by_pair.items():
        if pair in have:
            continue
        ah_r = EvidenceRecord(src=pkts[0]["src"], dst=pkts[0]["dst"], source_pcap=pcap)
        ah_r._ike, ah_r._esp, ah_r._ah = [], [], pkts
        ah_r._esp_only = True
        recs[("ah", pair)] = ah_r

    return list(recs.values())


def _set_child_spis(r: EvidenceRecord) -> None:
    """child_spi_out = first SPI seen src->dst, child_spi_in = first SPI seen
    dst->src, in capture order (ESP packets arrive frame-ordered from tshark).
    Later SPIs on the same record are rekeys; the packets stay in r._esp."""
    for p in r._esp:
        if not p.get("spi"):
            continue
        if not r.child_spi_out and p["src"] == r.src and p["dst"] == r.dst:
            r.child_spi_out = p["spi"]
        elif not r.child_spi_in and p["src"] == r.dst and p["dst"] == r.src:
            r.child_spi_in = p["spi"]


# --------------------------------------------------------------------------- #
# Extractors                                                                   #
# --------------------------------------------------------------------------- #
def extract_ike_meta(r: EvidenceRecord) -> None:
    """R3 IKE version, exchange set, NAT-T. O at T1."""
    ike = getattr(r, "_ike", [])
    init = [m for m in ike if m["exchange"] == 34]
    if not init:
        # Check for legacy IKEv1 (RFC 2409) exchange types (2, 4, 5, 32, 33)
        ikev1 = [m for m in ike if m.get("exchange") in (2, 4, 5, 32, 33)]
        if ikev1:
            ev = [EvidencePtr(r.source_pcap, m["frame"], "isakmp.exchangetype", m["exchange_name"]) for m in ikev1[:2]]
            r.add(Finding("ike_version", Status.OBSERVED, Vantage.T1, "ike_meta", value="IKEv1",
                          evidence=ev, note="ISAKMP version 1 exchanges detected; IKEv1 is deprecated (RFC 9395)"))
            exch = sorted({m["exchange_name"] for m in ike})
            r.add(Finding("ike_exchanges", Status.OBSERVED, Vantage.T1, "ike_meta", value=exch, evidence=ev))
            if r.ike_spi_i:
                r.add(Finding("ike_spi", Status.OBSERVED, Vantage.T1, "ike_meta",
                              value={"initiator": r.ike_spi_i, "responder": r.ike_spi_r or None}))
            return
        r.add(Finding("ike_version", Status.UNKNOWN, Vantage.T0, "ike_meta",
                      note="no IKE_SA_INIT in capture; SA predates capture or ESP-only vantage"))
        return
    ev = [EvidencePtr(r.source_pcap, m["frame"], "isakmp.exchangetype", m["exchange_name"]) for m in init[:2]]
    r.add(Finding("ike_version", Status.OBSERVED, Vantage.T1, "ike_meta", value="IKEv2",
                  evidence=ev, note="ISAKMP version 2 exchange types present"))
    exch = sorted({m["exchange_name"] for m in ike})
    r.add(Finding("ike_exchanges", Status.OBSERVED, Vantage.T1, "ike_meta", value=exch, evidence=ev))
    # R9 (T-048): SPI was already tracked internally for SA grouping but never
    # surfaced as a citable Finding.
    if r.ike_spi_i:
        r.add(Finding("ike_spi", Status.OBSERVED, Vantage.T1, "ike_meta",
                      value={"initiator": r.ike_spi_i, "responder": r.ike_spi_r or None}))


def _addke_ids(m: dict) -> list[int]:
    """Additional key exchange method ids (RFC 9370 Transform Types 6-12) in one
    message, NONE (id 0) removed. tshark routes the typed transforms (ENCR/PRF/
    INTEG/KE/ESN) to typed id fields, so the generic isakmp.tf.id carries exactly
    the additional-KE ids."""
    if not any(tt >= 6 for tt in m["transform_types"]):
        return []
    return [i for i in m["transform_ids"] if i != 0]


def extract_pq_addke(r: EvidenceRecord) -> None:
    """R8 key exchange + PQ posture. EXP-04/07, DEC-020, T-053.

    Plaintext first: the responder's IKE_SA_INIT response carries the single
    proposal it selected, so whether an additional key exchange was SELECTED is
    read directly (OBSERVED), never inferred from IKE_INTERMEDIATE being absent.
    RFC 9370: Transform ID 0 is NONE, i.e. the additional exchange is optional.
    A responder picking a proposal without PQ is a policy fact we can see; WHY
    (configured fallback, a second classical proposal, or an injected
    INVALID_KE_PAYLOAD making the initiator retry) is not attributable at T1."""
    ike = getattr(r, "_ike", [])
    init = [m for m in ike if m["exchange"] == 34]
    if not init:
        r.add(Finding("pq_key_exchange", Status.UNKNOWN, Vantage.T0, "pq_addke",
                      note="no IKE_SA_INIT visible"))
        return
    offered = sorted({i for m in init if not m["is_response"] for i in _addke_ids(m)})
    offered_names = [tshark.KE_METHOD.get(i, f"KE-id-{i}") for i in offered]
    # A response that selected a proposal carries transforms; an error-only one
    # (NO_PROPOSAL_CHOSEN, INVALID_KE_PAYLOAD, COOKIE) carries none. After a
    # retry, the last selecting response is the one that stands.
    selecting = [m for m in init if m["is_response"] and m["transform_types"]]
    has_intermediate = any(m["exchange"] == 43 for m in ike)

    if selecting:
        sel = selecting[-1]
        chosen = _addke_ids(sel)
        ev = [EvidencePtr(r.source_pcap, sel["frame"], "isakmp.tf.type/tf.id (responder SA)", str(chosen))]
        if chosen:
            r.add(Finding("pq_key_exchange", Status.OBSERVED, Vantage.T1, "pq_addke (responder selection)",
                          value=[tshark.KE_METHOD.get(i, f"KE-id-{i}") for i in chosen], evidence=ev,
                          note="responder selected additional key exchange(s) in its IKE_SA_INIT proposal"
                               + ("; IKE_INTERMEDIATE observed" if has_intermediate
                                  else "; IKE_INTERMEDIATE not observed (capture may end before it)")))
        elif offered:
            r.add(Finding("pq_key_exchange", Status.OBSERVED, Vantage.T1, "pq_addke (responder selection)",
                          value="offered-but-not-used", evidence=ev,
                          note=f"initiator offered {offered_names}; the responder's selected proposal carries "
                               "no additional key exchange (absent or NONE). The selection is plaintext; "
                               "whether it was configured policy or induced is not attributable at T1"))
        else:
            r.add(Finding("pq_key_exchange", Status.OBSERVED, Vantage.T1, "pq_addke",
                          value="classical-only", evidence=ev,
                          note="no additional key exchange offered (or only NONE)"))
        return

    ev = [EvidencePtr(r.source_pcap, init[0]["frame"], "isakmp.tf.type/tf.id (initiator SA)", str(offered))]
    if offered:
        r.add(Finding("pq_key_exchange", Status.UNKNOWN, Vantage.T1, "pq_addke (responder selection)",
                      evidence=ev,
                      note=f"initiator offered {offered_names} but no responder proposal selection is visible "
                           "(no response, or an error-only response)"))
    else:
        r.add(Finding("pq_key_exchange", Status.OBSERVED, Vantage.T1, "pq_addke",
                      value="classical-only", evidence=ev,
                      note="initiator offered no additional key exchange (or only NONE)"))


def extract_pfs(r: EvidenceRecord) -> None:
    """R14 PFS. EXP-03: a CREATE_CHILD_SA rekey carrying a KE payload is ~256 B
    larger than one without. Only judgeable when a rekey is observed.

    The 400 B rule is MEASURED for MODP groups only (EXP-03/07: PFS-off requests
    236-240 B, PFS-on 508-512 B, all MODP-2048). Smaller KE values - Curve25519
    32 octets (RFC 8031), ECP-256 64 octets (x|y, RFC 5903 sec 7) - shrink the gap
    to tens of bytes, within the variance of one traffic selector or ESP
    transform, and no capture of ours calibrates it: those groups are UNKNOWN
    (T-053). The IKE SA group is only a proxy - the Child SA's PFS group is
    negotiated inside the encrypted exchange and may differ."""
    ike = getattr(r, "_ike", [])
    ccsa = [m for m in ike if m["exchange"] == 36]
    if not ccsa:
        r.add(Finding("pfs", Status.NOT_OBSERVABLE, Vantage.T1, "pfs (EXP-03)",
                      note="no CREATE_CHILD_SA rekey observed; PFS only visible at rekey"))
        return
    # heuristic threshold from EXP-03/EXP-07 (PFS-on rekey request >= ~460 B for modp2048;
    # PFS-off ~220-240 B). Report as INFERRED with the observed size as evidence.
    req = [m for m in ccsa if not m["is_response"]]
    sizes = sorted(m["ip_len"] for m in req) or sorted(m["ip_len"] for m in ccsa)
    ev = [EvidencePtr(r.source_pcap, ccsa[0]["frame"], "ip.len", str(sizes))]

    dh_f = r.findings.get("ike_dh_group")
    dh_val = dh_f.value if (dh_f and isinstance(dh_f.value, str)) else None
    if dh_val and not dh_val.startswith("MODP"):
        r.add(Finding("pfs", Status.UNKNOWN, Vantage.T1, "pfs (EXP-03 length gap)", evidence=ev,
                      note=f"PFS size threshold uncalibrated for DH group {dh_val} (400 B rule measured on "
                           f"MODP-2048 only; request sizes {sizes}); needs a measured baseline for this group "
                           "or T2 endpoint telemetry"))
        return
    caveat = ("" if dh_val else
              " (IKE DH group not visible; the 400 B rule assumes a MODP-size KE, so a PFS rekey with a "
              "smaller group would read as PFS-off)")
    if sizes and max(sizes) >= 400:
        r.add(Finding("pfs", Status.INFERRED, Vantage.T1, "pfs (EXP-03 length gap)", value=True,
                      confidence=0.9, evidence=ev,
                      note=f"CREATE_CHILD_SA request {max(sizes)} B carries a KE payload{caveat}"))
    else:
        r.add(Finding("pfs", Status.INFERRED, Vantage.T1, "pfs (EXP-03 length gap)", value=False,
                      confidence=0.9, evidence=ev,
                      note=f"CREATE_CHILD_SA request {max(sizes) if sizes else '?'} B, no KE payload{caveat}"))


def extract_sa_lifecycle(r: EvidenceRecord) -> None:
    """R9/R12 (T-048, EXP-12): measured rekey cadence. IKEv2 does not negotiate
    a key lifetime (F-02) — the only honest answer is a MEASUREMENT of
    observed CREATE_CHILD_SA rekey timing, never a claimed configured value.
    Needs >=2 rekeys in the capture to measure an interval at all."""
    ike = getattr(r, "_ike", [])
    ccsa_req = sorted([m for m in ike if m["exchange"] == 36 and not m["is_response"]],
                      key=lambda m: m["t"])
    if len(ccsa_req) < 2:
        r.add(Finding("rekey_cadence", Status.NOT_OBSERVABLE, Vantage.T1, "sa_lifecycle (EXP-12)",
                      note=f"{len(ccsa_req)} CREATE_CHILD_SA rekey(s) observed; need >=2 to measure "
                           "an interval"))
        return
    intervals = [round(b["t"] - a["t"], 2) for a, b in zip(ccsa_req, ccsa_req[1:])]
    ev = [EvidencePtr(r.source_pcap, m["frame"], "frame.time_relative", str(m["t"])) for m in ccsa_req]
    r.add(Finding("rekey_cadence", Status.MEASURED, Vantage.T1, "sa_lifecycle (EXP-12)",
                  value={"n_rekeys": len(ccsa_req), "intervals_s": intervals,
                         "mean_interval_s": round(sum(intervals) / len(intervals), 2)},
                  evidence=ev,
                  note="measured from observed CREATE_CHILD_SA timing, never the configured/"
                       "negotiated lifetime - IKEv2 does not negotiate one (F-02)"))


def extract_auth_hint(r: EvidenceRecord) -> None:
    """R7/OQ-05 (T-048, EXP-11): does the on-wire trace tell us the PEER
    AUTHENTICATION METHOD (PSK / certificate / EAP) this specific tunnel used?

    Tested empirically before shipping, per DEC-008 (never claim what wasn't
    verified): CERTREQ and SIGNATURE_HASH_ALGORITHMS both appear in the
    PLAINTEXT IKE_SA_INIT, so 09-DEFINE.md's original disposition ("I at T1
    via CERTREQ/SIGHASH presence") looked buildable. It is only half true.

    - SIGNATURE_HASH_ALGORITHMS (notify 16431) is emitted UNCONDITIONALLY —
      confirmed present even in a capture from a responder with zero
      certificate configuration anywhere. Zero discriminating value.
    - CERTREQ presence tracks whether the RESPONDER has ANY certificate trust
      anchor loaded in its config — a differential test on the identical
      responder (same container, same swanctl.conf) showed CERTREQ present in
      BOTH a PSK-only exchange and a certificate exchange, once ANY
      certificate-capable connection existed in that responder's policy.
      This makes sense protocol-wise: CERTREQ is sent in IKE_SA_INIT, before
      IDi identifies which connection will be matched, so the responder
      cannot yet know which policy applies to THIS tunnel.

    Net: the per-tunnel auth method is only settled inside IKE_AUTH's CERT/
    AUTH payloads, which are encrypted — NOT-OBSERVABLE at T0/T1, the same
    encryption-boundary pattern as mode (EXP-08). CERTREQ presence is kept as
    its own, honestly-scoped finding: a genuine, useful signal about the
    RESPONDER'S fleet-wide policy capability, not this SA's actual method.
    """
    ike = getattr(r, "_ike", [])
    if not ike:
        return
    init_resp = [m for m in ike if m["exchange"] == 34 and m["is_response"]]
    r.add(Finding("peer_auth_method", Status.NOT_OBSERVABLE, Vantage.T1, "auth_hint (EXP-11)",
                  note="the actual CERT/AUTH payload is inside encrypted IKE_AUTH; CERTREQ/SIGHASH "
                       "in IKE_SA_INIT do not reliably indicate THIS tunnel's auth method (EXP-11)"))
    if not init_resp:
        return
    certreq_seen = any(m.get("has_certreq") for m in init_resp)
    r.add(Finding("responder_cert_capability", Status.OBSERVED, Vantage.T1, "auth_hint (EXP-11)",
                  value=certreq_seen,
                  note="CERTREQ presence in the IKE_SA_INIT response - reflects the responder's "
                       "own certificate trust-anchor policy fleet-wide, not necessarily this SA's "
                       "negotiated method (validated by a same-responder differential test, EXP-11)"))


def extract_failure(r: EvidenceRecord) -> None:
    """Why a tunnel failed. EXP-06 r2: deterministic structural signatures."""
    ike = getattr(r, "_ike", [])
    init = [m for m in ike if m["exchange"] == 34]
    auth = [m for m in ike if m["exchange"] == 35]
    esp = getattr(r, "_esp", [])
    NO_PROP = 14
    init_resp = [m for m in init if m["is_response"]]

    if not init:
        r.add(Finding("negotiation_outcome", Status.UNKNOWN, Vantage.T0, "failure_diag (EXP-06)",
                      note="no IKE_SA_INIT visible")); return
    if init and not init_resp:
        r.add(Finding("negotiation_outcome", Status.OBSERVED, Vantage.T1, "failure_diag F6",
                      value="peer-unreachable", note="IKE_SA_INIT sent, no response")); return
    if any(NO_PROP in m["notify_types"] for m in init_resp):
        r.add(Finding("negotiation_outcome", Status.OBSERVED, Vantage.T1, "failure_diag F1",
                      value="ike-proposal-mismatch", note="NO_PROPOSAL_CHOSEN in IKE_SA_INIT response")); return
    auth_resp = [m for m in auth if m["is_response"]]
    if auth_resp:
        maxlen = max(m["ip_len"] for m in auth_resp)
        if maxlen <= 144:
            r.add(Finding("negotiation_outcome", Status.INFERRED, Vantage.T1, "failure_diag F4 (112B rule)",
                          value="auth-or-child-failure", confidence=0.9,
                          note=f"IKE_AUTH response {maxlen} B carries only an error notify")); return
    if esp:
        r.add(Finding("negotiation_outcome", Status.OBSERVED, Vantage.T1, "failure_diag F0",
                      value="success", note="IKE_AUTH completed and ESP flows")); return
    # IKE up, no ESP observed. Originally reported as "child-sa-rejected" at
    # confidence 0.7 (backed by 10/10 EXP-06r2 F2/F3 captures, all genuine
    # rejections at this exact structural point). EXP-10 (real OpenBSD iked)
    # falsified that confidence: a genuine SUCCESS produced a 224 B IKE_AUTH
    # response - smaller than strongSwan's own F2/F3 REJECTION size (256 B),
    # because no ESP had been sent yet. A response-size threshold cannot be
    # made to classify both correctly with one constant (strongSwan F0
    # success=336B vs F2/F3 rejection=256B; iked success=224B) - this is
    # implementation-dependent in the same way EXP-07 found for fragment size
    # and notify placement, not a bug fixable with a better number. Reported
    # honestly as ambiguous rather than curve-fit to either vendor.
    r.add(Finding("negotiation_outcome", Status.INFERRED, Vantage.T1, "failure_diag (EXP-10 revised)",
                  value="post-auth-outcome-ambiguous", confidence=0.4,
                  note=("IKE up, no ESP observed at T0/T1. Two live hypotheses, not resolvable from "
                        "response size alone: (a) Child SA rejected (proposal/TS mismatch) - matches "
                        "10/10 of our own strongSwan fault-injection captures; (b) Child SA succeeded "
                        "but no data-plane traffic has been sent yet - confirmed possible on a real "
                        "OpenBSD iked capture (EXP-10), where a genuine success's response was smaller "
                        "than strongSwan's own rejection size. Resolve via T2 (swanctl/ipsecctl) or a "
                        "longer observation window.")))



def extract_ike_crypto(r: EvidenceRecord) -> None:
    """R4/R6/R8 for the IKE SA: ENCR (+key length), PRF, INTEG, DH group. All
    plaintext in the IKE_SA_INIT response -> O at T1. Note this is the IKE SA
    key length (observable); the ESP key length is NOT (F-05)."""
    c = tshark.ike_sa_crypto(r.source_pcap, ispi=r.ike_spi_i)
    # c is {} (no response) or has None fields (a NO_PROPOSAL_CHOSEN response
    # selected nothing). Either way, a field we could not read is UNKNOWN, never
    # a value-less OBSERVED (ADR-002).
    ev = [EvidencePtr(r.source_pcap, None, "isakmp IKE_SA_INIT response", str(c))]
    enc = (f"{c.get('encr')}-{c['encr_keylen']}" if c.get("encr") and c.get("encr_keylen")
           else c.get("encr"))
    # AEAD suites (AES-GCM/CCM, ChaCha20-Poly1305) carry no separate INTEG
    # transform: integrity is part of the cipher. Saying "no suite selected"
    # there was wrong (EXP-13 P3); say what is true and name the PRF instead.
    aead = bool(c.get("encr")) and any(x in c["encr"] for x in ("GCM", "CCM", "ChaCha20"))
    if c.get("prf"):
        r.add(Finding("ike_prf", Status.OBSERVED, Vantage.T1, "ike_crypto", value=c["prf"], evidence=ev))
    for attr, val, extra in (("ike_encr", enc, {}),
                             ("ike_integ", c.get("integ"), {}),
                             ("ike_dh_group", c.get("dh"), {"note": f"DH group id {c.get('dh_id')}"})):
        if val:
            r.add(Finding(attr, Status.OBSERVED, Vantage.T1, "ike_crypto", value=val, evidence=ev, **extra))
        else:
            is_v1 = r.findings.get("ike_version") and r.findings["ike_version"].value == "IKEv1"
            unknown_note = ("IKEv1 negotiation (RFC 2409); IKEv2 suite extraction not applicable"
                            if is_v1 else
                            f"AEAD suite ({enc}): no separate integrity transform; integrity is part of the cipher, "
                            f"PRF {c.get('prf')}. A rule written for HMAC integrity cannot judge it"
                            if attr == "ike_integ" and aead else
                            "no IKE SA suite selected (negotiation failed or no response visible)")
            r.add(Finding(attr, Status.UNKNOWN, Vantage.T0, "ike_crypto", note=unknown_note))


# ESP cipher-family sieve (EXP-01): IV/ICV/alignment constants per suite family.
_SIEVE = {
    "AES-CBC+HMAC-SHA256-128": dict(iv=16, icv=16, align=16),
    "AES-CBC+HMAC-SHA1-96": dict(iv=16, icv=12, align=16),
    "AES-CTR+HMAC-SHA256-128": dict(iv=8, icv=16, align=4),
    "AES-GCM-16": dict(iv=8, icv=16, align=4),
    "AES-CCM-16": dict(iv=8, icv=16, align=4),
    "ChaCha20-Poly1305": dict(iv=8, icv=16, align=4),
    # added 2026-09-20 (EXP-15): without these, a 3DES tunnel was reported as
    # "CBC excluded" with the true family missing from the candidate set
    "AES-CBC+HMAC-SHA384-192": dict(iv=16, icv=24, align=16),
    "AES-CBC+HMAC-SHA512-256": dict(iv=16, icv=32, align=16),
    "3DES-CBC+HMAC-SHA1-96": dict(iv=8, icv=12, align=8),
    # added 2026-09-20 (T-085) after third-party captures used ciphers the table
    # did not list: without them the "candidates" set could not contain the truth.
    # Several share an (IV, ICV, alignment) signature and are therefore not
    # separable by length alone - they are listed separately so the set is honest.
    "AES-CTR+HMAC-SHA1-96": dict(iv=8, icv=12, align=4),
    "DES-CBC+HMAC-96": dict(iv=8, icv=12, align=8),
    "Blowfish-CBC+HMAC-96": dict(iv=8, icv=12, align=8),
    "Twofish-CBC+HMAC-96": dict(iv=16, icv=12, align=16),
    "CAST-CBC+HMAC-96": dict(iv=8, icv=12, align=8),
    "NULL+HMAC-96": dict(iv=0, icv=12, align=4),
    "NULL+HMAC-SHA256-128": dict(iv=0, icv=16, align=4),
}


def extract_cipher_sieve(r: EvidenceRecord) -> None:
    """R5 ESP cipher family. EXP-01: a one-directional CBC-vs-AEAD/stream filter.
    Reports the surviving candidate SET (never a single suite it cannot resolve)."""
    esp = getattr(r, "_esp", [])
    lengths = [p["esp_content"] for p in esp if p["esp_content"] > 0]
    if len(lengths) < 5:
        r.add(Finding("esp_cipher_family", Status.UNKNOWN, Vantage.T0, "cipher_sieve (EXP-01)",
                      note=f"only {len(lengths)} ESP packets; need >=5 to constrain")); return
    survivors = [name for name, s in _SIEVE.items()
                 if all((c - s["iv"] - s["icv"]) >= 0 and (c - s["iv"] - s["icv"]) % s["align"] == 0
                        for c in lengths)]
    ev = [EvidencePtr(r.source_pcap, esp[0]["frame"], "esp content lengths", str(sorted(set(lengths))[:8]))]
    is_cbc = survivors == ["AES-CBC+HMAC-SHA256-128"] or (len(survivors) == 1 and "CBC" in survivors[0])
    if len(survivors) == 1:
        r.add(Finding("esp_cipher_family", Status.INFERRED, Vantage.T0, "cipher_sieve (EXP-01)",
                      value=survivors, confidence=0.95, evidence=ev))
    else:
        # the useful one-directional bit: block-mode(CBC) vs AEAD/stream
        has_cbc = any("CBC" in s for s in survivors)
        has_aead = any("CBC" not in s for s in survivors)
        klass = "AEAD/stream (CBC excluded)" if (has_aead and not has_cbc) else                 "CBC or AEAD/stream (ambiguous)" if (has_cbc and has_aead) else "CBC-mode"
        r.add(Finding("esp_cipher_family", Status.INFERRED, Vantage.T0, "cipher_sieve (EXP-01)",
                      value=survivors, confidence=0.9, evidence=ev,
                      note=f"one-directional sieve -> {klass}; {len(survivors)} candidate(s) among the "
                           f"{len(_SIEVE)} families modelled. ESP with no integrity at all (RFC 8221: MUST NOT "
                           "outside AEAD) or a cipher outside that table would not appear here"))


def extract_early_childsa_cve(r: EvidenceRecord) -> None:
    """CVE-2026-78135 (EXP-09): a usable Child SA obtained from a
    CREATE_CHILD_SA *before IKE_AUTH completes* (strongSwan 5.9.7+, fixed
    6.1.0). Exchange type, message ID and SPIs are plaintext, so the pattern is
    passively observable (doc 11, RL-033). Deterministic, no ML.

    Vantage discipline (DEC-003/008): the detector fires only when the SA was
    seen from its IKE_SA_INIT. If the capture starts mid-tunnel it returns
    UNKNOWN, never a detection — "I didn't see the handshake" must not read as
    "the handshake was skipped". This is what makes it 0-false-positive.
    """
    ike = getattr(r, "_ike", [])
    if not ike:
        return  # ESP-only flow: no IKE to reason about
    attr = "early_childsa_cve"
    method = "EXP-09 early-Child-SA (CVE-2026-78135)"
    init = [m for m in ike if m["exchange"] == 34]
    auth = [m for m in ike if m["exchange"] == 35]
    child = [m for m in ike if m["exchange"] == 36]

    if not init:
        r.add(Finding(attr, Status.UNKNOWN, Vantage.T0, method,
                      note="SA not observed from IKE_SA_INIT; cannot tell whether a Child SA preceded auth"))
        return
    if not child:
        r.add(Finding(attr, Status.OBSERVED, Vantage.T1, method, value="not-applicable",
                      note="no CREATE_CHILD_SA exchange in this capture"))
        return
    # Order by FRAME NUMBER (capture sequence), never by raw message ID.
    # Bug found by EXP-12 (T-048, 2026-09-13): message IDs are maintained
    # PER ORIGINATOR (RFC 7296 sec 2.1) — once the peer that answered IKE_AUTH
    # independently initiates its own exchange (a self-initiated rekey, DPD,
    # anything), that peer's own message-id counter restarts at 0. Comparing
    # "earliest child msgid < earliest auth msgid" then compares two DIFFERENT
    # counters and false-positives on ordinary bidirectional rekey activity —
    # confirmed on a real capture where the responder independently rekeyed
    # (testbed/captures/exp12/rekey-cadence.pcap). Frame number is a single,
    # globally consistent order regardless of which side originated what.
    earliest_auth_frame = min((m["frame"] for m in auth), default=None)
    earliest_child_frame = min((m["frame"] for m in child), default=None)
    earliest_child_mid = min(m["message_id"] for m in child
                             if m["frame"] == earliest_child_frame)
    pre_auth = earliest_auth_frame is None or earliest_child_frame < earliest_auth_frame
    if earliest_auth_frame is None:
        # T-055 (plan CVE-2b): "no IKE_AUTH in the capture" is not "no IKE_AUTH
        # was sent" - the capture may have lost it. Message IDs settle it: the
        # original initiator numbers its requests 0, 1, 2... (RFC 7296 sec 2.2),
        # so a CREATE_CHILD_SA that DIRECTLY follows its last pre-auth exchange
        # (IKE_SA_INIT, IKE_INTERMEDIATE) proves nothing was sent in between.
        # A gap means an IKE_AUTH may be missing from the capture -> UNKNOWN.
        gap = _msgid_gap_before_child(ike, earliest_child_frame)
        if gap is not None:
            r.add(Finding(attr, Status.UNKNOWN, Vantage.T1, method,
                          note=f"no IKE_AUTH in the capture, but CREATE_CHILD_SA (frame {earliest_child_frame}, "
                               f"msgid {earliest_child_mid}) {gap}; an IKE_AUTH may have been sent and "
                               "not captured, so the early-Child-SA pattern is not proven"))
            return
    if pre_auth:
        why = ("no IKE_AUTH observed for this SA" if earliest_auth_frame is None
               else f"IKE_AUTH first seen at frame {earliest_auth_frame}")
        r.add(Finding(attr, Status.OBSERVED, Vantage.T1, method,
                      value="early-child-sa-before-auth",
                      note=f"CREATE_CHILD_SA at frame {earliest_child_frame} (msgid {earliest_child_mid}), "
                           f"{why} — CVE-2026-78135 pattern (an attempt; whether the responder "
                           "accepted it is not visible at T1)"))
    else:
        r.add(Finding(attr, Status.OBSERVED, Vantage.T1, method, value="not-detected",
                      note=f"IKE_AUTH (frame {earliest_auth_frame}) precedes CREATE_CHILD_SA "
                           f"(frame {earliest_child_frame})"))


def _from_original_initiator(m: dict) -> bool:
    """Did the original IKE SA initiator originate this exchange? The I flag
    marks messages SENT by the original initiator, so its requests carry I and
    the other side's responses to them do not."""
    return m.get("is_initiator", True) != m["is_response"]


def _msgid_gap_before_child(ike: list[dict], child_frame: int) -> str | None:
    """None when message-ID accounting proves no exchange was sent between the
    last pre-auth exchange and the first CREATE_CHILD_SA; otherwise why it
    can't be proven."""
    child = next(m for m in ike if m["frame"] == child_frame)
    if not _from_original_initiator(child):
        return ("was originated by the responder, whose message IDs do not count the "
                "initiator's IKE_AUTH")
    pre = [m["message_id"] for m in ike
           if m["exchange"] in (34, 43) and m["frame"] < child_frame
           and m["message_id"] is not None and _from_original_initiator(m)]
    if not pre or child["message_id"] is None:
        return "has no pre-auth message ID to count from"
    expected = max(pre) + 1
    if child["message_id"] != expected:
        return (f"carries msgid {child['message_id']}, not {expected} (the next after the last "
                f"pre-auth exchange)")
    return None


def extract_offered_dh(r: EvidenceRecord) -> None:
    """EXP-13 P5: the key-exchange groups the INITIATOR offered, from its
    plaintext IKE_SA_INIT request(s). A peer that offers a weak group would
    accept it from any responder that picks it: downgrade exposure, even when
    this particular tunnel negotiated something strong. Only the initiator's
    offer is on the wire; the responder's acceptable set never is."""
    ike = getattr(r, "_ike", [])
    reqs = [m for m in ike if m["exchange"] == 34 and not m["is_response"] and m.get("offered_dh")]
    if not reqs:
        if ike:
            r.add(Finding("ike_offered_dh", Status.UNKNOWN, Vantage.T1, "offered_dh (EXP-13)",
                          note="no IKE_SA_INIT request with a key-exchange offer visible"))
        return
    ids = sorted({g for m in reqs for g in m["offered_dh"]})
    names = [tshark.KE_METHOD.get(g, f"dh-{g}") for g in ids]
    who = f"{reqs[0]['src']} (initiator)"
    ev = [EvidencePtr(r.source_pcap, m["frame"], "isakmp.tf.id.dh (initiator SA)", str(m["offered_dh"])) for m in reqs[:2]]
    r.add(Finding("ike_offered_dh", Status.OBSERVED, Vantage.T1, "offered_dh (EXP-13)", value=names, evidence=ev,
                  note=f"groups {who} offered in IKE_SA_INIT; the responder's acceptable set is not visible"))


ALL_EXTRACTORS = [extract_ike_meta, extract_ike_crypto, extract_pq_addke, extract_ipsec_protocols, extract_ah,
                  extract_cipher_sieve, extract_pfs, extract_sa_lifecycle, extract_mode, extract_sequence,
                  extract_auth_hint, extract_failure, extract_early_childsa_cve, extract_offered_dh,
                  extract_leakage, extract_attacker]


def build_records(pcap: str) -> list[EvidenceRecord]:
    recs = group_sas(pcap)
    for r in recs:
        for ex in ALL_EXTRACTORS:
            ex(r)
    return recs
