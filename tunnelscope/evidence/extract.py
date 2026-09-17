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

    # attach ESP packets by address pair and SPI
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
        # Sort SAs by initial IKE message timestamp
        sa_list.sort(key=lambda s: min((m["t"] for m in getattr(s, "_ike", []) if "t" in m), default=0.0))
        if len(sa_list) == 1:
            sa = sa_list[0]
            sa._esp = pair_esp
            spis_fwd = {p["spi"] for p in pair_esp if p["src"] == sa.src and p["dst"] == sa.dst and p.get("spi")}
            spis_rev = {p["spi"] for p in pair_esp if p["src"] == sa.dst and p["dst"] == sa.src and p.get("spi")}
            if spis_fwd and not sa.child_spi_out:
                sa.child_spi_out = sorted(spis_fwd)[0]
            if spis_rev and not sa.child_spi_in:
                sa.child_spi_in = sorted(spis_rev)[0]
        else:
            # Multiple SAs between the same host pair: segregate by SPI multiplexing
            for i, sa in enumerate(sa_list):
                sa_ike_times = [m["t"] for m in getattr(sa, "_ike", []) if "t" in m]
                t_start = min(sa_ike_times) if sa_ike_times else 0.0
                t_end = float("inf")
                if i + 1 < len(sa_list):
                    next_ike_times = [m["t"] for m in getattr(sa_list[i+1], "_ike", []) if "t" in m]
                    if next_ike_times:
                        t_end = min(next_ike_times)
                known_spis = {sa.child_spi_in, sa.child_spi_out} - {"", None}
                if known_spis:
                    sa._esp = [p for p in pair_esp if p.get("spi") in known_spis]
                else:
                    window_spis = {p.get("spi") for p in pair_esp if t_start <= p["t"] < t_end and p.get("spi")}
                    if window_spis:
                        sa._esp = [p for p in pair_esp if p.get("spi") in window_spis]
                    else:
                        sa._esp = []
                spis_fwd = {p["spi"] for p in sa._esp if p["src"] == sa.src and p["dst"] == sa.dst and p.get("spi")}
                spis_rev = {p["spi"] for p in sa._esp if p["src"] == sa.dst and p["dst"] == sa.src and p.get("spi")}
                if spis_fwd and not sa.child_spi_out:
                    sa.child_spi_out = sorted(spis_fwd)[0]
                if spis_rev and not sa.child_spi_in:
                    sa.child_spi_in = sorted(spis_rev)[0]

    # ESP-only flows (T0: the SA predates the capture, no IKE visible) still get a
    # record so size/timing leakage and the cipher sieve can run on them.
    ike_pairs = {tuple(sorted([r.src, r.dst])) for r in recs.values()}
    for pair, pkts in all_esp_by_pair.items():
        if pair in ike_pairs:
            continue
        host_a, host_b = pair
        spis_a_to_b = sorted({p["spi"] for p in pkts if p["src"] == host_a and p["dst"] == host_b and p.get("spi")})
        spis_b_to_a = sorted({p["spi"] for p in pkts if p["src"] == host_b and p["dst"] == host_a and p.get("spi")})

        # If at most one SPI exists in each direction, this is a single bidirectional tunnel
        if len(spis_a_to_b) <= 1 and len(spis_b_to_a) <= 1:
            esp_r = EvidenceRecord(src=pkts[0]["src"], dst=pkts[0]["dst"], source_pcap=pcap)
            esp_r._ike = []
            esp_r._esp = pkts
            esp_r._esp_only = True
            if pkts[0]["src"] == host_a:
                esp_r.child_spi_out = spis_a_to_b[0] if spis_a_to_b else ""
                esp_r.child_spi_in = spis_b_to_a[0] if spis_b_to_a else ""
            else:
                esp_r.child_spi_out = spis_b_to_a[0] if spis_b_to_a else ""
                esp_r.child_spi_in = spis_a_to_b[0] if spis_a_to_b else ""
            recs[("esp", pair)] = esp_r
        else:
            # Multiple SPIs per direction indicate multiple multiplexed tunnels between the same host pair
            pkts_by_spi = defaultdict(list)
            for p in pkts:
                pkts_by_spi[p.get("spi")].append(p)
            for spi_val, spi_pkts in pkts_by_spi.items():
                esp_r = EvidenceRecord(src=spi_pkts[0]["src"], dst=spi_pkts[0]["dst"], source_pcap=pcap)
                esp_r._ike = []
                esp_r._esp = spi_pkts
                esp_r._esp_only = True
                esp_r.child_spi_in = spi_val or ""
                recs[("esp", pair, spi_val)] = esp_r

    return list(recs.values())


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
                          evidence=ev, note="ISAKMP version 1 exchanges detected; deprecated by RFC 8247"))
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


def extract_pq_addke(r: EvidenceRecord) -> None:
    """R8 key exchange + PQ posture. EXP-04/07. Decisive signals: ADDKE transform
    in IKE_SA_INIT + presence of IKE_INTERMEDIATE (DEC-020).
    RFC 9370 §2.1: Transform ID 0 is NONE (indicates additional key exchange is optional)."""
    ike = getattr(r, "_ike", [])
    init = [m for m in ike if m["exchange"] == 34]
    if not init:
        r.add(Finding("pq_key_exchange", Status.UNKNOWN, Vantage.T0, "pq_addke",
                      note="no IKE_SA_INIT visible"))
        return
    # tshark routes typed transforms (ENCR/PRF/INTEG/KE-DH/ESN) to typed id
    # fields; the generic isakmp.tf.id therefore carries exactly the ADDKE key
    # exchange method ids. So: ADDKE present iff a transform type >= 6 appears,
    # and its method ids are the generic tf.id values.
    has_addke = any(tt >= 6 for m in init for tt in m["transform_types"])
    addke_ids = sorted({ti for m in init for ti in m["transform_ids"]}) if has_addke else []
    non_zero_addke = [ti for ti in addke_ids if ti != 0]
    has_none_transform = 0 in addke_ids
    has_intermediate = any(m["exchange"] == 43 for m in ike)
    ev = [EvidencePtr(r.source_pcap, init[0]["frame"], "isakmp.tf.type/tf.id", str(addke_ids))]

    init_resp = [m for m in init if m.get("is_response")]
    resp_addke = [ti for m in init_resp for ti in m.get("transform_ids", []) if ti != 0]
    chosen_addke = resp_addke if resp_addke else non_zero_addke

    if non_zero_addke and has_intermediate:
        names = [tshark.KE_METHOD.get(i, f"KE-id-{i}") for i in chosen_addke]
        r.add(Finding("pq_key_exchange", Status.OBSERVED, Vantage.T1, "pq_addke (EXP-04 signal 2+3)",
                      value=names, evidence=ev,
                      note="ADDKE transform(s) proposed AND IKE_INTERMEDIATE observed"))
    elif non_zero_addke and not has_intermediate:
        # proposed but no intermediate exchange -> the ADDKE was not actually used
        if has_none_transform:
            note_text = ("ADDKE proposed with NONE fallback (RFC 9370 §2.1); responder negotiated classical "
                         "KE and omitted IKE_INTERMEDIATE (negotiated classical fallback)")
            conf = 0.95
        else:
            note_text = "ADDKE proposed without NONE fallback; no IKE_INTERMEDIATE observed -> possible downgrade to classical KE"
            conf = 0.9
        r.add(Finding("pq_key_exchange", Status.INFERRED, Vantage.T1, "pq_addke downgrade check",
                      value="offered-but-not-used", confidence=conf, evidence=ev,
                      note=note_text))
    else:
        r.add(Finding("pq_key_exchange", Status.OBSERVED, Vantage.T1, "pq_addke",
                      value="classical-only", evidence=ev,
                      note="no ADDKE transform proposed" if not addke_ids else "only NONE transform proposed"))


def extract_pfs(r: EvidenceRecord) -> None:
    """R14 PFS. EXP-03: a CREATE_CHILD_SA rekey carrying a KE payload is larger
    than one without. Grounded in RFC 7296 §1.3 and RFC 5903 §7:
      - MODP-2048 (Group 14): KE data is 256 octets (total KE payload ~264 B).
      - Group 19 (ECP-256): KE data is 64 octets (RFC 5903 §7, NOT 32 bytes; total ~72 B).
      - Curve25519 (Group 31): KE data is 32 octets (RFC 8031; total ~40 B).
    Only judgeable when a rekey is observed."""
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
    dh_val = dh_f.value if (dh_f and dh_f.value) else ""
    if not dh_val:
        try:
            dh_val = tshark.ike_sa_crypto(r.source_pcap, ispi=r.ike_spi_i).get("dh") or ""
        except Exception:
            dh_val = ""
    is_curve25519 = "Curve25519" in str(dh_val)
    is_ec = is_curve25519 or any(ec in str(dh_val) for ec in ("ECP", "Curve448"))
    threshold = 255 if is_curve25519 else (280 if is_ec else 400)

    if sizes and max(sizes) >= threshold:
        r.add(Finding("pfs", Status.INFERRED, Vantage.T1, "pfs (EXP-03 length gap)", value=True,
                      confidence=0.9, evidence=ev, note=f"CREATE_CHILD_SA request {max(sizes)} B carries a KE payload"))
    else:
        r.add(Finding("pfs", Status.INFERRED, Vantage.T1, "pfs (EXP-03 length gap)", value=False,
                      confidence=0.9, evidence=ev, note=f"CREATE_CHILD_SA request {max(sizes) if sizes else '?'} B, no KE payload"))


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


def extract_mode(r: EvidenceRecord) -> None:
    """R4 tunnel/transport. EXP-08: NOT-OBSERVABLE at T0 from ESP alone."""
    r.add(Finding("mode", Status.NOT_OBSERVABLE, Vantage.T0, "mode (EXP-08)",
                  note="tunnel vs transport is not recoverable from passive ESP (every length is "
                       "valid in both modes; the inner IP header is encrypted). Report from T2/topology."))


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

    # Proposal matching: verify responder selected proposal was offered by initiator (Bottleneck a)
    ike = getattr(r, "_ike", [])
    init_req = [m for m in ike if m.get("exchange") == 34 and not m.get("is_response")]
    init_resp = [m for m in ike if m.get("exchange") == 34 and m.get("is_response")]
    offered_pn = [p["number"] for m in init_req for p in m.get("proposals", [])]
    chosen_pn = [p["number"] for m in init_resp for p in m.get("proposals", [])]
    prop_note = ""
    if chosen_pn and offered_pn:
        matched = chosen_pn[0] in offered_pn
        prop_note = f"; proposal #{chosen_pn[0]} {'matched initiator offer' if matched else 'not in initiator offer'}"

    for attr, val, extra in (("ike_encr", enc, {}),
                             ("ike_integ", c.get("integ"), {}),
                             ("ike_dh_group", c.get("dh"), {"note": f"DH group id {c.get('dh_id')}{prop_note}"})):
        if val:
            r.add(Finding(attr, Status.OBSERVED, Vantage.T1, "ike_crypto", value=val, evidence=ev, **extra))
        else:
            is_v1 = r.findings.get("ike_version") and r.findings["ike_version"].value == "IKEv1"
            unknown_note = ("IKEv1 negotiation (RFC 2409); IKEv2 suite extraction not applicable"
                            if is_v1 else "no IKE SA suite selected (negotiation failed or no response visible)")
            r.add(Finding(attr, Status.UNKNOWN, Vantage.T0, "ike_crypto", note=unknown_note))


# ESP cipher-family sieve (EXP-01): IV/ICV/alignment constants per suite family.
_SIEVE = {
    "AES-CBC+HMAC-SHA256-128": dict(iv=16, icv=16, align=16),
    "AES-CBC+HMAC-SHA1-96": dict(iv=16, icv=12, align=16),
    "AES-CTR+HMAC-SHA256-128": dict(iv=8, icv=16, align=4),
    "AES-GCM-16": dict(iv=8, icv=16, align=4),
    "AES-CCM-16": dict(iv=8, icv=16, align=4),
    "ChaCha20-Poly1305": dict(iv=8, icv=16, align=4),
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
                      note=f"one-directional sieve -> {klass}; {len(survivors)} candidate(s)"))


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
    if pre_auth:
        why = ("no IKE_AUTH observed for this SA" if earliest_auth_frame is None
               else f"IKE_AUTH first seen at frame {earliest_auth_frame}")
        r.add(Finding(attr, Status.OBSERVED, Vantage.T1, method,
                      value="early-child-sa-before-auth",
                      note=f"CREATE_CHILD_SA at frame {earliest_child_frame} (msgid {earliest_child_mid}), "
                           f"{why} — matches CVE-2026-78135"))
    else:
        r.add(Finding(attr, Status.OBSERVED, Vantage.T1, method, value="not-detected",
                      note=f"IKE_AUTH (frame {earliest_auth_frame}) precedes CREATE_CHILD_SA "
                           f"(frame {earliest_child_frame})"))


ALL_EXTRACTORS = [extract_ike_meta, extract_ike_crypto, extract_pq_addke,
                  extract_cipher_sieve, extract_pfs, extract_sa_lifecycle, extract_mode,
                  extract_auth_hint, extract_failure, extract_early_childsa_cve, extract_leakage]


def build_records(pcap: str) -> list[EvidenceRecord]:
    recs = group_sas(pcap)
    for r in recs:
        for ex in ALL_EXTRACTORS:
            ex(r)
    return recs
