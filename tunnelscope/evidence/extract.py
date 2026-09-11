"""Deterministic extractors: turn ingested IKE/ESP records into Findings.

Each extractor implements exactly one validated method from the experiments and
tags every Finding with its vantage, method and evidence. Extractors NEVER
return a bare value — an absence is a Finding with status NOT_OBSERVABLE/UNKNOWN.
"""
from __future__ import annotations

from collections import defaultdict

from .record import EvidenceRecord, Finding, Status, Vantage, EvidencePtr
from ..ingest import tshark


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

    # attach ESP packets by SPI proximity (best-effort; ESP SPIs differ from IKE SPIs)
    for r in recs.values():
        r._esp = []
    all_esp_by_pair = defaultdict(list)
    for p in esp:
        all_esp_by_pair[tuple(sorted([p["src"], p["dst"]]))].append(p)
    for r in recs.values():
        pair = tuple(sorted([r.src, r.dst]))
        r._esp = all_esp_by_pair.get(pair, [])

    return list(recs.values())


# --------------------------------------------------------------------------- #
# Extractors                                                                   #
# --------------------------------------------------------------------------- #
def extract_ike_meta(r: EvidenceRecord) -> None:
    """R3 IKE version, exchange set, NAT-T. O at T1."""
    ike = getattr(r, "_ike", [])
    init = [m for m in ike if m["exchange"] == 34]
    if not init:
        r.add(Finding("ike_version", Status.UNKNOWN, Vantage.T0, "ike_meta",
                      note="no IKE_SA_INIT in capture; SA predates capture or ESP-only vantage"))
        return
    ev = [EvidencePtr(r.source_pcap, m["frame"], "isakmp.exchangetype", m["exchange_name"]) for m in init[:2]]
    r.add(Finding("ike_version", Status.OBSERVED, Vantage.T1, "ike_meta", value="IKEv2",
                  evidence=ev, note="ISAKMP version 2 exchange types present"))
    exch = sorted({m["exchange_name"] for m in ike})
    r.add(Finding("ike_exchanges", Status.OBSERVED, Vantage.T1, "ike_meta", value=exch, evidence=ev))


def extract_pq_addke(r: EvidenceRecord) -> None:
    """R8 key exchange + PQ posture. EXP-04/07. Decisive signals: ADDKE transform
    in IKE_SA_INIT + presence of IKE_INTERMEDIATE (DEC-020)."""
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
    has_intermediate = any(m["exchange"] == 43 for m in ike)
    ev = [EvidencePtr(r.source_pcap, init[0]["frame"], "isakmp.tf.type/tf.id", str(addke_ids))]

    if addke_ids and has_intermediate:
        names = [tshark.KE_METHOD.get(i, f"KE-id-{i}") for i in addke_ids]
        r.add(Finding("pq_key_exchange", Status.OBSERVED, Vantage.T1, "pq_addke (EXP-04 signal 2+3)",
                      value=names, evidence=ev,
                      note="ADDKE transform(s) proposed AND IKE_INTERMEDIATE observed"))
    elif addke_ids and not has_intermediate:
        # proposed but no intermediate exchange -> the ADDKE was not actually used (downgrade)
        r.add(Finding("pq_key_exchange", Status.INFERRED, Vantage.T1, "pq_addke downgrade check",
                      value="offered-but-not-used", confidence=0.9, evidence=ev,
                      note="ADDKE proposed but no IKE_INTERMEDIATE -> possible downgrade to classical KE"))
    else:
        r.add(Finding("pq_key_exchange", Status.OBSERVED, Vantage.T1, "pq_addke",
                      value="classical-only", evidence=ev,
                      note="no ADDKE transform proposed"))


def extract_pfs(r: EvidenceRecord) -> None:
    """R14 PFS. EXP-03: a CREATE_CHILD_SA rekey carrying a KE payload is ~256 B
    larger than one without. Only judgeable when a rekey is observed."""
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
    if sizes and max(sizes) >= 400:
        r.add(Finding("pfs", Status.INFERRED, Vantage.T1, "pfs (EXP-03 length gap)", value=True,
                      confidence=0.9, evidence=ev, note=f"CREATE_CHILD_SA request {max(sizes)} B carries a KE payload"))
    else:
        r.add(Finding("pfs", Status.INFERRED, Vantage.T1, "pfs (EXP-03 length gap)", value=False,
                      confidence=0.9, evidence=ev, note=f"CREATE_CHILD_SA request {max(sizes) if sizes else '?'} B, no KE payload"))


def extract_mode(r: EvidenceRecord) -> None:
    """R4 tunnel/transport. EXP-08: NOT-OBSERVABLE at T0 from ESP alone."""
    r.add(Finding("mode", Status.NOT_OBSERVABLE, Vantage.T0, "mode (EXP-08)",
                  note="tunnel vs transport is not recoverable from passive ESP (every length is "
                       "valid in both modes; the inner IP header is encrypted). Report from T2/topology."))


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
    r.add(Finding("negotiation_outcome", Status.INFERRED, Vantage.T1, "failure_diag",
                  value="child-sa-rejected", confidence=0.7,
                  note="IKE up, no ESP; proposal or traffic-selector mismatch (reason needs T2)"))


ALL_EXTRACTORS = [extract_ike_meta, extract_pq_addke, extract_pfs, extract_mode, extract_failure]


def build_records(pcap: str) -> list[EvidenceRecord]:
    recs = group_sas(pcap)
    for r in recs:
        for ex in ALL_EXTRACTORS:
            ex(r)
    return recs
