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

    # attach ESP packets by address pair
    for r in recs.values():
        r._esp = []
    all_esp_by_pair = defaultdict(list)
    for p in esp:
        all_esp_by_pair[tuple(sorted([p["src"], p["dst"]]))].append(p)
    for r in recs.values():
        r._esp = all_esp_by_pair.get(tuple(sorted([r.src, r.dst])), [])

    # ESP-only flows (T0: the SA predates the capture, no IKE visible) still get a
    # record so size/timing leakage and the cipher sieve can run on them.
    ike_pairs = {tuple(sorted([r.src, r.dst])) for r in recs.values()}
    for pair, pkts in all_esp_by_pair.items():
        if pair in ike_pairs:
            continue
        esp_r = EvidenceRecord(src=pkts[0]["src"], dst=pkts[0]["dst"], source_pcap=pcap)
        esp_r._ike = []
        esp_r._esp = pkts
        esp_r._esp_only = True
        recs[("esp", pair)] = esp_r

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



def extract_ike_crypto(r: EvidenceRecord) -> None:
    """R4/R6/R8 for the IKE SA: ENCR (+key length), PRF, INTEG, DH group. All
    plaintext in the IKE_SA_INIT response -> O at T1. Note this is the IKE SA
    key length (observable); the ESP key length is NOT (F-05)."""
    c = tshark.ike_sa_crypto(r.source_pcap)
    # c is {} (no response) or has None fields (a NO_PROPOSAL_CHOSEN response
    # selected nothing). Either way, a field we could not read is UNKNOWN, never
    # a value-less OBSERVED (ADR-002).
    ev = [EvidencePtr(r.source_pcap, None, "isakmp IKE_SA_INIT response", str(c))]
    enc = (f"{c.get('encr')}-{c['encr_keylen']}" if c.get("encr") and c.get("encr_keylen")
           else c.get("encr"))
    for attr, val, extra in (("ike_encr", enc, {}),
                             ("ike_integ", c.get("integ"), {}),
                             ("ike_dh_group", c.get("dh"), {"note": f"DH group id {c.get('dh_id')}"})):
        if val:
            r.add(Finding(attr, Status.OBSERVED, Vantage.T1, "ike_crypto", value=val, evidence=ev, **extra))
        else:
            r.add(Finding(attr, Status.UNKNOWN, Vantage.T0, "ike_crypto",
                          note="no IKE SA suite selected (negotiation failed or no response visible)"))


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


ALL_EXTRACTORS = [extract_ike_meta, extract_ike_crypto, extract_pq_addke,
                  extract_cipher_sieve, extract_pfs, extract_mode, extract_failure,
                  extract_leakage]


def build_records(pcap: str) -> list[EvidenceRecord]:
    recs = group_sas(pcap)
    for r in recs:
        for ex in ALL_EXTRACTORS:
            ex(r)
    return recs
