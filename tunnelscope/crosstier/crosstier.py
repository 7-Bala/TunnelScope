"""Stage-3 C5 — cross-tier consistency (DEC-005 constraint 4; NOTES #13).

Ingests **T2 endpoint telemetry** — what the box itself reports, from
`swanctl --list-sas`, the pluto log, or the config — and reconciles it against
the T0/T1 passive findings already in an EvidenceRecord. Each cross-checked
attribute resolves to one of three honest outcomes:

  * ESCALATION   — the passive tier was UNKNOWN / NOT_OBSERVABLE, and T2 supplies
                   the answer (e.g. tunnel-vs-transport mode, invisible on the
                   wire per EXP-08, is stated in the config).
  * CONFIRMATION — T2 agrees with the passive finding, or refines it to the
                   exact value *within* the passive candidate set (e.g. the ESP
                   cipher family narrows to one cipher). Raises authority to T2.
  * CONTRADICTION — T2 disagrees. The finding becomes Status.CONTRADICTORY: the
                   honest alarm that configuration and wire have diverged. The
                   canonical real case is NOTES #13 — IP-TFS/TFC padding was
                   configured but the kernel never applied it, so T2 says
                   "padding on" while T0 measures "padding off".

Direction of trust (invariant): ground truth is causal — the endpoint's own
report. The analyzer's passive inference is checked *against* T2, never the
reverse. This module therefore only ever raises a passive finding's authority
or flags a divergence; it does not let a passive guess overrule the endpoint.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

from ..evidence.record import EvidenceRecord, Finding, Status, Vantage

# Attributes we know how to cross-check, and how the T2 value maps onto the
# passive finding. Anything else in the telemetry is ignored (with a note).
_SCALAR = {"mode", "ike_dh_group"}
_METHOD = "T2 endpoint telemetry (swanctl/pluto/config)"


@dataclass
class CrossCheck:
    attribute: str
    outcome: str          # "escalation" | "confirmation" | "contradiction" | "new"
    passive: object
    endpoint: object
    note: str


def _passive_absent(f: Finding | None) -> bool:
    return f is None or f.status in (Status.UNKNOWN, Status.NOT_OBSERVABLE)


def _reconcile_scalar(rec, attr, t2_val, checks):
    f = rec.findings.get(attr)
    if _passive_absent(f):
        rec.findings[attr] = Finding(attr, Status.OBSERVED, Vantage.T2, _METHOD,
                                     value=t2_val, note="supplied by endpoint (not observable passively)")
        checks.append(CrossCheck(attr, "escalation", None if f is None else f.value, t2_val,
                                 f"T0/T1 could not see {attr}; T2 says {t2_val!r}"))
        return
    if f.value == t2_val:
        checks.append(CrossCheck(attr, "confirmation", f.value, t2_val, f"T2 confirms {attr}={t2_val!r}"))
        # keep the passive finding but stamp confirmation in its note
        rec.findings[attr] = Finding(attr, f.status, f.vantage, f.method, value=f.value,
                                     confidence=f.confidence, evidence=f.evidence,
                                     note=(f.note + " | " if f.note else "") + f"confirmed by T2")
        return
    rec.findings[attr] = Finding(attr, Status.CONTRADICTORY, Vantage.T2,
                                 f"{f.method} vs {_METHOD}", value=None,
                                 note=f"passive {f.vantage.value}={f.value!r} disagrees with T2={t2_val!r}")
    checks.append(CrossCheck(attr, "contradiction", f.value, t2_val,
                             f"passive {f.value!r} vs endpoint {t2_val!r}"))


def _reconcile_esp_cipher(rec, t2_cipher, checks):
    """esp_cipher_family is a *candidate set* at T0 (EXP-01 sieve). T2 gives the
    exact cipher: within the set => refinement/confirmation; outside => conflict."""
    fam = rec.findings.get("esp_cipher_family")
    if _passive_absent(fam) or not isinstance(fam.value, list):
        rec.findings["esp_cipher"] = Finding("esp_cipher", Status.OBSERVED, Vantage.T2, _METHOD,
                                              value=t2_cipher, note="supplied by endpoint")
        checks.append(CrossCheck("esp_cipher", "escalation", None, t2_cipher, "no T0 sieve; T2 gives exact cipher"))
        return
    # The T0 sieve distinguishes only cipher *modes/families* (it cannot see key
    # length, F-05). Consistency means the exact T2 cipher shares a mode family
    # with a sieve entry — not a literal substring match.
    def _family(s):
        s = s.upper().replace("_", "").replace("-", "")
        for k in ("CHACHA", "POLY", "GCM", "CCM", "CTR", "CBC"):
            if k in s:
                return "CHACHA" if k in ("CHACHA", "POLY") else k
        return s
    t2_fam = _family(t2_cipher)
    inside = any(_family(c) == t2_fam for c in fam.value)
    if inside:
        rec.findings["esp_cipher"] = Finding("esp_cipher", Status.OBSERVED, Vantage.T2, _METHOD,
                                              value=t2_cipher,
                                              note=f"refines T0 candidate set ({len(fam.value)} options) to the exact cipher")
        checks.append(CrossCheck("esp_cipher", "confirmation", fam.value, t2_cipher,
                                 f"T2 {t2_cipher!r} lies within the T0 sieve set"))
    else:
        rec.findings["esp_cipher"] = Finding("esp_cipher", Status.CONTRADICTORY, Vantage.T2,
                                             f"EXP-01 sieve vs {_METHOD}", value=None,
                                             note=f"T2 cipher {t2_cipher!r} is outside the T0 sieve set {fam.value}")
        checks.append(CrossCheck("esp_cipher", "contradiction", fam.value, t2_cipher,
                                 f"endpoint {t2_cipher!r} not in T0 sieve set"))


def _reconcile_pq(rec, t2_pq, checks):
    """pq_key_exchange may be a list (['ML-KEM-768']) or a string
    ('offered-but-not-used' / 'classical-only') at T0/T1. T2 states what was
    actually installed."""
    f = rec.findings.get("pq_key_exchange")
    if _passive_absent(f):
        rec.findings["pq_key_exchange"] = Finding("pq_key_exchange", Status.OBSERVED, Vantage.T2,
                                                  _METHOD, value=t2_pq, note="installed KE reported by endpoint")
        checks.append(CrossCheck("pq_key_exchange", "escalation", None, t2_pq, "T2 gives installed KE"))
        return
    pv = f.value
    # "offered-but-not-used" (T0/T1 inference) and "classical-only" (installed)
    # both mean "no PQ in effect" — consistent, not a conflict.
    no_pq = {"offered-but-not-used", "classical-only"}
    agree = (pv == t2_pq) or (isinstance(pv, list) and t2_pq in pv) or (pv in no_pq and t2_pq in no_pq)
    if agree:
        checks.append(CrossCheck("pq_key_exchange", "confirmation", pv, t2_pq, f"T2 confirms {t2_pq!r}"))
    else:
        rec.findings["pq_key_exchange"] = Finding("pq_key_exchange", Status.CONTRADICTORY, Vantage.T2,
                                                  f"{f.method} vs {_METHOD}", value=None,
                                                  note=f"passive {pv!r} disagrees with endpoint {t2_pq!r}")
        checks.append(CrossCheck("pq_key_exchange", "contradiction", pv, t2_pq, f"{pv!r} vs {t2_pq!r}"))


def _reconcile_tfc(rec, t2_active, checks):
    """The NOTES #13 case. metadata_exposure carries tfc_padding_active measured
    from the wire (T0). T2 reports whether padding was *configured*. Divergence
    is a real, documented failure mode (kernel silently did not apply IP-TFS)."""
    me = rec.findings.get("metadata_exposure")
    observed = None
    if me is not None and isinstance(me.value, dict):
        observed = me.value.get("tfc_padding_active")
    if observed is None:
        checks.append(CrossCheck("tfc_padding_active", "new", None, t2_active,
                                 "no T0 padding measurement to compare"))
        return
    if bool(observed) == bool(t2_active):
        checks.append(CrossCheck("tfc_padding_active", "confirmation", observed, t2_active,
                                 f"T2 and T0 agree padding is {'on' if observed else 'off'}"))
    else:
        rec.findings["tfc_padding_active"] = Finding("tfc_padding_active", Status.CONTRADICTORY, Vantage.T2,
                                                     f"EXP-05 wire measurement vs {_METHOD}", value=None,
                                                     note=(f"config/T2 says padding={t2_active} but T0 measured "
                                                           f"padding={observed} (NOTES #13: IP-TFS configured, "
                                                           "kernel did not apply it)"))
        checks.append(CrossCheck("tfc_padding_active", "contradiction", observed, t2_active,
                                 f"configured {t2_active} vs measured {observed}"))


def apply_telemetry(rec: EvidenceRecord, telemetry: dict) -> list[CrossCheck]:
    """Reconcile one SA's T2 telemetry into its record. Returns the cross-checks."""
    checks: list[CrossCheck] = []
    for attr in _SCALAR:
        if attr in telemetry:
            _reconcile_scalar(rec, attr, telemetry[attr], checks)
    if "esp_cipher" in telemetry:
        _reconcile_esp_cipher(rec, telemetry["esp_cipher"], checks)
    if "pq_key_exchange" in telemetry:
        _reconcile_pq(rec, telemetry["pq_key_exchange"], checks)
    if "tfc_padding_active" in telemetry:
        _reconcile_tfc(rec, telemetry["tfc_padding_active"], checks)
    return checks


def load_telemetry(path: str) -> dict:
    """Load a T2 telemetry file (JSON, or trivial key: value YAML)."""
    text = open(path).read()
    if path.endswith(".json"):
        return json.loads(text)
    try:
        import yaml
        return yaml.safe_load(text)
    except Exception:
        # minimal key: value fallback so YAML is optional
        out = {}
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            k, v = (x.strip() for x in line.split(":", 1))
            if v.lower() in ("true", "false"):
                out[k] = v.lower() == "true"
            elif v:
                out[k] = v
        return out


def crosstier_records(recs: list[EvidenceRecord], telemetry: dict) -> dict:
    """Apply telemetry to the record(s) it addresses. Telemetry may be a single
    SA block (applied to the sole IKE-bearing record) or keyed by initiator SPI."""
    ike_recs = [r for r in recs if getattr(r, "_ike", [])]
    results = {}
    if telemetry and all(isinstance(v, dict) for v in telemetry.values()):
        by_spi = {r.ike_spi_i: r for r in ike_recs}
        for spi, tel in telemetry.items():
            r = by_spi.get(spi) or (ike_recs[0] if len(ike_recs) == 1 else None)
            if r is not None:
                results[spi] = apply_telemetry(r, tel)
    elif ike_recs:
        results[ike_recs[0].key()] = apply_telemetry(ike_recs[0], telemetry)
    return results
