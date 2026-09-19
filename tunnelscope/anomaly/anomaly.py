"""Per-tunnel anomaly detection (T-082): learn what is normal for each tunnel,
flag when it changes. Built for the SOC analyst (role D).

Three layers, from most to least explainable. Each anomaly names its layer.

1. POSTURE (rules, no learning needed beyond the tunnel's own history): the
   tunnel's usual crypto (the most common value it has shown) against today's.
   A move to a weaker key exchange, cipher, integrity or IKE version, losing a
   post-quantum key exchange, or a rule that newly FAILs is a DOWNGRADE (high).
   Crypto that only changes is reported too (medium).
2. TRAFFIC (robust statistics): packet rate, mean size and the size/timing
   exposure bits, against the tunnel's own median, in MAD units. Needs
   MIN_STATS observations. |z| > Z_CUT is flagged (medium).
3. MODEL (Isolation Forest, unsupervised): the whole feature vector against the
   tunnel's history once it has MIN_MODEL observations, and against the rest of
   the fleet (one tunnel unlike its peers) once the fleet has MIN_FLEET tunnels.

What it stores: one JSON line per observation, the posture profile below (no
packets, no payload, no keys) in <history>/history.jsonl. Nothing is learned
until you record observations; a tunnel with fewer than MIN_BASELINE is
reported as 'learning', never as 'normal'.

Tunnel identity is the unordered endpoint pair: IKE SPIs change at every
rekey, the endpoints don't.
"""
from __future__ import annotations

import json
import os
import statistics
import time
from collections import Counter
from pathlib import Path

MIN_BASELINE = 2     # observations before a tunnel has a "usual" posture
MIN_STATS = 5        # before traffic statistics are trusted
MIN_MODEL = 8        # before the per-tunnel Isolation Forest runs
MIN_FLEET = 6        # tunnels before the fleet-peer Isolation Forest runs
Z_CUT = 3.5          # robust z threshold (Iglewicz & Hoaglin's modified z-score)

# Approximate security strength in bits (NIST SP 800-57 Pt 1 Table 2 style
# equivalences). Only the ORDER matters here: it decides upgrade vs downgrade.
DH_BITS = {"MODP-768": 60, "MODP-1024": 80, "MODP-1024-S160": 80, "MODP-1536": 90,
           "MODP-2048": 112, "MODP-2048-S224": 112, "MODP-2048-S256": 112,
           "MODP-3072": 128, "ECP-256": 128, "Curve25519": 128, "MODP-4096": 150,
           "ECP-384": 192, "MODP-6144": 176, "MODP-8192": 200, "Curve448": 224, "ECP-521": 256}
INTEG_BITS = {"NONE": 0, "HMAC-MD5-96": 40, "HMAC-SHA1-96": 80, "AES-XCBC-96": 96,
              "HMAC-SHA2-256-128": 128, "HMAC-SHA2-384-192": 192, "HMAC-SHA2-512-256": 256}
VERSION_RANK = {"IKEv1": 1, "IKEv2": 2}
CRYPTO = ("ike_version", "ike_encr", "ike_integ", "ike_dh_group", "pq")
NUMERIC = ("esp_rate", "esp_mean_len", "size_bits", "timing_bits")


def _encr_bits(v) -> int | None:
    if not isinstance(v, str):
        return None
    if v.startswith("NULL"):
        return 0
    if v.startswith("3DES"):
        return 112
    tail = v.rsplit("-", 1)[-1]
    return int(tail) if tail.isdigit() else None


def _strength(attr: str, v):
    if v is None:
        return None
    if attr == "ike_dh_group":
        return DH_BITS.get(v)
    if attr == "ike_encr":
        return _encr_bits(v)
    if attr == "ike_integ":
        return INTEG_BITS.get(v)
    if attr == "ike_version":
        return VERSION_RANK.get(v)
    if attr == "pq":
        return 1 if v and v not in ("classical-only", "offered-but-not-used") else 0
    return None


def tunnel_id(src: str, dst: str) -> str:
    return " <-> ".join(sorted([src or "?", dst or "?"]))


def profile(record, verdicts) -> dict:
    """The posture of one SA, from findings the pipeline already produced."""
    f = record.findings
    val = lambda k: f[k].value if k in f and f[k].status.value in ("OBSERVED", "MEASURED", "INFERRED") else None
    esp = getattr(record, "_esp", [])
    lens = [p["ip_len"] for p in esp if p.get("ip_len")]
    span = (max(p["t"] for p in esp) - min(p["t"] for p in esp)) if len(esp) > 1 else 0
    mx = val("metadata_exposure") or {}
    pq = val("pq_key_exchange")
    return {
        "ike_version": val("ike_version"), "ike_encr": val("ike_encr"), "ike_integ": val("ike_integ"),
        "ike_dh_group": val("ike_dh_group"),
        "pq": "+".join(pq) if isinstance(pq, list) else pq,
        "fails": sorted({v.rule_id for v in verdicts if v.verdict == "FAIL"}),
        "esp_rate": round(len(esp) / span, 3) if span > 0 else None,
        "esp_mean_len": round(sum(lens) / len(lens), 1) if lens else None,
        "size_bits": mx.get("size_bits"), "timing_bits": mx.get("timing_bits"),
    }


class History:
    """Append-only JSONL store of observations. One file, readable by hand."""

    def __init__(self, directory: str):
        self.dir = Path(directory)
        self.path = self.dir / "history.jsonl"

    def load(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text().splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue      # a torn last line must not lose the rest
        return out

    def record(self, tunnel: str, source: str, prof: dict, at: float | None = None) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a") as fh:
            fh.write(json.dumps({"at": at or time.time(), "tunnel": tunnel, "source": source,
                                 "profile": prof}, sort_keys=True) + "\n")


def _mode(values):
    values = [v for v in values if v is not None]
    return Counter(values).most_common(1)[0][0] if values else None


def _vector(p: dict) -> list[float]:
    return [float(_strength(a, p.get(a)) or 0) for a in CRYPTO] + \
           [float(p.get(k) or 0) for k in NUMERIC] + [float(len(p.get("fails") or []))]


def _posture_layer(cur: dict, past: list[dict]) -> list[dict]:
    out = []
    for attr in CRYPTO:
        usual = _mode(p.get(attr) for p in past)
        now = cur.get(attr)
        if usual is None or now is None or now == usual:
            continue
        s0, s1 = _strength(attr, usual), _strength(attr, now)
        name = attr.replace("ike_", "").replace("_", " ")
        if s0 is not None and s1 is not None and s1 < s0:
            out.append({"layer": "posture", "kind": "downgrade", "severity": "high", "attribute": attr,
                        "usual": usual, "now": now,
                        "message": f"{name} downgraded: usually {usual}, now {now}"})
        elif s0 is not None and s1 is not None and s1 > s0:
            out.append({"layer": "posture", "kind": "upgrade", "severity": "informational", "attribute": attr,
                        "usual": usual, "now": now, "message": f"{name} strengthened: usually {usual}, now {now}"})
        else:
            out.append({"layer": "posture", "kind": "change", "severity": "medium", "attribute": attr,
                        "usual": usual, "now": now, "message": f"{name} changed: usually {usual}, now {now}"})
    seen = {r for p in past for r in (p.get("fails") or [])}
    new = sorted(set(cur.get("fails") or []) - seen)
    if new:
        out.append({"layer": "posture", "kind": "new_failure", "severity": "high", "attribute": "fails",
                    "usual": None, "now": new,
                    "message": f"rule(s) failing for the first time on this tunnel: {', '.join(new)}"})
    return out


def _traffic_layer(cur: dict, past: list[dict]) -> list[dict]:
    out = []
    for k in NUMERIC:
        xs = [p[k] for p in past if p.get(k) is not None]
        x = cur.get(k)
        if x is None or len(xs) < MIN_STATS:
            continue
        med = statistics.median(xs)
        mad = statistics.median(abs(v - med) for v in xs)
        if mad == 0:
            mad = max(abs(med) * 0.05, 1e-6)     # a perfectly steady history: allow 5% jitter
        z = 0.6745 * (x - med) / mad
        if abs(z) > Z_CUT:
            out.append({"layer": "traffic", "kind": "shift", "severity": "medium", "attribute": k,
                        "usual": round(med, 3), "now": x, "z": round(z, 1),
                        "message": f"{k.replace('_', ' ')} {'up' if z > 0 else 'down'} sharply: "
                                   f"usually about {med:g}, now {x:g} (robust z {z:+.1f})"})
    return out


def _iforest_outlier(train: list[list[float]], x: list[float]) -> float | None:
    """Isolation Forest anomaly score for x against train (sklearn convention:
    negative = anomalous). None if too little data to fit."""
    from sklearn.ensemble import IsolationForest
    if len(train) < 2:
        return None
    m = IsolationForest(n_estimators=200, contamination="auto", random_state=0).fit(train)
    return float(m.decision_function([x])[0])


def _model_layer(cur: dict, past: list[dict]) -> list[dict]:
    if len(past) < MIN_MODEL:
        return []
    s = _iforest_outlier([_vector(p) for p in past], _vector(cur))
    if s is not None and s < 0:
        return [{"layer": "model", "kind": "outlier", "severity": "medium", "attribute": "profile",
                 "usual": None, "now": None, "score": round(s, 3),
                 "message": f"Isolation Forest: this observation is unlike the tunnel's last {len(past)} "
                            f"(score {s:+.3f}; below 0 is anomalous)"}]
    return []


def detect(cur: dict, past: list[dict]) -> dict:
    """Compare one observation with that tunnel's earlier ones."""
    if len(past) < MIN_BASELINE:
        return {"status": "learning", "observations": len(past), "needed": MIN_BASELINE, "anomalies": []}
    anomalies = _posture_layer(cur, past) + _traffic_layer(cur, past) + _model_layer(cur, past)
    real = [a for a in anomalies if a["severity"] != "informational"]
    return {"status": "anomalous" if real else "normal", "observations": len(past), "anomalies": anomalies,
            "layers": ["posture"] + (["traffic"] if len(past) >= MIN_STATS else [])
                      + (["model"] if len(past) >= MIN_MODEL else [])}


def fleet_outliers(latest: dict[str, dict]) -> dict[str, dict]:
    """Tunnels unlike their peers (latest profile per tunnel), via Isolation
    Forest. Returns {tunnel: anomaly}. Empty below MIN_FLEET tunnels."""
    if len(latest) < MIN_FLEET:
        return {}
    from sklearn.ensemble import IsolationForest
    names = sorted(latest)
    X = [_vector(latest[n]) for n in names]
    m = IsolationForest(n_estimators=200, contamination="auto", random_state=0).fit(X)
    out = {}
    for n, s in zip(names, m.decision_function(X)):
        if s < 0:
            out[n] = {"layer": "model", "kind": "fleet_outlier", "severity": "medium", "attribute": "profile",
                      "usual": None, "now": None, "score": round(float(s), 3),
                      "message": f"unlike the other {len(names) - 1} tunnels in the fleet (Isolation Forest {s:+.3f})"}
    return out


def observe(history: History, sas: list[dict], source: str, record: bool = True, at: float | None = None) -> list[dict]:
    """For each analysed SA ({'record', 'verdicts'} from report.analyze), detect
    against the stored history, then (optionally) record it. Returns one result
    per SA, in order."""
    rows = history.load()
    results = []
    for sa in sas:
        r = sa["record"]
        tid = tunnel_id(r.src, r.dst)
        prof = profile(r, sa["verdicts"])
        past = [x["profile"] for x in rows if x["tunnel"] == tid]
        res = {"tunnel": tid, **detect(prof, past), "profile": prof}
        latest = {}
        for x in rows:
            latest[x["tunnel"]] = x["profile"]
        latest[tid] = prof
        fo = fleet_outliers(latest).get(tid)
        if fo:
            res["anomalies"].append(fo)
            if res["status"] == "normal":
                res["status"] = "anomalous"
        results.append(res)
        if record:
            history.record(tid, source, prof, at)
            rows.append({"tunnel": tid, "source": source, "profile": prof})
    return results


def default_history_dir() -> str | None:
    return os.environ.get("TUNNELSCOPE_HISTORY") or None
