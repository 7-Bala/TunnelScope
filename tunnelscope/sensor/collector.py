"""The central collector (T-139): accepts signed site reports from an inbox directory.

No network listener: reports arrive as files (the TunnelScope server stays 127.0.0.1-only). Each file is checked in
order: known site (a key file `<site>.key` in the keys directory), signature, strict schema, and a sequence number
higher than the last one accepted from that site. A rejected file is moved to `quarantine/` with the reason; an
accepted one updates `sites/<site>.json` and is deleted. Alerts in accepted reports are appended to the central
alert file tagged with the site.

A site's view is only as fresh as its last report: one that has not reported for STALE_WINDOWS of its own windows is
"stale" and its posture is UNKNOWN from then on, never the last one seen (absence of evidence is not a pass).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from . import report as R

STALE_WINDOWS = 3


class Collector:
    def __init__(self, inbox: str, state: str, keys: str, alerts: str | None = None, alert_format: str = "jsonl"):
        self.inbox, self.state, self.keys = Path(inbox), Path(state), Path(keys)
        self.alerts, self.alert_format = alerts, alert_format
        for d in (self.inbox, self.state / "sites", self.state / "quarantine"):
            d.mkdir(parents=True, exist_ok=True)

    def _site_file(self, site: str) -> Path:
        return self.state / "sites" / f"{site}.json"

    def _quarantine(self, p: Path, reason: str) -> dict:
        dest = self.state / "quarantine" / p.name
        os.replace(p, dest)
        dest.with_name(dest.name + ".reason").write_text(reason + "\n")
        return {"file": p.name, "accepted": False, "reason": reason}

    def accept_file(self, p: Path, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        try:
            rep = json.loads(p.read_text())
        except (OSError, ValueError):
            return self._quarantine(p, "not JSON")
        site = rep.get("site") if isinstance(rep, dict) else None
        if not isinstance(site, str) or not all(c.isalnum() or c in "-_." for c in site) or not site:
            return self._quarantine(p, "no valid site name")
        kf = self.keys / f"{site}.key"
        if not kf.is_file():
            return self._quarantine(p, f"unknown site {site!r} (no key)")
        try:
            R.verify(rep, R.read_key(kf))
        except R.ReportError as e:
            return self._quarantine(p, str(e))
        sf = self._site_file(site)
        st = json.loads(sf.read_text()) if sf.exists() else {"site": site, "last_seq": 0, "accepted": 0}
        if rep["seq"] <= st["last_seq"]:
            return self._quarantine(p, f"replayed or out-of-order sequence {rep['seq']} (last accepted {st['last_seq']})")
        gap = rep["seq"] - st["last_seq"] - 1
        st.update(last_seq=rep["seq"], accepted=st["accepted"] + 1, last_seen=now, window_s=rep["window_s"],
                  tool_version=rep["tool_version"], missing=st.get("missing", 0) + gap)
        if rep["kind"] == "window":
            st.update(last_window_end=rep["window_end"], last_window_ok=rep["ok"], tunnels=rep["tunnels"])
            # A window without a handshake says nothing new about the key exchange ("unknown"); the last handshake
            # that WAS observed is kept with its time, so a downgrade stays visible as a dated fact.
            hs = st.setdefault("last_handshake", {})
            for t in rep["tunnels"]:
                if t.get("posture") and not str(t["posture"]).startswith("unknown"):
                    hs[f"{t['src']} <-> {t['dst']}"] = {"posture": t["posture"], "observed_at": rep["window_end"],
                                                        "fails": [f["rule_id"] for f in t["fails"]]}
        else:
            st["last_heartbeat"] = rep["sent_at"]
        if rep["alerts"]:
            st["recent_alerts"] = (st.get("recent_alerts", []) + [
                {k: a.get(k) for k in ("kind", "attribute", "usual", "now", "tunnel", "time")} | {"received": now}
                for a in rep["alerts"]])[-20:]
        if rep["alerts"] and self.alerts:
            from ..anomaly.alerts import write_alerts
            write_alerts([{**a, "site": site, "message": f"{site}: {a['kind']} of {a['attribute']} on {a['tunnel']}",
                           "source": f"sensor:{site}#{rep['seq']}", "received": now} for a in rep["alerts"]],
                         self.alerts, self.alert_format)
        tmp = sf.with_suffix(".tmp")
        tmp.write_text(json.dumps(st, sort_keys=True))
        os.replace(tmp, sf)
        p.unlink()
        return {"file": p.name, "accepted": True, "site": site, "seq": rep["seq"], "alerts": len(rep["alerts"]),
                "kind": rep["kind"]}

    def process_once(self, now: float | None = None) -> list[dict]:
        """Accept every complete file in the inbox, oldest sequence first per site."""
        files = sorted((p for p in self.inbox.iterdir() if p.suffix == ".json" and not p.name.startswith(".")),
                       key=lambda p: p.name)
        return [self.accept_file(p, now) for p in files]

    def run(self, poll_s: float = 1.0, on_result=None) -> None:
        while True:
            for r in self.process_once():
                if on_result:
                    on_result(r)
            time.sleep(poll_s)


def sites_status(state: str, now: float | None = None) -> list[dict]:
    """Per-site freshness. A stale site reports posture UNKNOWN, not its last posture."""
    now = time.time() if now is None else now
    out = []
    d = Path(state) / "sites"
    for sf in sorted(d.glob("*.json")) if d.is_dir() else []:
        st = json.loads(sf.read_text())
        age = now - st.get("last_seen", 0)
        stale = age > STALE_WINDOWS * st.get("window_s", 30)
        hs = st.get("last_handshake", {})

        def handshake(key):
            h = hs.get(key)
            return None if h is None else {**h, "age_s": round(now - (h.get("observed_at") or now), 1)}
        tunnels = [] if stale else [{"src": t["src"], "dst": t["dst"], "posture": t["posture"],
                                     "fails": [f["rule_id"] for f in t["fails"]],
                                     "risk": (t.get("risk") or {}).get("band"),
                                     "last_handshake": handshake(f"{t['src']} <-> {t['dst']}")}
                                    for t in st.get("tunnels") or []]
        out.append({"site": st["site"], "status": "stale" if stale else "reporting", "last_seen": st.get("last_seen"),
                    "age_s": round(age, 1), "window_s": st.get("window_s"), "reports": st.get("accepted"),
                    "missing_reports": st.get("missing", 0), "last_window_ok": st.get("last_window_ok"),
                    "tunnels": tunnels,
                    "recent_alerts": [{**a, "age_s": round(now - a["received"], 1)}
                                      for a in reversed(st.get("recent_alerts", [])[-5:])],
                    "note": (f"no report for {age:.0f} s (> {STALE_WINDOWS} windows): posture UNKNOWN until it reports"
                             if stale else None)})
    return out
