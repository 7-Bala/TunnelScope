"""T-130 / DEC-040: known vulnerabilities for the IKE implementation TunnelScope fingerprinted (T-127).

Online (TUNNELSCOPE_NETWORK=on): NVD, EUVD and CISA KEV are queried and cached in TUNNELSCOPE_INTEL_DIR
(default ~/.tunnelscope-intel). Offline: the same directory filled by `tunnelscope intel-bundle` on a connected
machine and copied over; stale data is used and labelled stale, never silently.

What this can and cannot say: traffic reveals WHICH implementation, never its version, so every entry is
"a known vulnerability in some version of <implementation>", labelled INFERRED, never "this box is vulnerable".
Only product names leave the machine; never a capture, an address or a configuration."""
from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
from pathlib import Path

from .. import net
from .sources import PRODUCTS, SOURCES

TTL_S = 24 * 3600
IPSEC_WORDS = re.compile(r"\b(ike|ikev1|ikev2|ipsec|isakmp|charon|pluto|esp|l2tp|xfrm|vpn)\b", re.I)


def cache_dir() -> Path:
    return Path(os.environ.get("TUNNELSCOPE_INTEL_DIR") or Path.home() / ".tunnelscope-intel")


def _path(key: str) -> Path:
    return cache_dir() / (re.sub(r"[^a-z0-9_.-]+", "_", key.lower()) + ".json")


def _cached(key: str, fetch):
    """-> (data, status, fetched_at, reason). Fresh cache wins; else fetch if the network is on; else stale cache."""
    p = _path(key)
    old = json.loads(p.read_text()) if p.is_file() else None
    if old and time.time() - old["fetched_at"] < TTL_S:
        return old["data"], "cached", old["fetched_at"], None
    try:
        if not net.network_enabled():         # decided here, not left to the network layer to refuse
            raise net.NetworkDisabled(f"network is off ({net.ENV}=on fetches fresh data)")
        data = fetch()
    except net.NetworkDisabled as e:
        return ((old["data"], "stale-offline", old["fetched_at"], str(e)) if old else (None, "unavailable", None, str(e)))
    except (net.HttpError, OSError, ValueError) as e:
        reason = f"{type(e).__name__}: {e}"[:200]
        return ((old["data"], "stale-error", old["fetched_at"], reason) if old else (None, "unavailable", None, reason))
    p.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    p.write_text(json.dumps({"fetched_at": now, "key": key, "data": data}))
    return data, "fresh", now, None


def _nvd(keyword: str):
    items, start = [], 0
    key = os.environ.get(SOURCES["nvd"]["key_env"])
    headers = {SOURCES["nvd"]["key_header"]: key} if key else {}
    while True:
        q = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": 2000, "startIndex": start})
        d = net.http_json(f"{SOURCES['nvd']['api']}?{q}", headers=headers, timeout=60)
        for v in d.get("vulnerabilities", []):
            c = v["cve"]
            desc = next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), "")
            m = c.get("metrics", {})
            best = next((m[k][0]["cvssData"] for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
                         if m.get(k)), {})
            cpes = sorted({m["criteria"] for cfg in c.get("configurations", []) for n in cfg.get("nodes", [])
                           for m in n.get("cpeMatch", []) if m.get("vulnerable")})
            items.append({"id": c["id"], "description": desc, "published": c.get("published", "")[:10], "cpes": cpes,
                          "cvss": best.get("baseScore"), "cvss_version": best.get("version"),
                          "severity": best.get("baseSeverity")})
        start += d.get("resultsPerPage", 0) or 1
        if start >= d.get("totalResults", 0):
            return items
        time.sleep(1 if key else 6)          # stay inside NVD's documented rate limit


def _euvd(vendor: str):
    items, page = [], 0
    while True:
        q = urllib.parse.urlencode({"vendor": vendor, "size": 100, "page": page})
        d = net.http_json(f"{SOURCES['euvd']['api']}/search?{q}", timeout=60)
        for it in d.get("items", []):
            cves = [a for a in (it.get("aliases") or "").split() if a.startswith("CVE-")]
            items.append({"euvd_id": it.get("id"), "cves": cves, "epss": it.get("epss"),
                          "cvss": it.get("baseScore"), "description": it.get("description", "")})
        page += 1
        if not d.get("items") or len(items) >= d.get("total", 0) or page > 20:
            return items


def _kev():
    d = net.http_json(SOURCES["cisa_kev"]["api"], timeout=60)
    return [{"cve": v["cveID"], "vendor": v["vendorProject"], "product": v["product"], "added": v.get("dateAdded"),
             "due": v.get("dueDate"), "ransomware": v.get("knownRansomwareCampaignUse"), "name": v.get("vulnerabilityName")}
            for v in d.get("vulnerabilities", [])]


def lookup(implementation: str) -> dict:
    """Known vulnerabilities for one fingerprinted implementation, merged by CVE across NVD, EUVD and CISA KEV."""
    prod = PRODUCTS.get(implementation)
    if not prod:
        return {"implementation": implementation, "cves": [], "sources": {},
                "note": "no product mapping for this implementation"}
    status, cves = {}, {}
    nvd, st, at, why = _cached(f"nvd2-{prod['nvd_keyword']}", lambda: _nvd(prod["nvd_keyword"]))
    status["nvd"] = {"status": st, "fetched_at": at, "reason": why}
    for it in nvd or []:
        cpe = any(prod["cpe"] in c for c in it.get("cpes", []))
        cves[it["id"]] = {"id": it["id"], "description": it["description"], "published": it["published"],
                          "cvss": it["cvss"], "severity": it["severity"], "kev": False, "epss": None, "sources": ["nvd"],
                          # "cpe": NVD lists this product as vulnerable; "keyword": only the text mentions it (e.g. a
                          # management tool FOR strongSwan), weaker
                          "match": "cpe" if cpe else "keyword"}
    euvd, st, at, why = _cached(f"euvd-{prod['euvd_vendor']}", lambda: _euvd(prod["euvd_vendor"]))
    status["euvd"] = {"status": st, "fetched_at": at, "reason": why}
    for it in euvd or []:
        for cid in it["cves"]:
            e = cves.setdefault(cid, {"id": cid, "description": it["description"], "published": None,
                                      "cvss": it["cvss"], "severity": None, "kev": False, "epss": None, "sources": [],
                                      "match": "vendor"})     # EUVD lists it under this vendor
            e["epss"], e["euvd_id"] = it["epss"], it["euvd_id"]
            if "euvd" not in e["sources"]:
                e["sources"].append("euvd")
    kev, st, at, why = _cached("cisa-kev", _kev)
    status["cisa_kev"] = {"status": st, "fetched_at": at, "reason": why}
    vendor, product = prod["kev"]
    for k in kev or []:
        if vendor in k["vendor"].lower() and (product is None or product in k["product"].lower()):
            e = cves.setdefault(k["cve"], {"id": k["cve"], "description": k["name"], "published": None, "cvss": None,
                                           "severity": None, "kev": False, "epss": None, "sources": [],
                                           "match": "vendor"})
            e.update(kev=True, kev_added=k["added"], kev_due=k["due"], ransomware=k["ransomware"])
            if e["match"] == "keyword":
                e["match"] = "vendor"
            e["sources"].append("cisa_kev")
    for e in cves.values():
        e["ipsec_related"] = bool(IPSEC_WORDS.search(e.get("description") or ""))
    rank = {"cpe": 0, "vendor": 1, "keyword": 2}
    ordered = sorted(cves.values(), key=lambda e: (not e["kev"], rank[e["match"]], not e["ipsec_related"],
                                                   -(float(e["cvss"] or 0))))
    return {"implementation": implementation, "status": "INFERRED", "cves": ordered, "sources": status,
            "counts": {"total": len(ordered), "kev": sum(e["kev"] for e in ordered),
                       "product_listed": sum(e["match"] != "keyword" for e in ordered),
                       "ipsec_related": sum(e["ipsec_related"] for e in ordered)},
            "note": (f"known vulnerabilities in SOME version of {implementation}: traffic shows the implementation, never "
                     "its version, so none of these is confirmed on this tunnel. Version needs the configuration or "
                     "endpoint data. Sources: " + ", ".join(SOURCES[s]["attribution"] for s in ("nvd", "euvd", "cisa_kev")))}


def bundle(out_dir: str) -> dict:
    """Fill a directory with everything lookup() needs, for an air-gapped install (copy it and set
    TUNNELSCOPE_INTEL_DIR). Also stores the full ATT&CK and CAPEC catalogues."""
    os.environ["TUNNELSCOPE_INTEL_DIR"] = out_dir
    report = {}
    for impl in PRODUCTS:
        r = lookup(impl)
        report[impl] = {s: v["status"] for s, v in r["sources"].items()} | {"cves": r["counts"]["total"]}
    for sid in ("mitre_attack", "mitre_capec"):
        _, st, _, why = _cached(sid, lambda s=sid: net.http_json(SOURCES[s]["api"], timeout=300))
        report[sid] = st if not why else f"{st}: {why}"
    manifest = {"created_at": time.time(), "sources": {k: {x: v[x] for x in ("name", "owner", "licence",
                "licence_verified", "redistributable", "attribution")} for k, v in SOURCES.items()},
                "report": report,
                "warning": "Sources with redistributable=false may be used on the machine that fetched them; check "
                           "their terms before giving this bundle to anyone else."}
    Path(out_dir, "MANIFEST.json").write_text(json.dumps(manifest, indent=1))
    return manifest
