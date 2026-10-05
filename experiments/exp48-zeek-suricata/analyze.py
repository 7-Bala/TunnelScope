"""EXP-48 scorer (bars fixed in PREREG.md and its addenda; committed before the scored run).

    experiments/exp48-zeek-suricata/sensors.sh SENSOR_DIR          # Suricata and Zeek over every capture (Docker)
    python3 experiments/exp48-zeek-suricata/analyze.py SENSOR_DIR  # H1-H6, writes results/summary.json

Needs Docker for H1 (the real Zeek reader). Everything else reads the sensor output on disk.
"""
import ast
import glob
import io
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, REPO)
from tunnelscope.cli import main as cli_main  # noqa: E402
from tunnelscope.evidence.extract import build_records  # noqa: E402
from tunnelscope.siem import ecs, eve, export, zeek  # noqa: E402

CAP = os.path.join(REPO, "testbed", "captures")
AT = "2026-10-04T10:00:00Z"
SAMPLE_H6 = ["exp15/s-ecp256.pcap", "exp15/s-3des.pcap", "exp15/s-x25519.pcap", "exp15/s-modp1536.pcap", "exp15/s-modp4096.pcap",
             "cloud/c-v1.pcap", "cloud/c-w.pcap", "exp15/a-tra-sha1.pcap", "exp07/e7-pfs-on.pcap", "a7-cs-aes256gcm16.pcap"]

# ---- the name mapping of H4 (fixed here): both vocabularies -> an IANA-registry family, never compared by string
DH_NUM = {"MODP-768": 1, "MODP-1024": 2, "MODP-1536": 5, "MODP-2048": 14, "MODP-3072": 15, "MODP-4096": 16, "MODP-6144": 17, "MODP-8192": 18,
          "ECP-256": 19, "ECP-384": 20, "ECP-521": 21, "MODP-1024-S160": 22, "MODP-2048-S224": 23, "MODP-2048-S256": 24,
          "CURVE25519": 31, "CURVE448": 32}
SURI_DH_V1 = {"GROUPMODP768BIT": 1, "GROUPALTERNATE1024BITMODPGROUP": 2, "GROUPMODP1536BIT": 5, "GROUPMODP2048BIT": 14, "GROUPMODP3072BIT": 15,
              "GROUPMODP4096BIT": 16, "GROUPMODP6144BIT": 17, "GROUPMODP8192BIT": 18, "GROUPRANDOMECP256": 19, "GROUPRANDOMECP384": 20,
              "GROUPRANDOMECP521": 21}


def dh_family(name, suricata):
    if not isinstance(name, str):
        return None
    k = re.sub(r"[^A-Z0-9]", "", name.upper())
    if suricata:
        if k in SURI_DH_V1:
            return SURI_DH_V1[k]
        m = re.fullmatch(r"MODP(\d+)(S\d+)?", k)
        if m:
            return DH_NUM.get(f"MODP-{m.group(1)}" + (f"-{m.group(2)}" if m.group(2) else ""))
        m = re.fullmatch(r"ECP(\d+)", k)
        if m:
            return DH_NUM.get(f"ECP-{m.group(1)}")
        return DH_NUM.get({"CURVE25519": "CURVE25519", "CURVE448": "CURVE448"}.get(k, "?"))
    return DH_NUM.get(name.upper())


def enc_family(name, suricata):
    """(family, key length or None)."""
    if not isinstance(name, str):
        return None
    if suricata:
        fam = {"ENCR_AES_CBC": "AES-CBC", "ENCR_AES_GCM_16": "AES-GCM-16", "ENCR_3DES": "3DES", "ENCR_NULL": "NULL", "ENCAESCBC": "AES-CBC",
               "ENCTRIPLEDESCBC": "3DES", "ENCR_AES_CTR": "AES-CTR", "ENCR_AES_GCM_8": "AES-GCM-8", "ENCR_AES_GCM_12": "AES-GCM-12"}.get(name.upper())
        return (fam, None) if fam else None
    m = re.fullmatch(r"(AES-CBC|AES-CTR|AES-GCM-\d+|AES-CCM-\d+)-(\d+)", name)
    if m:
        return m.group(1), int(m.group(2))
    return (name, None) if name in ("3DES", "NULL", "ChaCha20-Poly1305") else None


def hash_family(name, suricata):
    """integ (HMAC-SHA2-256-128 ...) and prf (PRF-HMAC-SHA2-256) names -> (kind, hash) with kind from where the name sits."""
    if not isinstance(name, str):
        return None
    if suricata:
        v1 = {"HASHMD5": "HMAC-MD5", "HASHSHA": "HMAC-SHA1", "HASHTIGER": "HMAC-TIGER", "HASHSHA2_256": "HMAC-SHA2-256", "HASHSHA2_384": "HMAC-SHA2-384",
              "HASHSHA2_512": "HMAC-SHA2-512"}
        if name.upper() in v1:
            return v1[name.upper()]
        k = re.sub(r"^(AUTH|PRF)_", "", name.upper()).replace("_", "-")
        return k if k.startswith("HMAC-") else None
    k = re.sub(r"^PRF-", "", name.upper())
    return k if k.startswith("HMAC-") else None


# ---- reading
def rel_names():
    return sorted(os.path.relpath(p, CAP) for p in glob.glob(os.path.join(CAP, "**", "*.pcap"), recursive=True))


def sensor_name(rel):
    return rel.replace(os.sep, "_")


def read_eve(sdir, rel):
    path = os.path.join(sdir, "suricata", sensor_name(rel), "eve.json")
    return [json.loads(l) for l in open(path)] if os.path.exists(path) else []


def read_conn(sdir, rel):
    path = os.path.join(sdir, "zeek", sensor_name(rel), "conn.log")
    if not os.path.exists(path):
        return []
    fields, rows = None, []
    for l in open(path):
        l = l.rstrip("\n")
        if l.startswith("#fields"):
            fields = l.split("\t")[1:]
        elif not l.startswith("#"):
            rows.append(dict(zip(fields, l.split("\t"))))
    return rows


# ---- H1: the real Zeek reader
READER = """redef exit_only_after_terminate = T;
type Val: record {
  ts: time;
  id: record { orig_h: addr &optional; resp_h: addr &optional; };
  ike_spi_i: string &optional; ike_spi_r: string &optional;
  baseline: string &optional; rule_id: string &optional; attribute: string &optional; verdict: string &optional; severity: string &optional;
  title: string &optional; observed: string &optional; message: string &optional;
};
function h(s: string): string { return s == "" ? "" : bytestring_to_hexstr(s); }
event line(description: Input::EventDescription, tpe: Input::Event, v: Val) {
  print fmt("ROW|%.6f|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s", time_to_double(v$ts),
    (v?$id && v$id?$orig_h) ? cat(v$id$orig_h) : "UNSET", (v?$id && v$id?$resp_h) ? cat(v$id$resp_h) : "UNSET",
    v?$ike_spi_i ? "S" + h(v$ike_spi_i) : "UNSET", v?$ike_spi_r ? "S" + h(v$ike_spi_r) : "UNSET",
    v?$baseline ? "S" + h(v$baseline) : "UNSET", v?$rule_id ? "S" + h(v$rule_id) : "UNSET", v?$attribute ? "S" + h(v$attribute) : "UNSET",
    v?$verdict ? "S" + h(v$verdict) : "UNSET", v?$severity ? "S" + h(v$severity) : "UNSET", v?$title ? "S" + h(v$title) : "UNSET",
    v?$observed ? "S" + h(v$observed) : "UNSET", v?$message ? "S" + h(v$message) : "UNSET");
}
event zeek_init() { Input::add_event([$source="/d/t.log", $name="t", $fields=Val, $ev=line, $want_record=T, $mode=Input::MANUAL]); }
event Input::end_of_data(name: string, source: string) { print "END"; terminate(); }
"""

HOSTILE = [dict(observed="a\tb\nc\\d"), dict(observed="-"), dict(observed=""), dict(observed="(empty)"), dict(observed="héllo ☃   end"),
           dict(observed="x" * 3000), dict(observed=["list", 1]), dict(message="-"), dict(message=None), dict(observed="\\x09"),
           dict(title="t\r\n"), dict(observed="\x00\x01\x1f\x7f\xff")]
BASE = dict(baseline="B", rule_id="R", attribute="a", verdict="FAIL", severity="high", title="t", observed="o", message="m")


def expected_cells(row_line):
    """What the reader must return for a row we wrote, as the script prints it, computed from the in-memory values (not from the file)."""
    return row_line


def h1(corpus_rows, per_capture_cli_ok, log):
    at = ecs.timestamp(AT)
    items = list(corpus_rows)                                  # (verdict dict, src, dst, sa)
    for c in HOSTILE:
        items.append(({**BASE, **c}, "10.0.0.1", "fe80::1%eth0", "?_?"))
    items.append(({**BASE}, "2001:db8::1", "10.0.0.2", "6a40351269c748e6_e52016fd8d3f5989"))
    text = zeek.document([zeek.row(v, src=s, dst=d, sa=sa, at=at) for v, s, d, sa in items], at)
    d = tempfile.mkdtemp(prefix="exp48-h1-")
    open(os.path.join(d, "t.log"), "w", encoding="utf-8").write(text)
    open(os.path.join(d, "r.zeek"), "w").write(READER)
    r = subprocess.run(["docker", "run", "--rm", "-v", f"{d}:/d", "-w", "/d", "--entrypoint", "zeek", "zeek/zeek:latest", "-C", "r.zeek"],
                       capture_output=True, text=True, timeout=600)
    rows = [l for l in r.stdout.splitlines() if l.startswith("ROW|")]
    problems = []
    if "END" not in r.stdout.splitlines():
        problems.append("reader never reached end of data")
    if r.stderr.strip() and "received termination signal" not in r.stderr:
        problems.append("reader stderr: " + r.stderr.strip()[:300])
    if len(rows) != len(items):
        problems.append(f"read {len(rows)} rows, wrote {len(items)}")
    hx = lambda s: "S" + s.encode("utf-8").hex() if s not in (None, "") else "UNSET"
    for i, ((v, s, dd, sa), got) in enumerate(zip(items, rows)):
        spi_i, spi_r = zeek._spis(sa)
        obs, _ = ecs.as_text(v.get("observed"))
        want = ["ROW", f"{zeek._epoch(at):.6f}", ecs.as_ip(s) or "UNSET", ecs.as_ip(dd) or "UNSET", hx(spi_i), hx(spi_r), hx(v["baseline"]),
                hx(v["rule_id"]), hx(v["attribute"]), hx(v["verdict"]), hx(v.get("severity", "medium")), hx(v["title"]), hx(obs),
                hx(v.get("message"))]
        if got.split("|") != want:
            problems.append(f"row {i}: wrote {want} read {got.split('|')}")
            if len(problems) > 12:
                break
    # zeek-cut over the same file
    cut = subprocess.run(["docker", "run", "--rm", "-v", f"{d}:/d", "-w", "/d", "--entrypoint", "sh", "zeek/zeek:latest", "-c",
                          "zeek-cut ts rule_id verdict < t.log | wc -l; zeek-cut -n ts < t.log | wc -l"], capture_output=True, text=True)
    cut_lines = [x.strip() for x in cut.stdout.split()]
    if cut_lines[:1] != [str(len(items))]:
        problems.append(f"zeek-cut returned {cut_lines[:1]} lines, expected {len(items)}")
    log(f"H1: wrote {len(items)} rows ({len(corpus_rows)} corpus + {len(HOSTILE) + 1} hostile), reader returned {len(rows)}, "
        f"{len(problems)} problem(s), CLI==module on {per_capture_cli_ok[0]}/{per_capture_cli_ok[1]} captures")
    return {"rows_written": len(items), "corpus_rows": len(corpus_rows), "hostile_rows": len(HOSTILE) + 1, "rows_read": len(rows),
            "zeek_cut_lines": cut_lines[:1], "problems": problems, "cli_equals_module": per_capture_cli_ok,
            "pass": not problems and per_capture_cli_ok[0] == per_capture_cli_ok[1]}


def main():
    sdir = os.path.abspath(sys.argv[1])
    out = {"sensor_images": open(os.path.join(sdir, "images.txt")).read().split("\n")[:2]}
    lines = []

    def log(s):
        print(s, flush=True)
        lines.append(s)

    names = rel_names()
    out["captures"] = len(names)
    out["capture_list_sha256"] = __import__("hashlib").sha256("\n".join(names).encode()).hexdigest()
    corpus_rows, eve_all, tunnels = [], [], []
    cli_ok = [0, 0]
    for rel in names:
        p = os.path.join(CAP, rel)
        recs = [r for r in build_records(p) if getattr(r, "_ike", []) or getattr(r, "_esp", []) or getattr(r, "_ah", [])]
        for v, ctx in export.verdicts(p):
            corpus_rows.append((v, ctx["src"], ctx["dst"], ctx["sa"]))
        for line in export.eve_lines(p, at=AT):
            eve_all.append((rel, line))
        for r in recs:
            tunnels.append({"cap": rel, "src": r.src, "dst": r.dst, "spi_i": r.ike_spi_i, "spi_r": r.ike_spi_r, "ike": bool(getattr(r, "_ike", [])),
                            "esp": bool(getattr(r, "_esp", [])), "ah": bool(getattr(r, "_ah", [])),
                            "f": {a: (r.findings[a].value if a in r.findings and r.findings[a].status.value == "OBSERVED"
                                      and isinstance(r.findings[a].value, str) else None)
                                  for a in ("ike_version", "ike_encr", "ike_integ", "ike_prf", "ike_dh_group")},
                            "rekey": any(m["exchange"] == 36 for m in getattr(r, "_ike", []))})
    for rel in SAMPLE_H6 + names[::12]:
        o, e = io.StringIO(), io.StringIO()
        with redirect_stdout(o), redirect_stderr(e):
            cli_main(["export", os.path.join(CAP, rel), "--format", "zeek", "--at", AT])
        cli_ok[1] += 1
        cli_ok[0] += int(o.getvalue() == export.zeek_log(os.path.join(CAP, rel), at=AT))

    out["H1"] = h1(corpus_rows, cli_ok, log)

    # ---- H2
    sur_ts, sur_types = [], Counter()
    for rel in names:
        for ev in read_eve(sdir, rel):
            if ev["event_type"] == "ike":
                sur_ts.append(ev["timestamp"])
                sur_types[(type(ev["event_type"]).__name__, type(ev.get("src_ip")).__name__, type(ev.get("dest_ip")).__name__)] += 1
    pat = re.compile(re.sub(r"\d", r"\\d", re.escape(sur_ts[0]))) if sur_ts else None
    bad = []
    for rel, line in eve_all:
        j = json.loads(line)
        if "\n" in line or not pat.fullmatch(j["timestamp"]) or j["event_type"] != "tunnelscope" or "alert" in j or \
                set(j) - {"timestamp", "event_type", "src_ip", "dest_ip", "tunnelscope"} or \
                (type(j["event_type"]).__name__, type(j.get("src_ip")).__name__, type(j.get("dest_ip")).__name__) not in sur_types:
            bad.append((rel, line[:160]))
    out["H2"] = {"eve_lines": len(eve_all), "suricata_ike_events": len(sur_ts), "suricata_ts_pattern": pat.pattern if pat else None,
                 "all_suricata_ts_match": all(pat.fullmatch(t) for t in sur_ts), "suricata_type_signatures": {"|".join(k): v for k, v in sur_types.items()},
                 "violations": bad[:10], "pass": not bad and all(pat.fullmatch(t) for t in sur_ts)}
    log(f"H2: {len(eve_all)} EVE lines, {len(bad)} violation(s); Suricata timestamp pattern {pat.pattern if pat else None}")

    # ---- H3 / H4 / H5
    h3 = {"ike_tunnels": 0, "ip_pair_in_zeek_conn": 0, "spi_pair_in_suricata": 0, "explained_ip_misses": [], "explained_spi_misses": Counter(),
          "unexplained": []}
    h4 = {"compared": Counter(), "agree": Counter(), "disagree": [], "suricata_silent": Counter(), "ts_unknown": Counter(), "unmapped": Counter(),
          "finer_in_tunnelscope": 0}
    h5 = {"zeek_udp_ike_conns": 0, "zeek_udp_ike_conns_with_service": 0, "zeek_unknown_transport_conns": 0, "captures_with_esp_or_ah": 0,
          "captures_with_esp_or_ah_and_zeek_unknown_transport": 0, "suricata_flow_proto": Counter(), "suricata_esp_flows": 0,
          "rekey_tunnels": 0, "suricata_createchildsa_events": 0, "suricata_createchildsa_with_keyexchange": 0, "suricata_createchildsa_payload_lists": Counter(),
          "suricata_event_types": Counter(), "suricata_anomaly_events": Counter()}
    by_cap = defaultdict(list)
    for t in tunnels:
        by_cap[t["cap"]].append(t)
    for rel in names:
        eve_ev, conns = read_eve(sdir, rel), read_conn(sdir, rel)
        pairs = {frozenset((c["id.orig_h"], c["id.resp_h"])) for c in conns}
        sur_ike = [e for e in eve_ev if e["event_type"] == "ike"]
        spi_pairs = {(e["ike"]["init_spi"], e["ike"]["resp_spi"]) for e in sur_ike}
        for e in eve_ev:
            h5["suricata_event_types"][e["event_type"]] += 1
            if e["event_type"] == "flow":
                h5["suricata_flow_proto"][e["proto"]] += 1
            if e["event_type"] == "anomaly":
                h5["suricata_anomaly_events"][e.get("anomaly", {}).get("event", "?")] += 1
            if e["event_type"] == "ike" and e["ike"].get("exchange_type") == 36 and e["ike"].get("version_major") == 2:
                h5["suricata_createchildsa_events"] += 1
                h5["suricata_createchildsa_payload_lists"]["+".join(e["ike"].get("payload", []))] += 1
                if "KeyExchange" in e["ike"].get("payload", []):
                    h5["suricata_createchildsa_with_keyexchange"] += 1
        h5["suricata_esp_flows"] += sum(1 for e in eve_ev if e["event_type"] == "flow" and e["proto"] in ("ESP", "AH", "50", "51"))
        for c in conns:
            ports = {c.get("id.orig_p"), c.get("id.resp_p")}
            if c["proto"] == "udp" and ports & {"500", "4500"}:
                h5["zeek_udp_ike_conns"] += 1
                h5["zeek_udp_ike_conns_with_service"] += int(c["service"] not in ("-", ""))
            if c["proto"] == "unknown_transport":
                h5["zeek_unknown_transport_conns"] += 1
        ts_here = by_cap.get(rel, [])
        if any(t["esp"] or t["ah"] for t in ts_here):
            h5["captures_with_esp_or_ah"] += 1
            h5["captures_with_esp_or_ah_and_zeek_unknown_transport"] += int(any(c["proto"] == "unknown_transport" for c in conns))
        for t in ts_here:
            h5["rekey_tunnels"] += int(t["rekey"])
            if not t["ike"]:
                continue
            h3["ike_tunnels"] += 1
            if frozenset((t["src"], t["dst"])) in pairs:
                h3["ip_pair_in_zeek_conn"] += 1
            else:
                h3["unexplained"].append(("ip pair not in conn.log", rel, t["src"], t["dst"]))
            if not (t["spi_i"] and t["spi_r"]):
                h3["explained_spi_misses"]["IKE_SA_INIT not in the capture (SPI pair incomplete)"] += 1
            elif (t["spi_i"], t["spi_r"]) in spi_pairs:
                h3["spi_pair_in_suricata"] += 1
            elif not sur_ike:
                h3["explained_spi_misses"]["Suricata logged no ike event for the capture"] += 1
            else:
                h3["unexplained"].append(("spi pair not in suricata", rel, t["spi_i"], t["spi_r"]))
            # H4: responder selection per SA
            sel = None
            for e in sur_ike:
                k = e["ike"]
                if (k["init_spi"], k["resp_spi"]) != (t["spi_i"], t["spi_r"]) or "alg_enc" not in k:
                    continue
                if k.get("version_major") == 2 and k.get("exchange_type") == 34 and k.get("role") == "responder":
                    sel = k
                    break
                if k.get("version_major") == 1 and k["resp_spi"] != "0000000000000000":
                    sel = k
                    break
            if not (t["spi_i"] and t["spi_r"]):
                continue
            v1 = t["f"]["ike_version"] == "IKEv1"
            pairs_cmp = [("ike_encr", enc_family(t["f"]["ike_encr"], False), enc_family(sel and sel.get("alg_enc"), True) if sel else None, sel and sel.get("alg_enc")),
                         ("ike_dh_group", dh_family(t["f"]["ike_dh_group"], False), dh_family(sel and sel.get("alg_dh"), True) if sel else None, sel and sel.get("alg_dh")),
                         ("ike_prf", hash_family(t["f"]["ike_prf"], False), hash_family(sel and (sel.get("alg_hash") if v1 else sel.get("alg_prf")), True) if sel else None,
                          sel and (sel.get("alg_hash") if v1 else sel.get("alg_prf")))]
            if not v1:
                pairs_cmp.append(("ike_integ", hash_family(t["f"]["ike_integ"], False), hash_family(sel and sel.get("alg_auth"), True) if sel else None,
                                  sel and sel.get("alg_auth")))
            for attr, ours, theirs, raw in pairs_cmp:
                if t["f"][attr] is None:
                    h4["ts_unknown"][attr] += 1
                    continue
                if sel is None:
                    h4["suricata_silent"][attr] += 1
                    continue
                if ours is None or theirs is None:
                    h4["unmapped"][(attr, t["f"][attr], raw)] += 1
                    continue
                h4["compared"][attr] += 1
                of, tf = (ours[0], theirs[0]) if isinstance(ours, tuple) else (ours, theirs)
                same = of == tf
                if same and isinstance(ours, tuple) and ours[1] and theirs[1] and ours[1] != theirs[1]:
                    same = False
                if same:
                    h4["agree"][attr] += 1
                    h4["finer_in_tunnelscope"] += int(isinstance(ours, tuple) and ours[1] is not None and theirs[1] is None)
                else:
                    h4["disagree"].append({"capture": rel, "attr": attr, "tunnelscope": t["f"][attr], "suricata": raw, "ikev": "1" if v1 else "2"})
    h3["explained_spi_misses"] = dict(h3["explained_spi_misses"])
    h3["pass"] = not h3["unexplained"]
    out["H3"] = h3
    log(f"H3: {h3['ike_tunnels']} IKE tunnels; IP pair in Zeek conn.log {h3['ip_pair_in_zeek_conn']}; SPI pair in Suricata {h3['spi_pair_in_suricata']}; "
        f"explained SPI misses {h3['explained_spi_misses']}; unexplained {len(h3['unexplained'])}")
    h4_out = {k: (dict(v) if isinstance(v, Counter) else v) for k, v in h4.items()}
    h4_out["unmapped"] = [{"attr": a, "tunnelscope": x, "suricata": y, "n": n} for (a, x, y), n in h4["unmapped"].items()]
    h4_out["pass"] = None  # decided by the owner of the diagnosis in RESULT.md: the bar is "0 undiagnosed disagreements"
    out["H4"] = h4_out
    log(f"H4: compared {dict(h4['compared'])}, agree {dict(h4['agree'])}, disagreements {len(h4['disagree'])}, unmapped {len(h4_out['unmapped'])}")
    h5["suricata_createchildsa_payload_lists"] = dict(h5["suricata_createchildsa_payload_lists"])
    h5["suricata_flow_proto"] = dict(h5["suricata_flow_proto"])
    h5["suricata_event_types"] = dict(h5["suricata_event_types"])
    h5["suricata_anomaly_events"] = dict(h5["suricata_anomaly_events"])
    out["H5"] = h5
    log("H5: " + json.dumps({k: v for k, v in h5.items() if not isinstance(v, dict)}))

    # ---- H6
    banned = {"socket", "ssl", "urllib", "http", "requests", "smtplib", "ftplib"}
    bad_imports = []
    for f in glob.glob(os.path.join(REPO, "tunnelscope", "siem", "*.py")):
        for node in ast.walk(ast.parse(open(f).read())):
            ns = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                [("." * node.level) + (node.module or "")] if isinstance(node, ast.ImportFrom) else []
            bad_imports += [(os.path.basename(f), n) for n in ns if n.split(".")[0] in banned or "net" in n.split(".")]
    base = tempfile.mkdtemp(prefix="exp48-base-")                      # the code the branch started from (the T-129 head)
    subprocess.run(f"git -C {REPO} archive b242551 tunnelscope | tar -x -C {base}", shell=True, check=True)
    same = []
    for rel in SAMPLE_H6:
        for fmt in ("ecs", "syslog"):
            args = ["export", os.path.join(CAP, rel), "--format", fmt, "--at", AT]
            new_out = subprocess.run([sys.executable, "-m", "tunnelscope.cli", *args], capture_output=True, text=True, cwd=REPO,
                                     env={**os.environ, "PYTHONPATH": REPO}).stdout
            old_out = subprocess.run([sys.executable, "-m", "tunnelscope.cli", *args], capture_output=True, text=True, cwd=base,
                                     env={**os.environ, "PYTHONPATH": base}).stdout
            same.append(bool(new_out) and new_out == old_out)
    out["H6"] = {"banned_imports": bad_imports, "pass_imports": not bad_imports, "ecs_syslog_identical_to_base": [sum(same), len(same)],
                 "pass": not bad_imports and all(same)}
    log(f"H6: imports {bad_imports or 'none'}; ecs+syslog byte-identical to the base on {sum(same)}/{len(same)} (capture, format) pairs")
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    json.dump(out, open(os.path.join(HERE, "results", "summary.json"), "w"), indent=1, sort_keys=True, default=str)
    print("wrote results/summary.json")


if __name__ == "__main__":
    main()
