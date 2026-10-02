"""EXP-46 scorer (pre-registered in PREREG.md, 991e939). Writes results/summary.json.

    .venv/bin/python experiments/exp46-siem-export/analyze.py [--limit N] [--keep]

Needs Docker and the two official images already pulled (docker.elastic.co/elasticsearch/elasticsearch:9.5.4,
docker.elastic.co/beats/filebeat:9.5.4). Starts Elasticsearch bound to 127.0.0.1 and Filebeat on a private network,
ingests everything the exporter produces for the corpus, scores H1-H6, then removes the containers and the network.
`--limit N` is a rehearsal on the first N captures: it never writes results/summary.json.
This script (not the tunnelscope package) is the only code here that talks to the network.
"""
import argparse
import ast
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))
CAPS = os.path.join(REPO, "testbed", "captures")
AT = "2026-10-02T12:00:00Z"
ES_IMAGE = "docker.elastic.co/elasticsearch/elasticsearch:9.5.4"
FB_IMAGE = "docker.elastic.co/beats/filebeat:9.5.4"
ES = "http://127.0.0.1:9200"
INDEX = "logs-tunnelscope-default"
H3_CAPTURES = ["exp15/s-ecp256.pcap", "exp15/s-3des.pcap", "exp15/s-x25519.pcap", "exp15/s-modp1536.pcap",
               "exp15/s-modp4096.pcap", "cloud/c-v1.pcap", "cloud/c-w.pcap", "exp15/a-tra-sha1.pcap",
               "exp07/e7-pfs-on.pcap", "a7-cs-aes256gcm16.pcap"]
PROFILE = "nist-sp800-77r1"


def captures(base=None):
    out = []
    for root, _, files in os.walk(base or CAPS):
        out += [os.path.join(root, f) for f in files if f.endswith((".pcap", ".pcapng"))]
    return sorted(out)


# ------------------------------------------------------------------ per-capture work (runs in a pool)
def work(job):
    """job = (path, profile or None). Exports in-process, then asks the CLI's own `assess` for the independent count."""
    path, profile, base = job
    from tunnelscope.siem import ecs as E, syslog as S, export
    rel = os.path.relpath(path, base)
    res = {"rel": rel, "profile": profile, "docs": [], "lines": [], "assess": [], "error": None}
    try:
        profiles = [profile] if profile else None
        for v, ctx in export.verdicts(path, profiles):
            res["docs"].append(E.verdict_event(v, at=AT, **ctx))
            res["lines"].append(S.verdict_line(v, at=AT, hostname="analyze-host", file=ctx["file"], src=ctx["src"],
                                               dst=ctx["dst"], sa=ctx["sa"]))
        cmd = [sys.executable, "-m", "tunnelscope.cli", "assess", path, "--json"] + (["--profile", profile] if profile else [])
        r = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, env={**os.environ, "PYTHONPATH": REPO}, timeout=600)
        if r.returncode != 0:
            res["error"] = f"assess exit {r.returncode}: {r.stderr.strip()[-200:]}"
        else:
            res["assess"] = [(x["rule_id"], x["verdict"]) for x in json.loads(r.stdout)]
    except Exception as e:                        # a capture that cannot be read is reported, never skipped silently
        res["error"] = f"{type(e).__name__}: {e}"
    return res


# ------------------------------------------------------------------ small helpers
def sh(*cmd, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:4])}...: {r.stderr.strip()[-300:]}")
    return r.stdout.strip()


def es(method, path, body=None, raw=None, timeout=120):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(ES + path, data=data, method=method,
                                 headers={"Content-Type": "application/x-ndjson" if raw is not None else "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code, "body": e.read().decode()[:500]}


def wait_es():
    for _ in range(90):
        try:
            if es("GET", "/_cluster/health?wait_for_status=yellow&timeout=5s").get("status") in ("yellow", "green"):
                return
        except Exception:
            pass
        time.sleep(2)
    raise RuntimeError("Elasticsearch did not become ready")


def count(index, query=None):
    return es("POST", f"/{index}/_count", {"query": query} if query else None).get("count")


def all_docs(index, fields):
    """Scroll through an index; returns the _source (limited to `fields`) of every document."""
    out = []
    r = es("POST", f"/{index}/_search?scroll=2m", {"size": 1000, "_source": fields, "query": {"match_all": {}}})
    while r.get("hits", {}).get("hits"):
        out += [h["_source"] for h in r["hits"]["hits"]]
        r = es("POST", "/_search/scroll", {"scroll": "2m", "scroll_id": r["_scroll_id"]})
    return out


def epoch(ts):
    """RFC 3339 / ISO 8601 with Z or an offset -> epoch seconds (so '+00:00' and 'Z' compare equal)."""
    from datetime import datetime, timezone
    d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return int((d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp())


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, help="rehearsal on the first N captures (never writes summary.json)")
    ap.add_argument("--keep", action="store_true", help="leave the containers running")
    ap.add_argument("--captures", default=CAPS, help="capture directory (ADDENDUM A: the full local corpus of the main checkout)")
    a = ap.parse_args()
    t0 = time.time()
    from ecs_check import problems
    from tunnelscope.siem import ecs as E, export, syslog as S
    from tunnelscope.anomaly.alerts import alerts_from, format_alert
    from tunnelscope.anomaly.anomaly import History, observe
    from tunnelscope.report.report import analyze

    base = os.path.abspath(a.captures)
    caps = captures(base)
    names_hash = hashlib.sha256("\n".join(os.path.relpath(c, base) for c in caps).encode()).hexdigest()
    jobs = [(c, None, base) for c in (caps[:a.limit] if a.limit else caps)] + [(os.path.join(base, c), PROFILE, base) for c in H3_CAPTURES]
    print(f"{len(jobs)} export jobs over {len(caps)} captures ...", flush=True)
    with ProcessPoolExecutor(8) as ex:
        results = list(ex.map(work, jobs, chunksize=4))
    errors = [(r["rel"], r["profile"], r["error"]) for r in results if r["error"]]
    docs = [d for r in results for d in r["docs"]]
    lines = [x for r in results for x in r["lines"]]
    print(f"{len(docs)} verdict documents, {len(errors)} capture errors, {time.time() - t0:.0f} s", flush=True)

    # alerts: the T-134 replay on one tunnel, half of them as if reported by a site sensor
    alert_docs, alert_lines = [], []
    with tempfile.TemporaryDirectory() as td:
        h = History(os.path.join(td, "h"))
        for i, n in enumerate(["pq-mlkem768.pcap", "pq-mlkem768.pcap", "pq-downgrade.pcap", "classical-baseline.pcap"]):
            for al in alerts_from(observe(h, analyze(os.path.join(base, n))["sas"], n, at=1759406400.0 + i), n, 1759406400.0 + i):
                if i == 3:
                    al = {**al, "site": "plant-7"}
                alert_docs.append(json.loads(format_alert(al, "ecs")))
                alert_lines.append(format_alert(al, "syslog"))

    # ---- H1 schema
    bad = [(d["rule"]["id"] if "rule" in d else "alert", p) for d in docs + alert_docs for p in problems(d)]
    h1 = {"documents": len(docs) + len(alert_docs), "violations": len(bad), "first": bad[:10], "pass": not bad}

    # ---- H4a strict RFC 5424 parser over every line (verdicts and alerts)
    parsed, parse_bad = [], []
    for ln in lines + alert_lines:
        try:
            parsed.append(S.parse(ln))
        except ValueError as e:
            parse_bad.append((ln[:120], str(e)))

    # ---- H6 determinism and H5 side effects (the CLI, run twice / against origin/main)
    sample = caps[::max(1, len(caps) // 20)][:20] if not a.limit else caps[:min(a.limit, 3)]
    nondet = []
    for c in sample:
        for fmt in ("ecs", "syslog"):
            outs = []
            for _ in range(2):
                buf = io.StringIO()
                with redirect_stdout(buf), redirect_stderr(io.StringIO()):
                    from tunnelscope.cli import main as cli
                    cli(["export", c, "--at", AT, "--format", fmt])
                outs.append(buf.getvalue())
            if outs[0] != outs[1]:
                nondet.append((os.path.relpath(c, base), fmt))
    h6 = {"captures": len(sample), "runs_each": 2, "differences": nondet, "pass": not nondet}

    banned = {"socket", "ssl", "urllib", "http", "requests", "smtplib", "ftplib"}
    net = []
    for f in os.listdir(os.path.join(REPO, "tunnelscope", "siem")):
        if f.endswith(".py"):
            for node in ast.walk(ast.parse(open(os.path.join(REPO, "tunnelscope", "siem", f)).read())):
                names = [x.name for x in node.names] if isinstance(node, ast.Import) else \
                    [("." * node.level) + (node.module or "")] if isinstance(node, ast.ImportFrom) else []
                net += [(f, n) for n in names if n.split(".")[0] in banned or "net" in n.split(".")]
    with tempfile.TemporaryDirectory() as old:
        tar = subprocess.run(["git", "-C", REPO, "archive", "origin/main", "tunnelscope"], capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", old], input=tar, check=True)
        differ = []
        for c in H3_CAPTURES:
            outs = []
            for root in (old, REPO):
                outs.append(subprocess.run([sys.executable, "-m", "tunnelscope.cli", "assess", os.path.join(base, c), "--json"],
                                           capture_output=True, text=True, cwd=root, env={**os.environ, "PYTHONPATH": root}).stdout)
            if outs[0] != outs[1]:
                differ.append(c)
        main_sha = sh("git", "-C", REPO, "rev-parse", "--short", "origin/main")
    h5 = {"network_imports_in_siem": net, "assess_json_differs_from_origin_main": differ, "origin_main": main_sha,
          "pass": not net and not differ}

    # ---- Elasticsearch + Filebeat
    sh("docker", "network", "create", "tsc-net", check=False)
    sh("docker", "rm", "-f", "tsc-es", "tsc-fb", check=False)
    digests = {n: sh("docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", n) for n in (ES_IMAGE, FB_IMAGE)}
    sh("docker", "run", "-d", "--name", "tsc-es", "--network", "tsc-net", "-p", "127.0.0.1:9200:9200",
       "-e", "discovery.type=single-node", "-e", "xpack.security.enabled=false", "-e", "xpack.ml.enabled=false",
       "-e", "ES_JAVA_OPTS=-Xms1g -Xmx1g", ES_IMAGE)
    try:
        wait_es()
        es_version = es("GET", "/")["version"]["number"]
        fb_version = sh("docker", "run", "--rm", FB_IMAGE, "filebeat", "version")
        sent = errors_bulk = 0
        body = [d for d in docs + alert_docs]
        for i in range(0, len(body), 1000):
            raw = "".join(json.dumps({"create": {"_index": INDEX}}) + "\n" + E.dumps(d) + "\n" for d in body[i:i + 1000]).encode()
            r = es("POST", "/_bulk", raw=raw, timeout=300)
            sent += len(body[i:i + 1000])
            errors_bulk += sum(1 for it in r.get("items", []) if "error" in list(it.values())[0]) if r.get("errors") else 0
            if "_http_error" in r:
                errors_bulk += 1000
        es("POST", f"/{INDEX}/_refresh")
        # negative control (ADDENDUM A): a document with a malformed ECS ip. logs-* data streams set ignore_malformed, so
        # Elasticsearch drops the field silently; the `_ignored` check must see it. Separate data stream, not counted below.
        ctl = json.loads(E.dumps(docs[0])); ctl["source"]["ip"] = "not-an-ip"
        r = es("POST", "/_bulk", raw=(json.dumps({"create": {"_index": "logs-tunnelscope-control"}}) + "\n" + E.dumps(ctl) + "\n").encode())
        es("POST", "/logs-tunnelscope-control/_refresh")
        control_es = {"bulk_errors": bool(r.get("errors")), "documents_with_ignored_field": count("logs-tunnelscope-control", {"exists": {"field": "_ignored"}}),
                      "schema_checker_flags_it": bool(problems(ctl))}
        got = count(INDEX)
        ignored = count(INDEX, {"exists": {"field": "_ignored"}})
        mp = es("GET", f"/{INDEX}/_mapping/field/@timestamp,source.ip,destination.ip,rule.id,event.severity,event.kind")
        types = {}
        for v in mp.values():
            for f, m in v["mappings"].items():
                types[f] = list(m["mapping"].values())[0]["type"]
        want = {"@timestamp": "date", "source.ip": "ip", "destination.ip": "ip", "rule.id": "keyword", "event.severity": "long",
                "event.kind": "keyword"}
        agg = es("POST", f"/{INDEX}/_search", {"size": 0, "query": {"term": {"event.dataset": "tunnelscope.verdict"}}, "aggs": {
            "r": {"terms": {"field": "rule.id", "size": 500}, "aggs": {"v": {"terms": {"field": "tunnelscope.verdict", "size": 10}}}}}})
        es_counts = Counter()
        for rb in agg["aggregations"]["r"]["buckets"]:
            for vb in rb["v"]["buckets"]:
                es_counts[(rb["key"], vb["key"])] = vb["doc_count"]
        cli_counts = Counter(tuple(x) for r in results for x in r["assess"])
        diff = sorted(set(es_counts) | set(cli_counts))
        diff = [(k, es_counts[k], cli_counts[k]) for k in diff if es_counts[k] != cli_counts[k]]
        h2 = {"sent": sent, "in_elasticsearch": got, "bulk_item_errors": errors_bulk, "documents_with_ignored_field": ignored,
              "mapping": {k: [types.get(k), v] for k, v in want.items()}, "pass": errors_bulk == 0 and ignored == 0 and got == sent and
              all(types.get(k) == v for k, v in want.items())}
        h3 = {"rule_verdict_pairs": len(cli_counts), "verdict_events_cli": sum(cli_counts.values()),
              "verdict_events_elasticsearch": sum(es_counts.values()), "differences": diff[:20], "pass": not diff and bool(cli_counts)}

        # Filebeat: verdict lines and alert lines as two files
        with tempfile.TemporaryDirectory() as fbd:
            os.chmod(fbd, 0o755)
            open(os.path.join(fbd, "verdicts.log"), "w", encoding="utf-8").write("".join(x + "\n" for x in lines))
            open(os.path.join(fbd, "alerts.log"), "w", encoding="utf-8").write("".join(x + "\n" for x in alert_lines))
            cfg = os.path.join(fbd, "filebeat.yml")
            open(cfg, "w").write(open(os.path.join(HERE, "filebeat.yml")).read())
            os.mkdir(os.path.join(fbd, "data")); os.mkdir(os.path.join(fbd, "control"))
            open(os.path.join(fbd, "control", "bad.log"), "w").write("<14>1 not-a-timestamp h app - - - this is not RFC 5424\n")
            for f in ("verdicts.log", "alerts.log"):
                os.rename(os.path.join(fbd, f), os.path.join(fbd, "data", f))
            sh("docker", "run", "-d", "--name", "tsc-fb", "--network", "tsc-net", "--user", "root",
               "-v", f"{cfg}:/usr/share/filebeat/filebeat.yml:ro", "-v", f"{os.path.join(fbd, 'data')}:/data:ro", "-v", f"{os.path.join(fbd, 'control')}:/control:ro",
               FB_IMAGE, "filebeat", "-e", "--strict.perms=false")
            total = len(lines) + len(alert_lines)
            for _ in range(180):
                es("POST", "/tsc-syslog/_refresh")
                if (count("tsc-syslog") or 0) >= total:
                    break
                time.sleep(2)
            time.sleep(3)
            es("POST", "/tsc-syslog/_refresh")
        for _ in range(30):
            es("POST", "/tsc-control/_refresh")
            if (count("tsc-control") or 0) >= 1:
                break
            time.sleep(2)
        control_fb = {"events": count("tsc-control"), "events_with_error_message": count("tsc-control", {"exists": {"field": "error.message"}})}
        try:
            S.parse("<14>1 not-a-timestamp h app - - - this is not RFC 5424")
            control_fb["strict_parser_rejects_it"] = False
        except ValueError:
            control_fb["strict_parser_rejects_it"] = True
        fb_got = count("tsc-syslog")
        fb_err = count("tsc-syslog", {"exists": {"field": "error.message"}})
        fb_ign = count("tsc-syslog", {"exists": {"field": "_ignored"}})
        src = all_docs("tsc-syslog", ["@timestamp", "message", "log.syslog", "log.file.path", "error"])
        want_c = Counter()
        for p in parsed:
            want_c[json.dumps([p["pri"], p["facility"], p["severity"], p["hostname"], p["app"], p["msgid"], epoch(p["timestamp"]),
                               sorted(p["sd"].get(f"tunnelscope@{S.PEN}", {}).items())], sort_keys=True)] += 1
        got_c = Counter()
        for d in src:
            ls = d["log"]["syslog"]
            got_c[json.dumps([int(ls["priority"]), int(ls["facility"]["code"]), int(ls["severity"]["code"]), ls["hostname"],
                              ls["appname"], ls["msgid"], epoch(d["@timestamp"]), sorted((ls.get("structured_data") or {}).get(f"tunnelscope@{S.PEN}", {}).items())],
                             sort_keys=True)] += 1
        missing = sum((want_c - got_c).values())
        extra = sum((got_c - want_c).values())
        h4 = {"lines": total, "strict_parser_rejected": parse_bad[:5], "strict_parser_rejected_count": len(parse_bad),
              "filebeat_events": fb_got, "filebeat_error_message": fb_err, "filebeat_ignored": fb_ign,
              "fields_missing_or_different": missing, "fields_unexpected": extra,
              "pass": not parse_bad and fb_got == total and fb_err == 0 and missing == 0 and extra == 0 and fb_ign == 0}
    finally:
        if not a.keep:
            sh("docker", "rm", "-f", "tsc-fb", "tsc-es", check=False)
            sh("docker", "network", "rm", "tsc-net", check=False)

    summary = {
        "corpus": {"captures": len(caps), "capture_dir": base, "name_list_sha256": names_hash, "export_jobs": len(jobs), "documents": len(docs),
                   "alert_documents": len(alert_docs), "syslog_lines": len(lines), "alert_lines": len(alert_lines),
                   "capture_errors": errors},
        "versions": {"elasticsearch": es_version, "filebeat": fb_version, "ecs_reference": "v9.5.0",
                     "images": digests},
        "H1_schema": h1, "H2_elasticsearch_accepts": h2, "H3_counts_agree": h3, "H4_syslog": h4,
        "H5_no_network_no_side_effects": h5, "H6_deterministic": h6,
        "negative_controls": {"elasticsearch": control_es, "filebeat": control_fb,
                              "pass": control_es["documents_with_ignored_field"] == 1 and control_es["schema_checker_flags_it"] and
                              control_fb["events_with_error_message"] == 1 and control_fb["strict_parser_rejects_it"]},
        "all_pass": all(x["pass"] for x in (h1, h2, h3, h4, h5, h6)) and not errors and
        control_es["documents_with_ignored_field"] == 1 and control_es["schema_checker_flags_it"] and
        control_fb["events_with_error_message"] == 1 and control_fb["strict_parser_rejects_it"],
        "seconds": round(time.time() - t0),
    }
    out = os.path.join(HERE, "results", "summary.json") if not a.limit else os.path.join(tempfile.gettempdir(), "exp46-rehearsal.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as fh:
        json.dump(summary, fh, indent=1, sort_keys=True, default=str)
    print(json.dumps({k: (v["pass"] if isinstance(v, dict) and "pass" in v else v) for k, v in summary.items()
                      if k.startswith("H") or k in ("all_pass", "seconds")}, indent=1))
    print("written", out)


if __name__ == "__main__":
    main()
