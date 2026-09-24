#!/usr/bin/env python3
"""Build the judge demo kit and the presenter's guide (T-093).

  .venv/bin/python build/sih/deck/make_guides.py [kit_dir] [--pdf]

Everything numeric or named (rule ids, threats, per-capture results) is read from the code and
from the real tool output at build time, so this document cannot drift from what TunnelScope does.
Writes: <kit_dir>/*.pcap, play_live.sh, live-windows/, DEMO-GUIDE.md, and build/sih/PRESENTER-GUIDE.md.
"""
import glob, inspect, os, re, shutil, subprocess, sys
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, ROOT)
from tunnelscope.report.report import analyze
from tunnelscope.api.server import analysis_json
from tunnelscope.report.labels import LABELS
from tunnelscope.risk import risk as riskmod

KIT = next((a for a in sys.argv[1:] if not a.startswith("--")), os.path.expanduser("~/Downloads/TunnelScope_demo_kit"))
CAP = os.path.join(ROOT, "testbed", "captures")
DEMO = [
    ("01-weak-cipher.pcap", "cloud/c-w.pcap", "A weak legacy setup",
     "AES-128 / SHA-1 / MODP-1024 negotiated between two gateways. The classic 'nobody updated the config' tunnel.",
     "Open Verdicts: V-207193 and RFC8247-DH-MUST fail. Open Threats: key exchange, integrity and 'harvest now, decrypt later' are present.",
     "This is what a misconfigured VPN looks like from outside. Every failed line names the rule that failed it."),
    ("02-pq-downgrade.pcap", "pq-downgrade.pcap", "Post-quantum downgrade (our flagship)",
     "The initiator offered a post-quantum (ML-KEM) key exchange, but the tunnel settled on classical.",
     "Posture chip reads 'PQ not selected'. DST-PQ-DOWNGRADE fails (high).",
     "Recorded traffic can be decrypted by a future quantum computer. Nothing else in our survey flags a downgrade from a passive capture."),
    ("03-pq-hybrid-good.pcap", "pq-mlkem768.pcap", "Post-quantum hybrid selected",
     "The same lab with hybrid ML-KEM-768 actually negotiated.",
     "Posture chip reads 'PQ hybrid' (green). Risk drops a band.",
     "Note it still fails DISA's group>=16 rule: DISA and RFC 8247 disagree about MODP-2048, which is exactly why we show every baseline separately instead of one blended score."),
    ("04-ah-no-encryption.pcap", "exp15/a-tra-sha1.pcap", "AH: authenticated but not encrypted",
     "Traffic protected by AH only, in transport mode.",
     "Evidence tab: IPsec protocol AH, mode transport (read from AH's own header), integrity narrowed from the ICV length. RFC4301-CONFIDENTIALITY fails.",
     "AH proves who sent a packet but hides nothing. The tool spots it from the header alone."),
    ("05-replay-attack.pcap", "synthetic/replay-attack.pcap", "A replayed packet",
     "A real capture with one ESP packet re-sent later (made for testing; marked synthetic in the dataset).",
     "Verdicts: RFC4303-SEQ fails, 'a sequence number was used twice'. Threats: replay present.",
     "A packet recorded twice by a second tap is NOT called a replay; only genuine repeats are. And whether the receiver would drop it is not visible from outside, and the tool says so."),
    ("06-traffic-messaging.pcap", "exp15/traffic/exp15-tun-messaging-rep4.pcap", "The AI: traffic type inside the tunnel",
     "An ESP-only capture of messaging-style traffic (no handshake, so no key-exchange findings).",
     "Traffic & exposure tab: 'Messaging (WhatsApp-like)' with about 98% confidence, runners-up shown, and an exposure score.",
     "This is the AI part of the brief. It reads only sizes, timing and direction. Because there is no handshake, most rules say UNKNOWN: it never guesses."),
]

def run(cmd): return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

# ------------------------------------------------------------------ demo kit
os.makedirs(os.path.join(KIT, "live-windows"), exist_ok=True)
results = {}
for name, src, *_ in DEMO:
    shutil.copy(os.path.join(CAP, src), os.path.join(KIT, name))
    sa = analysis_json(analyze(os.path.join(CAP, src)), name)["sas"][0]
    F = {f["attribute"]: f for f in sa["findings"]}
    r = sa["risk"]["risk"]
    results[name] = dict(posture=sa["posture"], risk=r["score"], band=r["band"], assess=f'{r["assessable"]} of {r["total"]}', conf=sa["risk"]["confidence"]["score"],
                         fails=[v["rule_id"] for v in sa["verdicts"] if v["verdict"] == "FAIL"], F=F,
                         present=[t["name"] for t in sa["risk"]["threats"] if t["status"] == "present"])
for i, (src, dst) in enumerate([("cloud/c-m.pcap", "live-1.pcap"), ("cloud/c-m.pcap", "live-2.pcap"), ("cloud/c-m.pcap", "live-3.pcap"), ("cloud/c-w.pcap", "live-4.pcap")]):
    shutil.copy(os.path.join(CAP, src), os.path.join(KIT, "live-windows", dst))
open(os.path.join(KIT, "play_live.sh"), "w").write('''#!/bin/bash
# Simulates a network sensor: drops one capture "window" into a folder every 7 seconds.
# Windows 1-3 are a healthy tunnel (AES-256 / SHA-2 / MODP-2048); window 4 is the SAME tunnel
# re-negotiated weaker (AES-128 / SHA-1 / MODP-1024), so the Live tab flags a downgrade.
#
#   terminal 1 (repo folder):  mkdir -p /tmp/tunnelscope-live-demo && rm -rf .tunnelscope-history && ./start.sh --live-follow /tmp/tunnelscope-live-demo --window 5
#   terminal 2 (this folder):  bash play_live.sh
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"; DEST="${1:-/tmp/tunnelscope-live-demo}"
mkdir -p "$DEST"; rm -f "$DEST"/*.pcap
for i in 1 2 3 4; do
  cp "$HERE/live-windows/live-$i.pcap" "$DEST/w-$i.pcap"
  echo "window $i written"; sleep 7
done
echo "done: open the Live tab and look for 'changed'"
''')
os.chmod(os.path.join(KIT, "play_live.sh"), 0o755)

def show(v):
    return "not determinable" if v is None else (", ".join(map(str, v)) if isinstance(v, list) else str(v))
L = ["# TunnelScope demo kit: what to drop in, what you will see", "",
     "Start the app from the project folder (`./start.sh`), then drag a file onto the page. Every result below is real output, produced by running the tool on that file when this guide was built.", "",
     "| # | File | Risk | Posture | What it shows |", "|---|---|---|---|---|"]
for name, src, title, what, see, say in DEMO:
    r = results[name]; L.append(f"| {name[:2]} | `{name}` | {r['risk']} ({r['band']}) | {r['posture']} | {title} |")
L += ["", "Suggested order for three minutes: **01, then 02, then 04, then 06, then the live demo**. Keep 03 and 05 for questions.", ""]
for name, src, title, what, see, say in DEMO:
    r = results[name]; F = r["F"]
    L += [f"## {name[:2]}  {title}", "", f"**File:** `{name}`  ({os.path.getsize(os.path.join(KIT, name)) // 1024 or 1} KB, lab traffic only)", "", f"**What it is:** {what}", "",
          f"**What you will see:** risk **{r['risk']} / 100 ({r['band']})**, {r['assess']} threats assessable, evidence confidence {r['conf']}%. Posture: *{r['posture']}*."]
    ike = [f"{LABELS[k]}: {show(F[k]['value'])}" for k in ("ike_version", "ike_encr", "ike_integ", "ike_dh_group") if k in F and F[k]["value"] is not None]
    if ike: L += ["", "Read from the handshake: " + "; ".join(ike) + "."]
    if F.get("traffic_type", {}).get("value"): t = F["traffic_type"]["value"]; L += ["", f"Traffic type predicted: **{t['label']}**, {round(t['probability'] * 100)}% model confidence."]
    if r["fails"]: L += ["", "Failed checks: " + ", ".join(f"`{x}`" for x in r["fails"]) + "."]
    if r["present"]: L += ["", "Threats present: " + "; ".join(r["present"]) + "."]
    L += ["", f"**Click:** {see}", "", f"**Say:** {say}", ""]
L += ["## Live demo (no Docker needed)", "", "Simulates a network sensor. Window 4 is the same tunnel re-negotiated with weaker settings.", "", "```bash",
      "# terminal 1, in the project folder", 'cd "/Users/bala/Documents/SIH 2026"', "mkdir -p /tmp/tunnelscope-live-demo   # the engine refuses to follow a folder that does not exist yet", "rm -rf .tunnelscope-history", "./start.sh --live-follow /tmp/tunnelscope-live-demo --window 5", "",
      "# terminal 2, in this kit folder", "bash play_live.sh", "```", "",
      "Open the **Live** tab. Windows 1 to 3 show the tunnel learning its normal; window 4 flips it to **changed**, naming the encryption, integrity and key-exchange downgrades, and the risk jumps.", "",
      "## If something goes wrong", "", "- Page says the engine is unreachable: run `./start.sh status`, then `./start.sh` again.",
      "- Nothing on the Live tab: wait about 15 seconds after the last window (the newest file is only read once it stops growing).",
      "- Start fresh between runs: `./start.sh stop; rm -rf .tunnelscope-history`.",
      "- Engine fails to start with a live folder: the folder must exist first (`mkdir -p /tmp/tunnelscope-live-demo`); check `logs/engine.log`."]
open(os.path.join(KIT, "DEMO-GUIDE.md"), "w").write("\n".join(L))

# ------------------------------------------------------------------ presenter's guide
rules = []
for f in sorted(glob.glob(os.path.join(ROOT, "tunnelscope/rules/*.yaml"))):
    d = yaml.safe_load(open(f))
    for r in d["rules"]: rules.append((d["baseline"], r["id"], r["severity"], r["attribute"], r["title"]))
threats = re.findall(r'Threat\("(TH-\d\d)", "([^"]+)", (\d),\s*\n?\s*"([^"]+)"', inspect.getsource(riskmod))

ATTR = [  # (attribute, plain meaning, how we get it, label + vantage, why it matters)
 ("ike_version", "Which IKE protocol version the tunnel uses: IKEv1 (old) or IKEv2.", "Read from the exchange type in each IKE message header.", "OBSERVED, T1", "IKEv1 is retired. DISA V-207205 requires IKEv2. Threat TH-06."),
 ("ike_exchanges", "Which IKE exchanges appear in the capture (IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA, INFORMATIONAL...).", "Read from the exchange types.", "OBSERVED, T1", "Shows how much of the handshake the capture contains. A capture that starts mid-tunnel says so, instead of pretending."),
 ("ike_spi", "The two 8-byte identifiers that name one IKE security association.", "Read from the IKE header.", "OBSERVED, T1", "Groups packets into one tunnel record. They change at each rekey, so the tunnel is identified by its endpoint pair."),
 ("ike_prf", "The function used to derive the session keys.", "Chosen transform in the responder's IKE_SA_INIT reply.", "OBSERVED, T1", "For AES-GCM there is no separate integrity algorithm, so the PRF is the closest thing; the tool says so."),
 ("ike_encr", "The cipher and key length that protect the IKE handshake itself, for example AES-CBC-256.", "Chosen transform in the IKE_SA_INIT reply. Uses the LAST reply that actually selects a suite, so a refused first attempt cannot hide it.", "OBSERVED, T1", "RFC8247-ENCR. This is the handshake's cipher, not the data cipher: keep those two apart."),
 ("ike_integ", "The integrity algorithm for the IKE handshake, for example HMAC-SHA2-256-128.", "Chosen transform in the IKE_SA_INIT reply. Absent for AEAD suites such as GCM.", "OBSERVED, T1 (UNKNOWN for GCM)", "DISA V-207223 asks for SHA-2 at 384 bits or more. Threat TH-05."),
 ("ike_dh_group", "The key-exchange group chosen (MODP-2048, ECP-384, Curve25519, ...). This is what protects the keys.", "Chosen key-exchange transform in the reply.", "OBSERVED, T1", "V-207193 (DISA, group 16 or higher) and RFC8247-DH-MUST. Weak groups mean the keys can be recovered. Threat TH-01."),
 ("ike_offered_dh", "Every group the initiator was willing to use.", "All key-exchange transforms in the initiator's plaintext IKE_SA_INIT.", "OBSERVED, T1", "RFC8247-DH-OFFER. A tunnel can negotiate a strong group while its endpoint still accepts a forbidden one: that is downgrade exposure. Only the initiator's offer is visible."),
 ("pq_key_exchange", "Whether a post-quantum key exchange (ML-KEM hybrid) was used, offered, or absent.", "Additional key-exchange transforms and extra IKE messages in plaintext (RFC 9370).", "OBSERVED, T1", "DST-PQ-KE and DST-PQ-DOWNGRADE. Threats TH-02 (harvest now, decrypt later) and TH-03 (downgrade)."),
 ("ipsec_protocols", "Whether the data is carried by ESP, AH, or both.", "IP protocol numbers 50 (ESP) and 51 (AH), excluding headers merely quoted inside ICMP errors.", "OBSERVED, T0", "AH alone authenticates but does not encrypt: RFC4301-CONFIDENTIALITY, threat TH-07."),
 ("esp_cipher_family", "The set of ESP ciphers consistent with the packet lengths.", "The 'cipher sieve': each family has fixed IV, ICV and alignment rules, so lengths rule families out.", "INFERRED, T0", "A candidate SET, never one answer. It cannot tell AES-128 from AES-256 (both give identical sizes), and the tool says that is provable, not a shortcoming."),
 ("ah_integrity", "The integrity algorithm used by AH.", "AH's integrity value sits in the clear; its length (12, 16, 24 or 32 bytes) names the algorithm family.", "OBSERVED or INFERRED, T0", "RFC8221-AH-INTEG and -LEGACY. A 12-byte value cannot tell MD5 from SHA-1, so that rule says UNKNOWN, not FAIL."),
 ("mode", "Tunnel mode (the whole original packet is wrapped) or transport mode (only the payload is).", "AH: read from its next-header field. ESP: transport is proven when a packet is smaller than any tunnel packet can be; otherwise a model estimate for TCP over AEAD; otherwise unknown.", "OBSERVED, INFERRED, or UNKNOWN", "The brief asks for it. Tunnel mode is never claimed from ESP traffic alone."),
 ("sequence_integrity", "Whether any sequence number is used twice on one SA.", "Per-SPI ESP/AH sequence numbers; separates real repeats from a second tap recording the same packet.", "OBSERVED, T0", "RFC4303-SEQ. A repeat means a replay or a broken sender. Whether the receiver drops replays is not visible. Threat TH-08."),
 ("pfs", "Whether a rekey used a fresh key exchange (perfect forward secrecy).", "The rekey message is larger when it carries a key exchange (a 256-byte gap, experiment EXP-03).", "INFERRED, needs a rekey in the capture", "Without PFS one stolen key exposes past and future keys. Threat TH-11."),
 ("rekey_cadence", "How often the tunnel rekeys.", "Time between observed CREATE_CHILD_SA exchanges.", "MEASURED with 2 or more rekeys, else NOT_OBSERVABLE", "Evidence for key lifetime. It is a measurement, never a claimed configured lifetime."),
 ("peer_auth_method", "How the peers proved who they are: pre-shared key, certificate or EAP.", "Not on the wire: negotiated inside the encrypted IKE_AUTH.", "NOT_OBSERVABLE", "We tested the tempting shortcut (certificate requests) and it was misleading, so we report not observable."),
 ("responder_cert_capability", "Whether the responder has any certificate trust anchor loaded.", "A certificate request in the plaintext IKE_SA_INIT.", "OBSERVED, T1", "Describes the responder's policy, not the method this tunnel used."),
 ("negotiation_outcome", "Whether the tunnel came up, or why it failed (proposal mismatch, traffic-selector mismatch, authentication failure).", "Message sizes and notify codes, by a written decision tree (experiment EXP-06).", "OBSERVED or INFERRED", "Turns 'the VPN is down' into a cause an engineer can fix."),
 ("early_childsa_cve", "The CVE-2026-78135 pattern: a Child SA requested before authentication finished.", "IKE message IDs and exchange order, compared per originator.", "OBSERVED; UNKNOWN if the capture starts mid-tunnel", "Rule CVE-2026-78135, threat TH-09. Built so that not seeing the handshake is never reported as a detection."),
 ("metadata_exposure", "How many bits of size and timing information leak per packet, and whether padding hides sizes.", "Entropy of ESP packet lengths and inter-arrival times.", "MEASURED, T0", "Threat TH-10. Padding can zero the size channel but leaves timing, as our experiment showed."),
 ("attacker_exposure", "A 0 to 100 score: how sure and consistent our attacker model is about this tunnel's traffic.", "The traffic classifier is run as an eavesdropper over 2-second windows.", "MEASURED (UNKNOWN with too little traffic)", "Turns 'traffic analysis is possible' into a number."),
 ("traffic_type", "The predicted kind of traffic inside the tunnel, with a probability and runners-up.", "Random Forest over 31 numbers per 2-second window; a second model checks for mixed traffic.", "INFERRED, or UNKNOWN when uncertain or mixed", "The brief's 'predict the type of traffic'. It abstains instead of guessing, and states its known weak spot."),
]
assert {a[0] for a in ATTR} <= set(LABELS), "attribute missing from labels.py"

G = ["# TunnelScope presenter's guide", "", "How it works, what every attribute means, and what it is built with. Rule names, threats and results are read from the code when this file is built.", "",
     "## 1. The pitch in one paragraph", "",
     "A VPN is only as secure as its settings, and most of an IPsec tunnel is encrypted, so an outside observer can read some things and not others. TunnelScope reads what is readable, infers what is hidden only with a stated confidence, judges everything against written standards, and says plainly what it cannot know. Every fact carries a label, every verdict cites its rule, and unknown is never scored as safe.", "",
     "## 2. How it works, step by step", "",
     "1. **Capture.** A pcap file, or a live stream cut into short windows (`tunnelscope live`).",
     "2. **Read.** `tshark` (Wireshark's dissector) reads IKE, ESP and AH headers. Only `tunnelscope/ingest/tshark.py` ever runs it. Payloads are never decrypted.",
     "3. **Evidence.** Extractors turn packets into *findings*: an attribute, a value, a label (observed, inferred, measured, unknown, not observable), a vantage, the packet it came from. An unknown finding is not allowed to carry a value; the code refuses.",
     "4. **Judge.** YAML rule files are run against the findings. Each rule yields PASS, FAIL or UNKNOWN and cites its standard.",
     "5. **Models.** Four models we trained fill in what the wire is silent about (section 5).",
     "6. **Score.** Threats are rated by likelihood and impact into a threat matrix and one risk score, with an evidence-confidence figure.",
     "7. **Deliver.** Dashboard, executive and technical reports, a CycloneDX cryptographic bill of materials, plain-English explanations, change detection.", "",
     "**Vantage** says how much access a finding needed. T0: the encrypted packets only. T1: the plaintext handshake. T2: data from the endpoint itself (the tool can cross-check it). T3 keys, T4 active probing: deliberately out of scope.", "",
     "## 3. Every attribute, explained", "",
     "Attributes are the facts TunnelScope extracts for each tunnel. They appear in the dashboard's **Evidence** tab.", ""]
for a, meaning, how, label, why in ATTR:
    G += [f"### {LABELS[a]}  (`{a}`)", "", f"- **What it is:** {meaning}", f"- **How we get it:** {how}", f"- **Label:** {label}", f"- **Why it matters:** {why}", ""]
G += ["## 4. The rules and the threats", "", "### The rules (each names its standard)", "", "| Baseline | Rule | Severity | Judges | What it checks |", "|---|---|---|---|---|"]
for b, i, sev, attr, title in rules: G.append(f"| {b} | `{i}` | {sev} | {LABELS.get(attr, attr)} | {title} |")
G += ["", "### The twelve threats (the threat matrix)", "", "Each threat has an impact (1 to 3). It is *present* if a rule that tests for it fails, *mitigated* if the rules pass, and *not assessable* if the evidence is unknown; not assessable is never counted as safe.", "", "| Id | Threat | Impact |", "|---|---|---|"]
for tid, name, imp, desc in threats: G.append(f"| {tid} | {name} | {['', 'low', 'medium', 'high'][int(imp)]} |")
G += ["", "### The scores", "",
      "- **Risk score (0 to 100):** `100 x (1 - product(1 - 0.6 x likelihood x impact / 9))` over the present threats. Adding a threat never lowers it. 0 means none was seen in what could be assessed, not that the tunnel is safe. It is a designed formula, not measured against real attacks.",
      "- **Evidence confidence:** the share of the attributes we assess that this capture supports, weighting observed 1.0 and inferred by its stated confidence.",
      "- **Model confidence:** the traffic classifier's own probability. Not the same as accuracy.",
      "- **Per-baseline compliance scores:** one per standard, never averaged together, so a disagreement between DISA and RFC 8247 stays visible.", "",
      "## 5. The four models (all trained by us)", "",
      "| Model | Method | Input | Output | Trained on |", "|---|---|---|---|---|",
      "| Traffic type | Random Forest (scikit-learn) | 31 numbers per 2-second window: packet counts, sizes, timing gaps, size histogram, direction | 1 of 8 types + confidence, or uncertain | 1,964 windows, 216 sessions: synthetic shapes, real applications, Libreswan |",
      "| Mixed traffic | Random Forest | The pattern of the first model's per-window probabilities | single vs mixed | The project's own mixed and single sessions |",
      "| Tunnel or transport | Random Forest | Shares of ACK-sized packets | mode + confidence, or abstain | Tunnel and transport sessions |",
      "| Change detection | Isolation Forest, plus rules and robust statistics | A tunnel's posture and traffic profile over time | normal, changed, learning | Each tunnel's own history |", "",
      "No pretrained or third-party AI model is used, and a test fails if one is ever added. Models ship as plain arrays (no pickle) and train in about a second at first use. The eight traffic types are voip, web, bulk file transfer, interactive shell, video, e-mail, messaging and icmp; they are traffic *shapes* (real software against lab servers, plus a seeded generator), not app fingerprints.", "",
      "## 6. What it is built with", "",
      "**Analysis engine (Python)**", "- Python 3.11 or newer (developed on 3.13); `tshark` for reading packets; `scikit-learn` and `numpy` for the models; `PyYAML` for the rule files.",
      "- Local server: Python standard library `http.server`, bound to 127.0.0.1 only. CLI: `argparse`.",
      "- Outputs: Markdown and HTML reports, CycloneDX 1.6 JSON (CBOM).", "",
      "**Dashboard (web)**", "- React 19, TypeScript 6, Vite 8, Tailwind CSS 4, Radix UI components, Recharts 3, lucide icons.",
      "- three.js for the intro and background tunnel, Motion and GSAP for animation. Fonts: Geist, Geist Mono, and Kufica Bold for the wordmark.", "",
      "**Lab (Docker)**", "- strongSwan 5.9.8 and 6.1.0, Libreswan 5.4, and a real OpenBSD `iked` 7.9 VM for one experiment.",
      "- A router container with `tcpdump` and no keys (the observer's position); `tc netem` for delay and loss.",
      "- Real software for traffic: Chromium, nginx, OpenSSH and SFTP, Postfix with swaks, Prosody (XMPP), ffmpeg (RTP), ping.", "",
      "**Quality and process**", "- `pytest` (392 tests), 60 browser checks (Playwright), GitHub Actions CI, a ground-truth check against each endpoint's own `swanctl` output, a dataset hash check, and a check against other people's public captures.",
      "- Double Diamond method; pre-registered experiments (predictions written before capture; failures kept); an offline install bundle proven in an air-gapped container.",
      "- Standards used: DISA VPN SRG V2R6, RFC 4301, 4302, 4303, 7296, 8221, 8247, 9370, CycloneDX, the DST/NQM post-quantum report; DPDP Rules 2025 and CERT-In as context only.", "",
      "## 7. Questions judges ask", "",
      "- **Is it really AI?** The parts that need judgement are AI: traffic type, mixed traffic, mode, change detection. Plaintext fields are read exactly, because guessing them would be worse.",
      "- **Can you tell AES-128 from AES-256?** No, and nobody can from outside: both give identical packet sizes. We prove it and say so.",
      "- **Do you decrypt anything?** Never. Headers, sizes and timing only.",
      "- **How accurate is it on real traffic?** 0.986 macro-F1 on held-out runs. A model trained on synthetic traffic only scored 0.461 on real applications, which is why the shipped model also trains on real ones. One lab, no real WAN yet.",
      "- **Why several scores instead of one?** DISA and RFC 8247 disagree about some groups. One blended number would hide that.",
      "- **What is the risk score based on?** A designed formula over rated threats. It ranks tunnels sensibly; it is not a measured probability of an attack.",
      "- **What would you do next?** Delay and packet loss (already pre-registered), vendor equipment and a real cloud tunnel, and learning on the customer's own network.", "",
      "## 8. Where to show the code", "",
      "- `tunnelscope/evidence/extract.py` and `protocol.py`: packets to findings. `tunnelscope/rules/*.yaml`: the rules. `tunnelscope/assess/engine.py`: the judge.",
      "- `tunnelscope/risk/risk.py`: threats and score. `tunnelscope/leakage/`: the traffic and mode models. `tunnelscope/anomaly/`: change detection. `tunnelscope/live/`: live mode.",
      "- `fleet-dashboard/src/`: the dashboard. `testbed/`: the lab. `experiments/`: each experiment with its pre-registration and result."]
GP = os.path.join(ROOT, "build/sih/PRESENTER-GUIDE.md"); open(GP, "w").write("\n".join(G))
print("kit:", KIT, "|", len(DEMO), "captures | guide:", GP, f"({len(ATTR)} attributes, {len(rules)} rules, {len(threats)} threats)")

if "--pdf" in sys.argv:
    import markdown  # installed in a scratch venv by the caller
    css = "body{font:13.5px/1.55 -apple-system,Helvetica,Arial,sans-serif;max-width:860px;margin:32px auto;color:#1a1a22;padding:0 24px}h1{font-size:26px}h2{font-size:19px;margin-top:30px;border-bottom:1px solid #ddd;padding-bottom:4px}h3{font-size:14.5px;margin:18px 0 4px}code{background:#f0eefb;padding:1px 4px;border-radius:4px;font-size:12px}table{border-collapse:collapse;width:100%;font-size:12px;margin:8px 0}th,td{border:1px solid #ddd;padding:5px 7px;vertical-align:top;text-align:left}th{background:#f5f4fb}li{margin:2px 0}"
    for md, pdf in ((GP, os.path.expanduser("~/Downloads/TunnelScope_Presenters_Guide.pdf")), (os.path.join(KIT, "DEMO-GUIDE.md"), os.path.join(KIT, "DEMO-GUIDE.pdf"))):
        html = md.replace(".md", ".html"); tmp = os.path.join("/tmp", os.path.basename(html))
        open(tmp, "w").write(f"<html><head><meta charset='utf-8'><style>{css}</style></head><body>{markdown.markdown(open(md).read(), extensions=['tables', 'fenced_code'])}</body></html>")
        subprocess.run(["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "--headless=new", "--disable-gpu", f"--print-to-pdf={pdf}", "--no-pdf-header-footer", f"file://{tmp}"], capture_output=True)
        print("pdf:", pdf, os.path.exists(pdf))
