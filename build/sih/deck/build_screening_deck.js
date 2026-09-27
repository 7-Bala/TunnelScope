// TunnelScope idea-submission deck for the SIH screening round: the official 6-slide idea template
// (Title, Idea, Technical approach, Feasibility & viability, Impact & benefits, Research & references).
//   node build/sih/deck/build_screening_deck.js [out.pptx]
// Layout follows the SIH idea template (team badge top-left, SIH logo top-right, blue footer bar);
// structure and copy follow the teardown of past winning decks. Every number on a slide has a source,
// listed in SOURCES below. Fill TEAM_ID / VIDEO_URL / REPO_URL before exporting to PDF: while empty they
// render as a yellow "fill before export" marker so they cannot be missed.
const pptxgen = require("pptxgenjs");
const sharp = require("sharp");
const React = require("react");
const ReactDOMServer = require("react-dom/server");
const fi = require("react-icons/fi");
const path = require("path");
const HERE = __dirname;
const OUT = process.argv[2] || path.join(process.env.HOME, "Downloads", "TunnelScope_SIH26160_Idea_Submission.pptx");

const TEAM_NAME = "Think2Thrive";
const TEAM_ID = "";   // from the SIH portal
const VIDEO_URL = ""; // demo video, on a host that does not sleep
const REPO_URL = "";  // only if the repository is public or shared with the evaluators

// SOURCES (checked 2026-09-27)
//   516 unit tests pass ........ `.venv/bin/python -m pytest -q` -> "516 passed, 1 skipped"
//   ~1.6 s per capture ......... `tunnelscope report` on 4 lab captures: 1.58-1.67 s wall time each
//   124 lab captures ........... testbed/captures/**/*.groundtruth.json (endpoint ground truth)
//   0.174 -> 0.757, 99.8% ...... experiments/exp20-real-ipsec-and-users/RESULT.md (R3), DEC-037
//   20 experiments ............. experiments/*/RESULT.md
//   4 implementations .......... strongSwan, Libreswan (EXP-07), OpenBSD iked (EXP-10), MikroTik RouterOS (EXP-26)
//   pq-downgrade verdicts ...... `tunnelscope report testbed/captures/pq-downgrade.pcap`
//   screenshot ................. img/threats.jpg (dashboard, lab capture a-tra-sha1.pcap), cropped to img/tunnel-view.jpg

const C = { INK: "16213A", INK2: "3F4A60", MUTED: "6B7488", LINE: "D9DEE7", TINT: "F2F4F8", NAVY: "1F3864",
  VIOLET: "6D28D9", VTINT: "EFEAFD", BAR: "0070C0", WHITE: "FFFFFF", DARK: "121218",
  OBS: "1E7B4A", INF: "5B3FD6", MEAS: "0F766E", UNK: "B7791F", NOBS: "6B7280", NEG: "C0392B", HL: "FFF200" };
const F = "Arial";
const W = 13.333, H = 7.5;

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";
pres.title = "TunnelScope: SIH26160 idea submission";
pres.author = "Team " + TEAM_NAME;

function t(s, str, o) {
  s.addText(str, Object.assign({ fontFace: F, fontSize: 13, color: C.INK, isTextBox: true, margin: 0, valign: "top" }, o));
}
function box(s, x, y, w, h, o = {}) {
  s.addShape(o.round === false ? pres.shapes.RECTANGLE : pres.shapes.ROUNDED_RECTANGLE, Object.assign({ x, y, w, h,
    fill: { color: o.fill ?? C.WHITE }, line: { color: o.line ?? C.LINE, width: o.lw ?? 1 } }, o.round === false ? {} : { rectRadius: o.r ?? 0.08 }));
}
async function icon(Comp, color, px = 256) {
  const svg = ReactDOMServer.renderToStaticMarkup(React.createElement(Comp, { color: "#" + color, size: String(px) }));
  const png = await sharp(Buffer.from(svg)).png().toBuffer();
  return "image/png;base64," + png.toString("base64");
}
function iconDot(s, data, x, y, d, fill) {
  s.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color: fill }, line: { color: fill, width: 0.5 } });
  const p = d * 0.56;
  s.addImage({ data, x: x + (d - p) / 2, y: y + (d - p) / 2, w: p, h: p });
}
function numDot(s, n, x, y, d = 0.3, fill = C.VIOLET) {
  s.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color: fill }, line: { color: C.WHITE, width: 1.25 } });
  t(s, String(n), { x, y, w: d, h: d, fontSize: 11, bold: true, color: C.WHITE, align: "center", valign: "middle" });
}
// value, or a yellow marker while it is still empty
function fill(v, what) { return v ? { text: v } : { text: "FILL BEFORE EXPORT: " + what, options: { highlight: C.HL, bold: true, color: C.INK } }; }

// template chrome: team badge, centred title, SIH logo, blue footer bar with the page number
function chrome(s, num, title) {
  s.background = { color: C.WHITE };
  s.addShape(pres.shapes.OVAL, { x: 0.3, y: 0.22, w: 1.75, h: 0.62, fill: { color: C.WHITE }, line: { color: "7F5FA8", width: 1.5 } });
  t(s, TEAM_NAME, { x: 0.3, y: 0.22, w: 1.75, h: 0.62, fontSize: 12, align: "center", valign: "middle", color: C.INK });
  t(s, title, { x: 2.25, y: 0.26, w: 8.6, h: 0.6, fontSize: 28, bold: true, align: "center", valign: "middle", color: C.INK });
  logo(s, 11.1, 0.14, 0.72);
  s.addShape(pres.shapes.RECTANGLE, { x: 0, y: 7.12, w: W, h: 0.38, fill: { color: C.BAR }, line: { color: C.BAR, width: 0 } });
  t(s, "@SIH Idea submission- Template", { x: 3.67, y: 7.12, w: 6, h: 0.38, fontSize: 10, color: C.WHITE, align: "center", valign: "middle" });
  t(s, String(num), { x: 12.3, y: 7.12, w: 0.6, h: 0.38, fontSize: 10, bold: true, color: C.WHITE, align: "right", valign: "middle" });
}
function logo(s, x, y, h) {
  s.addImage({ path: path.join(HERE, "img", "sih-bulb.png"), x, y, w: h * 521 / 600, h });
  t(s, "SMART INDIA\nHACKATHON\n2026", { x: x + h * 0.9, y: y + 0.02, w: 1.3, h, fontSize: 10.5, bold: true, color: "4F5F6A", valign: "middle", lineSpacingMultiple: 0.95 });
}
function sectionHead(s, str, x, y, w, color = C.VIOLET) {
  t(s, str, { x, y, w, h: 0.3, fontSize: 14.5, bold: true, color });
}

(async () => {
  const I = {
    search: await icon(fi.FiSearch, C.WHITE), tool: await icon(fi.FiTool, C.WHITE), clip: await icon(fi.FiClipboard, C.WHITE),
    lock: await icon(fi.FiLock, C.WHITE), book: await icon(fi.FiBookOpen, C.WHITE), db: await icon(fi.FiDatabase, C.WHITE),
    flag: await icon(fi.FiFlag, C.WHITE), shield: await icon(fi.FiShield, C.WHITE), rupee: await icon(fi.FiLayers, C.WHITE),
    globe: await icon(fi.FiWifiOff, C.WHITE),
  };

  // ============ 1  Title page
  { const s = pres.addSlide(); s.background = { color: C.WHITE };
    t(s, "SMART INDIA HACKATHON 2026", { x: 0.5, y: 0.3, w: 10.3, h: 0.7, fontSize: 34, bold: true, color: C.NAVY, align: "center", valign: "middle" });
    logo(s, 11.1, 0.2, 0.75);
    t(s, "TITLE PAGE", { x: 0.5, y: 1.1, w: 7.6, h: 0.5, fontSize: 22, bold: true, align: "center" });
    // template art: soft hexagons behind the SIH bulb
    s.addShape(pres.shapes.HEXAGON, { x: 8.05, y: 1.35, w: 4.9, h: 4.9, fill: { color: "E9EBEF" }, line: { color: "E9EBEF", width: 0 }, rotate: 90 });
    s.addShape(pres.shapes.HEXAGON, { x: 7.55, y: 1.05, w: 1.6, h: 1.6, fill: { color: C.WHITE, transparency: 100 }, line: { color: "DADDE3", width: 3 }, rotate: 90 });
    s.addShape(pres.shapes.HEXAGON, { x: 7.35, y: 4.45, w: 1.2, h: 1.2, fill: { color: "EEF0F3" }, line: { color: "EEF0F3", width: 0 }, rotate: 90 });
    s.addImage({ path: path.join(HERE, "img", "sih-bulb.png"), x: 8.85, y: 1.95, w: 3.3 * 521 / 600, h: 3.3 });
    const rows = [
      ["Problem Statement ID", [{ text: "SIH26160" }]],
      ["Problem Statement Title", [{ text: "AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework" }]],
      ["Theme", [{ text: "Blockchain & Cybersecurity" }]],
      ["PS Category", [{ text: "Software" }]],
      ["Team ID", [fill(TEAM_ID, "Team ID")]],
      ["Team Name (Registered on portal)", [{ text: TEAM_NAME }]],
    ];
    const para = [];
    rows.forEach(([k, v], i) => {
      para.push({ text: k + " – ", options: { bold: true, bullet: true, breakLine: false } });
      v.forEach((r, j) => para.push({ text: r.text, options: Object.assign({}, r.options || {}, j === v.length - 1 && i < rows.length - 1 ? { breakLine: true } : {}) }));
    });
    t(s, para, { x: 0.7, y: 1.95, w: 6.9, h: 4.6, fontSize: 18, color: C.INK, paraSpaceAfter: 16, valign: "top" });
    t(s, "Idea: TunnelScope – IPsec and post-quantum posture, from the wire", { x: 0.7, y: 6.55, w: 7.2, h: 0.4, fontSize: 14, italic: true, color: C.MUTED });
  }

  // ============ 2  Idea title
  { const s = pres.addSlide(); chrome(s, 2, "IDEA TITLE");
    const X = 0.5, CWL = 7.25;
    t(s, [{ text: "TunnelScope", options: { bold: true, color: C.VIOLET } }, { text: ": know what an IPsec VPN really negotiated, how secure it is, and what cannot be known from outside", options: { bold: true } }],
      { x: X, y: 1.08, w: CWL, h: 0.62, fontSize: 15.5 });

    sectionHead(s, "Proposed solution", X, 1.8, CWL);
    t(s, [
      { text: "A passive analyser: give it a ", options: { bullet: true } }, { text: "packet capture or a live span-port feed", options: { bold: true } },
      { text: " of an IPsec VPN; it reports the tunnel's settings, judges them against ", options: {} }, { text: "written security standards", options: { bold: true } },
      { text: ", and scores the risk.", options: { breakLine: true } },
      { text: "Reads only headers with tshark: ", options: { bullet: true } }, { text: "nothing is decrypted", options: { bold: true } },
      { text: ". Runs on one laptop, offline by default.", options: {} },
    ], { x: X, y: 2.08, w: CWL, h: 0.95, fontSize: 12, paraSpaceAfter: 3 });

    sectionHead(s, "How it addresses the problem statement", X, 3.12, CWL);
    const ps = [
      ["a", "Testbed", "Docker lab: strongSwan, Libreswan, OpenBSD iked; AES-CBC/GCM, PFS on/off, tunnel/transport, IPv4/IPv6"],
      ["b", "Capture", "pcap files and live span-port windows; IKE, ESP and AH"],
      ["c", "AI identification", "protocol, IKE version, ciphers, key exchange, mode, traffic type, each with a confidence"],
      ["d", "Assessment", "5 written baselines, a 12-threat matrix, post-quantum readiness"],
      ["e", "Outputs", "risk score, evidence confidence, executive + technical reports, CBOM, dashboard"],
    ];
    ps.forEach(([l, k, v], i) => { const y = 3.44 + i * 0.365;
      s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: X, y: y + 0.02, w: 0.3, h: 0.27, rectRadius: 0.06, fill: { color: C.VTINT }, line: { color: C.VTINT, width: 0 } });
      t(s, l, { x: X, y: y + 0.02, w: 0.3, h: 0.27, fontSize: 11.5, bold: true, color: C.VIOLET, align: "center", valign: "middle" });
      t(s, [{ text: k + ": ", options: { bold: true } }, { text: v }], { x: X + 0.42, y, w: CWL - 0.42, h: 0.34, fontSize: 12, valign: "middle" });
    });

    sectionHead(s, "Innovation and uniqueness", X, 5.34, CWL);
    t(s, [
      { text: "Evidence tiers. ", options: { bold: true, bullet: true } }, { text: "Every finding is OBSERVED, INFERRED, MEASURED, UNKNOWN or NOT OBSERVABLE; an unknown is never scored as a pass.", options: { breakLine: true } },
      { text: "Post-quantum downgrade detection ", options: { bold: true, bullet: true } }, { text: "from plaintext IKE: post-quantum, classical, or \"PQ offered, classical used\".", options: { breakLine: true } },
      { text: "One tunnel, many standards. ", options: { bold: true, bullet: true } }, { text: "Each verdict names its rule; the same tunnel can pass RFC 8247 and fail DISA." },
    ], { x: X, y: 5.64, w: CWL, h: 1.42, fontSize: 12, paraSpaceAfter: 4 });

    // proof it runs: a real dashboard view with numbered callouts
    const ix = 8.05, iy = 1.08, iw = 4.85, ih = iw * 1341 / 1400;
    s.addImage({ path: path.join(HERE, "img", "tunnel-view.jpg"), x: ix, y: iy, w: iw, h: ih });
    s.addShape(pres.shapes.RECTANGLE, { x: ix, y: iy, w: iw, h: ih, fill: { color: C.WHITE, transparency: 100 }, line: { color: C.LINE, width: 1 } });
    // dots sit on the image edge or in empty dark space, never over the value they point at
    [[1, -0.03, 0.225], [2, 0.97, 0.07], [3, -0.03, 0.42], [4, 0.47, 0.19], [5, 0.97, 0.665]].forEach(([n, fx, fy]) => numDot(s, n, ix + fx * iw, iy + fy * ih));
    const leg = [["Risk score 0-100, with what drives it", "Same tunnel, several standards: DISA 38.5, RFC 8247 100", "Evidence confidence: observed, inferred, not visible"],
                 ["Threat matrix: likelihood × impact", "Every reason cites its rule", ""]];
    leg.forEach((col, ci) => col.forEach((str, ri) => { if (!str) return;
      const x = ix + ci * 2.5, y = iy + ih + 0.1 + ri * 0.3; numDot(s, ci * 3 + ri + 1, x, y + 0.02, 0.22);
      t(s, str, { x: x + 0.28, y, w: ci ? 2.1 : 2.2, h: 0.28, fontSize: 9.5, color: C.INK2, valign: "middle" }); }));
    t(s, "Real TunnelScope dashboard, lab capture a-tra-sha1.pcap", { x: ix + 2.5, y: iy + ih + 0.7, w: 2.35, h: 0.28, fontSize: 9.5, italic: true, color: C.MUTED, valign: "middle" });
  }

  // ============ 3  Technical approach
  { const s = pres.addSlide(); chrome(s, 3, "TECHNICAL APPROACH");
    const lanes = [
      ["CAPTURE", "Capture", "pcap file, or live span-port windows", "dumpcap ring buffer"],
      ["DISSECT", "Dissect", "IKEv2, ESP and AH headers only; nothing decrypted", "tshark"],
      ["EVIDENCE", "Evidence", "per-tunnel findings, each labelled with how it is known", "Python 3.11"],
      ["JUDGE", "Judge", "5 written baselines and 4 models trained by us", "YAML rules · scikit-learn"],
      ["REPORT", "Report", "12-threat matrix, 0-100 risk score, reports, CBOM", "React + TypeScript dashboard"],
    ];
    const lw = 2.3, gap = 0.22, x0 = 0.47, y0 = 1.12, lh = 1.95;
    lanes.forEach(([eb, title, body, tool], i) => { const x = x0 + i * (lw + gap);
      const hi = i === 3;
      box(s, x, y0, lw, lh, { fill: hi ? C.VTINT : C.TINT, line: hi ? C.VIOLET : C.LINE, lw: hi ? 1.5 : 1 });
      t(s, (i + 1) + "  " + eb, { x: x + 0.15, y: y0 + 0.12, w: lw - 0.3, h: 0.25, fontSize: 10.5, bold: true, color: C.VIOLET, charSpacing: 2 });
      t(s, body, { x: x + 0.15, y: y0 + 0.45, w: lw - 0.3, h: 0.95, fontSize: 12.5, color: C.INK });
      t(s, tool, { x: x + 0.15, y: y0 + lh - 0.42, w: lw - 0.3, h: 0.3, fontSize: 10.5, color: C.MUTED, italic: true });
      if (i < lanes.length - 1) s.addShape(pres.shapes.CHEVRON, { x: x + lw + 0.04, y: y0 + lh / 2 - 0.11, w: 0.14, h: 0.22, fill: { color: C.VIOLET }, line: { color: C.VIOLET, width: 0 } });
    });

    // the one rule
    t(s, "Every finding carries one label:", { x: x0, y: 3.27, w: 2.6, h: 0.34, fontSize: 12.5, bold: true, valign: "middle" });
    const tiers = [["OBSERVED", "read from packets", C.OBS], ["INFERRED", "deduced, with a confidence", C.INF], ["MEASURED", "computed from traffic", C.MEAS],
                   ["UNKNOWN", "not in this capture", C.UNK], ["NOT OBSERVABLE", "hidden by encryption", C.NOBS]];
    let tx = 3.2; tiers.forEach(([k, v, col]) => { const w = 1.9;
      s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: tx, y: 3.25, w, h: 0.38, rectRadius: 0.19, fill: { color: col }, line: { color: col, width: 0 } });
      t(s, k, { x: tx, y: 3.25, w, h: 0.2, fontSize: 9.5, bold: true, color: C.WHITE, align: "center", valign: "bottom" });
      t(s, v, { x: tx, y: 3.44, w, h: 0.18, fontSize: 8.5, color: C.WHITE, align: "center", valign: "top" });
      tx += w + 0.05; });

    const by = 3.88, bh = 3.1;
    // A: where the AI is
    box(s, x0, by, 4.55, bh, { fill: C.WHITE });
    sectionHead(s, "Where the AI is (models trained by us)", x0 + 0.18, by + 0.14, 4.2);
    t(s, [
      { text: "Traffic type: ", options: { bold: true, bullet: true } }, { text: "Random Forest on 2-second windows of packet size, timing and direction; a type with a confidence, or \"uncertain\"", options: { breakLine: true } },
      { text: "Mixed traffic: ", options: { bold: true, bullet: true } }, { text: "Random Forest flags tunnels carrying several kinds at once", options: { breakLine: true } },
      { text: "Tunnel vs transport: ", options: { bold: true, bullet: true } }, { text: "Random Forest; abstains when packets cannot tell", options: { breakLine: true } },
      { text: "Change detection: ", options: { bold: true, bullet: true } }, { text: "Isolation Forest learns each tunnel's normal and flags downgrades" },
    ], { x: x0 + 0.18, y: by + 0.5, w: 4.2, h: 2.05, fontSize: 11.5, paraSpaceAfter: 4 });
    t(s, "Fields readable in plaintext are parsed exactly, never guessed.", { x: x0 + 0.18, y: by + bh - 0.45, w: 4.2, h: 0.3, fontSize: 10.5, italic: true, color: C.MUTED });

    // B: technologies by role
    const bx = x0 + 4.55 + 0.22;
    box(s, bx, by, 3.9, bh, { fill: C.WHITE });
    sectionHead(s, "Technologies, by role", bx + 0.18, by + 0.14, 3.6);
    [["Analysis", "Python 3.11, tshark, scikit-learn"], ["Rules", "versioned YAML, one file per standard"], ["Interface", "React + TypeScript dashboard, 127.0.0.1 only"],
     ["Lab", "Docker; strongSwan, Libreswan, OpenBSD iked, MikroTik RouterOS"]].forEach(([k, v], i) => {
      const y = by + 0.52 + i * 0.6;
      t(s, k.toUpperCase(), { x: bx + 0.18, y, w: 3.5, h: 0.2, fontSize: 9.5, bold: true, color: C.MUTED, charSpacing: 2 });
      t(s, v, { x: bx + 0.18, y: y + 0.2, w: 3.55, h: 0.38, fontSize: 11.5 });
    });

    // C: method
    const cx = bx + 3.9 + 0.22, cw = W - 0.47 - cx;
    box(s, cx, by, cw, bh, { fill: C.WHITE });
    sectionHead(s, "Method", cx + 0.18, by + 0.14, cw - 0.3);
    t(s, "Each capability is an experiment: the expected result is written down, then captured in the lab and scored against what the VPN endpoints themselves report.",
      { x: cx + 0.18, y: by + 0.48, w: cw - 0.34, h: 1.05, fontSize: 11.5 });
    [["20", "experiments with recorded results"], ["124", "lab captures with endpoint ground truth"], ["4", "IPsec implementations tested"]].forEach(([n, l], i) => {
      const y = by + 1.6 + i * 0.47;
      t(s, n, { x: cx + 0.18, y, w: 0.75, h: 0.42, fontSize: 22, bold: true, color: C.VIOLET, valign: "middle" });
      t(s, l, { x: cx + 0.95, y, w: cw - 1.1, h: 0.42, fontSize: 11, color: C.INK2, valign: "middle" });
    });
  }

  // ============ 4  Feasibility and viability
  { const s = pres.addSlide(); chrome(s, 4, "FEASIBILITY AND VIABILITY");
    const X = 0.5, LW = 4.0;
    sectionHead(s, "Feasibility: already built and tested", X, 1.1, LW);
    const stats = [["516", "unit tests pass"], ["1.6 s", "to assess one capture, end to end"], ["124", "lab captures checked against endpoint ground truth"], ["0.757", "traffic-type F1 on real IPsec traffic (was 0.174)"]];
    stats.forEach(([n, l], i) => { const x = X + (i % 2) * 2.05, y = 1.5 + Math.floor(i / 2) * 1.3;
      box(s, x, y, 1.95, 1.18, { fill: C.TINT, line: C.TINT });
      t(s, n, { x: x + 0.14, y: y + 0.1, w: 1.7, h: 0.5, fontSize: 24, bold: true, color: C.VIOLET, valign: "middle" });
      t(s, l, { x: x + 0.14, y: y + 0.6, w: 1.7, h: 0.52, fontSize: 10.5, color: C.INK2 });
    });
    sectionHead(s, "Viability", X, 4.2, LW);
    t(s, [
      { text: "One laptop, offline by default; ", options: { bold: true, bullet: true } }, { text: "online extras sit behind one switch, off unless configured", options: { breakLine: true } },
      { text: "Open-source stack, ", options: { bold: true, bullet: true } }, { text: "no licence cost to deploy", options: { breakLine: true } },
      { text: "Users: ", options: { bold: true, bullet: true } }, { text: "NTRO and SOC analysts, VPN operators, auditors", options: { breakLine: true } },
      { text: "Reuses tshark ", options: { bold: true, bullet: true } }, { text: "for dissection instead of a new parser" },
    ], { x: X, y: 4.55, w: LW, h: 2.4, fontSize: 12, paraSpaceAfter: 5 });

    // risk -> strategy, one row each
    const RX = 4.75, RW = W - 0.5 - RX, cw1 = RW * 0.47;
    const hy = 1.1;
    s.addShape(pres.shapes.RECTANGLE, { x: RX, y: hy, w: RW, h: 0.4, fill: { color: C.INK }, line: { color: C.INK, width: 0 } });
    t(s, "Potential challenges and risks", { x: RX + 0.15, y: hy, w: cw1 - 0.2, h: 0.4, fontSize: 12.5, bold: true, color: C.WHITE, valign: "middle" });
    t(s, "Strategy to overcome it", { x: RX + cw1 + 0.15, y: hy, w: RW - cw1 - 0.3, h: 0.4, fontSize: 12.5, bold: true, color: C.WHITE, valign: "middle" });
    const risks = [
      ["The data cipher is encrypted.", "The ESP algorithm is not sent in the clear.", "Report a candidate set as INFERRED, never one guess. The handshake suite is read exactly."],
      ["AI can misread traffic.", "Mixed or unfamiliar traffic confuses a traffic-type model.", "Abstain rule answers \"uncertain\" with a reason; mixed-traffic detector. Retrained on real IPsec: right 99.8% of the time it answers."],
      ["Lab is not the field.", "Most tests use open-source VPN stacks.", "4 implementations incl. MikroTik RouterOS, plus a real public IPsec dataset. Vendor appliances next, stated as untested."],
      ["Some risks are invisible on the wire.", "Weak PSK, compromised endpoint, anti-replay window.", "Listed as out of scope with where to check them; never scored."],
      ["Captures are sensitive.", "Traffic data must not leave the site.", "Binds to 127.0.0.1 and runs offline by default; nothing is uploaded unless an operator turns it on."],
    ];
    const rh = 1.08;
    risks.forEach(([lead, why, fix], i) => { const y = hy + 0.4 + i * rh;
      s.addShape(pres.shapes.RECTANGLE, { x: RX, y, w: RW, h: rh, fill: { color: i % 2 ? C.WHITE : C.TINT }, line: { color: C.LINE, width: 0.75 } });
      t(s, [{ text: lead, options: { bold: true, breakLine: true } }, { text: why, options: { color: C.INK2 } }], { x: RX + 0.15, y: y + 0.1, w: cw1 - 0.3, h: rh - 0.2, fontSize: 11.5, valign: "middle" });
      s.addShape(pres.shapes.CHEVRON, { x: RX + cw1 - 0.14, y: y + rh / 2 - 0.1, w: 0.13, h: 0.2, fill: { color: C.VIOLET }, line: { color: C.VIOLET, width: 0 } });
      t(s, fix, { x: RX + cw1 + 0.15, y: y + 0.1, w: RW - cw1 - 0.3, h: rh - 0.2, fontSize: 11.5, valign: "middle" });
    });
  }

  // ============ 5  Impact and benefits
  { const s = pres.addSlide(); chrome(s, 5, "IMPACT AND BENEFITS");
    const X = 0.5, LW = 7.55;
    sectionHead(s, "Potential impact on the target audience", X, 1.1, LW);
    const who = [
      [I.search, "NTRO / SOC analyst", "A verdict per tunnel in about 1.6 s, each finding linked to the packets it came from, instead of reading Wireshark by hand."],
      [I.tool, "VPN operator", "A plain-English fix for each failed rule; the lab fix loop keeps a change only if a fresh capture proves it."],
      [I.clip, "Auditor", "Verdicts against DISA, RFC 8247, RFC 8221 and India's post-quantum baseline, each citing its rule; DPDP Rules 2025 and CERT-In shown as evidence."],
      [I.lock, "National post-quantum migration", "Finds tunnels still on classical key exchange or downgraded, and exports a CycloneDX CBOM crypto inventory."],
    ];
    who.forEach(([ic, k, v], i) => { const y = 1.5 + i * 1.02;
      iconDot(s, ic, X, y + 0.05, 0.55, C.VIOLET);
      t(s, k, { x: X + 0.75, y, w: LW - 0.75, h: 0.3, fontSize: 13.5, bold: true });
      t(s, v, { x: X + 0.75, y: y + 0.3, w: LW - 0.75, h: 0.65, fontSize: 12, color: C.INK2 });
    });
    t(s, [{ text: "Future scope: ", options: { bold: true } }, { text: "validation on vendor appliances, feeds from network sensors, more real-traffic training data." }],
      { x: X, y: 5.65, w: LW, h: 0.5, fontSize: 12, color: C.INK });
    t(s, [{ text: "Indian context: ", options: { bold: true } }, { text: "DPDP Rules 2025 and CERT-In guidelines require encryption without naming algorithms; TunnelScope supplies the evidence, never a compliance verdict." }],
      { x: X, y: 6.2, w: LW, h: 0.75, fontSize: 11.5, color: C.INK2 });

    // real output card, in the product's own dark look
    const RX = 8.35, RW = W - 0.5 - RX;
    box(s, RX, 1.1, RW, 2.75, { fill: C.DARK, line: C.DARK, r: 0.1 });
    t(s, "REAL OUTPUT  ·  pq-downgrade.pcap", { x: RX + 0.2, y: 1.22, w: RW - 0.4, h: 0.25, fontSize: 9.5, bold: true, color: "A78BFA", charSpacing: 2 });
    t(s, "Quantum posture: DOWNGRADED", { x: RX + 0.2, y: 1.52, w: RW - 0.4, h: 0.35, fontSize: 15, bold: true, color: "F3F3F6" });
    t(s, "post-quantum offered, classical used", { x: RX + 0.2, y: 1.86, w: RW - 0.4, h: 0.26, fontSize: 11, color: "9C9CA8" });
    t(s, [{ text: "90", options: { fontSize: 30, bold: true, color: "EF4444" } }, { text: " / 100  critical risk", options: { fontSize: 12, color: "C7CAD1" } }],
      { x: RX + 0.2, y: 2.18, w: RW - 0.4, h: 0.55, valign: "middle" });
    [["RFC 8247", "100", "22C55E"], ["DISA VPN SRG", "38.5", "F2B33D"], ["DST post-quantum", "0", "EF4444"]].forEach(([k, v, col], i) => {
      const y = 2.82 + i * 0.3;
      t(s, k, { x: RX + 0.2, y, w: 2.3, h: 0.28, fontSize: 11, color: "C7CAD1", valign: "middle" });
      t(s, v, { x: RX + RW - 1.2, y, w: 1.0, h: 0.28, fontSize: 12, bold: true, color: col, align: "right", valign: "middle" });
    });
    t(s, "Output of `tunnelscope report` on a lab capture", { x: RX, y: 3.9, w: RW, h: 0.25, fontSize: 9.5, italic: true, color: C.MUTED });

    sectionHead(s, "Benefits", RX, 4.3, RW);
    [[I.shield, "Security", "catches weak or downgraded tunnels that break nothing visibly"],
     [I.rupee, "Economic", "open-source stack on one laptop, with no licence cost"],
     [I.globe, "Strategic", "works air-gapped; no capture leaves the site by default"]].forEach(([ic, k, v], i) => {
      const y = 4.68 + i * 0.78;
      iconDot(s, ic, RX, y + 0.04, 0.42, C.INK);
      t(s, [{ text: k + ": ", options: { bold: true } }, { text: v, options: { color: C.INK2 } }], { x: RX + 0.55, y, w: RW - 0.55, h: 0.7, fontSize: 11.5 });
    });
  }

  // ============ 6  Research and references
  { const s = pres.addSlide(); chrome(s, 6, "RESEARCH AND REFERENCES");
    // one entry = a short linked label on one line, then a grey line saying what we use it for
    const E = (label, url, desc) => [
      url ? { text: label, options: { hyperlink: { url }, color: "1F57B5", breakLine: true } } : { text: label, options: { bold: true, breakLine: true } },
      { text: desc, options: { fontSize: 10.5, color: C.MUTED, breakLine: true } }];
    const HEAD = (str) => [{ text: str, options: { bold: true, color: C.VIOLET, breakLine: true } }];
    const cols = [
      [I.book, "Standards we judge against", [
        ...E("RFC 7296 (IKEv2)", "https://www.rfc-editor.org/rfc/rfc7296.html", "the handshake we parse"),
        ...E("RFC 4303 (ESP)", "https://datatracker.ietf.org/doc/html/rfc4303", "sequence numbers, padding"),
        ...E("RFC 8221", "https://www.rfc-editor.org/rfc/rfc8221", "ESP and AH algorithm rules"),
        ...E("RFC 8247", "https://www.rfc-editor.org/rfc/rfc8247.html", "IKEv2 algorithm rules"),
        ...E("RFC 9370", "https://www.rfc-editor.org/info/rfc9370/", "hybrid post-quantum key exchange"),
        ...E("RFC 9395", "https://datatracker.ietf.org/doc/rfc9395/", "IKEv1 and old algorithms deprecated"),
        ...E("NIST SP 800-77 Rev. 1", "https://csrc.nist.gov/pubs/sp/800/77/r1/final", "guide to IPsec VPNs"),
        ...E("DISA VPN SRG V2R6", null, "US DoD rules for VPN gateways"),
        ...E("DST Task Force report, Feb 2026", "https://dst.gov.in/sites/default/files/Report_TaskForce_PQMigration_4Feb26%20(v1).pdf", "India's post-quantum migration"),
      ]],
      [I.db, "Real traffic and prior art", [
        ...E("USBVPN2022 (Zenodo 7301756)", "https://zenodo.org/records/7301756", "real L2TP/IPsec tunnels"),
        ...E("MIT Lincoln Laboratory VNAT", "https://www.ll.mit.edu/r-d/datasets/vpnnonvpn-network-application-traffic-dataset-vnat", "real VPN application traffic"),
        ...E("arXiv:2205.05628", "https://arxiv.org/pdf/2205.05628", "the VNAT paper"),
        ...E("WireGuard flows (Zenodo 18945858)", "https://zenodo.org/records/18945858", "real people's traffic at home"),
        { text: " ", options: { breakLine: true } },
        ...HEAD("The gap we found"),
        ...E("Wireshark issue #21072", "https://gitlab.com/wireshark/wireshark/-/work_items/21072", "IKEv2 dissector does not decode ML-KEM"),
        ...E("strongSwan 6.0.0 release", "https://strongswan.org/blog/2024/12/03/strongswan-6.0.0-released.html", "VPNs already negotiate ML-KEM"),
      ]],
      [I.flag, "Indian context and our evidence", [
        ...E("DPDP Rules 2025", null, "G.S.R. 846(E), 13 Nov 2025"),
        ...E("CERT-In Guidelines (2023)", "https://www.pib.gov.in/PressReleaseIframePage.aspx?PRID=1936470", "security practices for government entities"),
        { text: " ", options: { breakLine: true } },
        ...HEAD("Our evidence"),
        ...E("20 lab experiments", null, "each with a recorded result"),
        ...E("124 captures", null, "checked against endpoint ground truth"),
        { text: " ", options: { breakLine: true } },
        Object.assign({}, fill(VIDEO_URL, "demo video link"), VIDEO_URL ? { options: { hyperlink: { url: VIDEO_URL }, color: "1F57B5", breakLine: true } } : { options: { highlight: C.HL, bold: true, color: C.INK, breakLine: true } }),
        Object.assign({}, fill(REPO_URL, "code link (only if public)"), REPO_URL ? { options: { hyperlink: { url: REPO_URL }, color: "1F57B5" } } : {}),
      ]],
    ];
    const cw = (W - 1.0 - 0.5) / 3;
    cols.forEach(([ic, head, runs], i) => { const x = 0.5 + i * (cw + 0.25), y = 1.12, h = 5.85;
      box(s, x, y, cw, h, { fill: C.WHITE });
      iconDot(s, ic, x + 0.2, y + 0.18, 0.46, C.VIOLET);
      t(s, head, { x: x + 0.78, y: y + 0.18, w: cw - 0.95, h: 0.46, fontSize: 14, bold: true, valign: "middle" });
      t(s, runs, { x: x + 0.2, y: y + 0.85, w: cw - 0.4, h: h - 1.0, fontSize: 12.5, paraSpaceAfter: 2, color: C.INK });
    });
  }

  await pres.writeFile({ fileName: OUT });
  console.log("wrote " + OUT);
})();
