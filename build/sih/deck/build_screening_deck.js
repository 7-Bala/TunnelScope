// TunnelScope idea-submission deck for the SIH screening round: the official 6-slide idea template
// (Title, Idea title, Technical approach, Feasibility & viability, Impact & benefits, Research & references).
//   node build/sih/deck/build_screening_deck.js [out.pptx]
// Plain SIH-template look, like past winning decks: white slides, Times New Roman headings, Arial text,
// thin-bordered text boxes, ➤ bullets, one classic flowchart in plain words. Every number has a source,
// listed in SOURCES below. Fill TEAM_ID / VIDEO_URL / REPO_URL before exporting to PDF: while empty they
// render as a yellow "fill before export" marker so they cannot be missed.
const pptxgen = require("pptxgenjs");
const JSZip = require("jszip");
const fs = require("fs");
const path = require("path");
const HERE = __dirname;
const OUT = process.argv[2] || path.join(process.env.HOME, "Downloads", "TunnelScope_SIH26160_Idea_Submission.pptx");

const TEAM_NAME = "Think2Thrive";
const TEAM_ID = "";   // from the SIH portal
const VIDEO_URL = ""; // demo video, on a host that does not sleep
const REPO_URL = "";  // only if the repository is public or shared with the evaluators

// SOURCES (checked 2026-09-27)
//   531 unit tests pass ........ `.venv/bin/python -m pytest -q` -> "531 passed, 1 skipped"
//   ~1.6 s per capture ......... `tunnelscope report` on 4 lab captures: 1.58-1.67 s wall time each
//   124 lab captures ........... testbed/captures/**/*.groundtruth.json (endpoint ground truth)
//   0.174 -> 0.757, 99.8% ...... experiments/exp20-real-ipsec-and-users/RESULT.md (R3), DEC-037
//   20 experiments ............. experiments/*/RESULT.md
//   4 implementations .......... strongSwan, Libreswan (EXP-07), OpenBSD iked (EXP-10), MikroTik RouterOS (EXP-26)
//   pq-downgrade verdicts ...... `tunnelscope report testbed/captures/pq-downgrade.pcap`
//   screenshot ................. img/threats.jpg (dashboard, lab capture a-tra-sha1.pcap), cropped to img/tunnel-view.jpg

const C = { INK: "000000", TEXT: "1A1A1A", GREY: "595959", LINE: "7F7F7F", NAVY: "1F3864", BLUE: "2E75B6",
  BAR: "0070C0", WHITE: "FFFFFF", LINK: "0563C1", HL: "FFFF00",
  PROC: "DEEBF7", PROC_L: "2E75B6", DEC: "FFF2CC", DEC_L: "BF9000", TERM: "E2F0D9", TERM_L: "548235", SIDE: "F2F2F2", SIDE_L: "7F7F7F" };
const HEAD = "Times New Roman", F = "Arial";
const W = 13.333, H = 7.5;

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";
pres.title = "TunnelScope: SIH26160 idea submission";
pres.author = "Team " + TEAM_NAME;

function t(s, str, o) {
  s.addText(str, Object.assign({ fontFace: F, fontSize: 13, color: C.TEXT, isTextBox: true, margin: 0, valign: "top" }, o));
}
function frame(s, x, y, w, h) {
  s.addShape(pres.shapes.RECTANGLE, { x, y, w, h, fill: { color: C.WHITE }, line: { color: C.LINE, width: 1 } });
}
// value, or a yellow marker while it is still empty
function fill(v, what) { return v ? v : null; }
function marker(what) { return { text: "FILL BEFORE EXPORT: " + what, options: { highlight: C.HL, bold: true, color: C.INK } }; }

// ➤ bullet paragraphs: items are strings or [bold lead, rest]
function bullets(items, o = {}) {
  const runs = [];
  items.forEach((it, i) => {
    const last = i === items.length - 1;
    const bl = { bullet: { code: "27A4" }, indentLevel: o.level || 0 };
    if (typeof it === "string") runs.push({ text: it, options: Object.assign({}, bl, last ? {} : { breakLine: true }) });
    else {
      runs.push({ text: it[0], options: Object.assign({ bold: true }, bl) });
      runs.push({ text: it[1], options: last ? {} : { breakLine: true } });
    }
  });
  return runs;
}

// template chrome: team badge, title, SIH logo, blue footer bar with the page number
function chrome(s, num, title) {
  s.background = { color: C.WHITE };
  s.addShape(pres.shapes.OVAL, { x: 0.3, y: 0.24, w: 1.7, h: 0.6, fill: { color: C.WHITE }, line: { color: "595959", width: 1.25 } });
  t(s, TEAM_NAME, { x: 0.3, y: 0.24, w: 1.7, h: 0.6, fontSize: 12, align: "center", valign: "middle", color: C.INK });
  t(s, title, { x: 2.2, y: 0.22, w: 8.7, h: 0.7, fontFace: HEAD, fontSize: 32, bold: true, align: "center", valign: "middle", color: C.INK });
  logo(s, 11.1, 0.14, 0.72);
  s.addShape(pres.shapes.RECTANGLE, { x: 0, y: 7.12, w: W, h: 0.38, fill: { color: C.BAR }, line: { color: C.BAR, width: 0 } });
  t(s, "@SIH Idea submission- Template", { x: 3.67, y: 7.12, w: 6, h: 0.38, fontSize: 10, color: C.WHITE, align: "center", valign: "middle" });
  t(s, String(num), { x: 12.3, y: 7.12, w: 0.6, h: 0.38, fontSize: 10, bold: true, color: C.WHITE, align: "right", valign: "middle" });
}
function logo(s, x, y, h) {
  s.addImage({ path: path.join(HERE, "img", "sih-bulb.png"), x, y, w: h * 521 / 600, h });
  t(s, "SMART INDIA\nHACKATHON\n2026", { x: x + h * 0.9, y: y + 0.02, w: 1.3, h, fontSize: 10.5, bold: true, color: "4F5F6A", valign: "middle", lineSpacingMultiple: 0.95 });
}
function heading(s, str, x, y, w) {
  t(s, str, { x, y, w, h: 0.32, fontSize: 15, bold: true, color: C.NAVY });
}

// ---- flowchart helpers (coordinates in inches)
function node(s, shape, x, y, w, h, label, fillc, linec, fs = 11) {
  s.addText(label, { shape, x, y, w, h, fill: { color: fillc }, line: { color: linec, width: 1.25 },
    fontFace: F, fontSize: fs, color: C.INK, align: "center", valign: "middle", margin: 2, isTextBox: false });
}
function line(s, x1, y1, x2, y2, arrow = true) {
  s.addShape(pres.shapes.LINE, { x: Math.min(x1, x2), y: Math.min(y1, y2), w: Math.max(Math.abs(x2 - x1), 0.001), h: Math.max(Math.abs(y2 - y1), 0.001),
    flipH: x2 < x1, flipV: y2 < y1, line: { color: "404040", width: 1.25, endArrowType: arrow ? "triangle" : undefined } });
}
function tag(s, str, x, y) { t(s, str, { x, y, w: 0.5, h: 0.22, fontSize: 10, bold: true, color: C.INK }); }

(async () => {
  // ============ 1  Title page
  { const s = pres.addSlide(); s.background = { color: C.WHITE };
    t(s, "SMART INDIA HACKATHON 2026", { x: 0.5, y: 0.3, w: 10.3, h: 0.75, fontFace: HEAD, fontSize: 36, bold: true, color: C.NAVY, align: "center", valign: "middle" });
    logo(s, 11.1, 0.2, 0.75);
    t(s, "TITLE PAGE", { x: 0.5, y: 1.15, w: 7.6, h: 0.5, fontFace: HEAD, fontSize: 24, bold: true, align: "center", color: C.INK });
    s.addShape(pres.shapes.HEXAGON, { x: 8.05, y: 1.35, w: 4.9, h: 4.9, fill: { color: "EDEDED" }, line: { color: "EDEDED", width: 0 }, rotate: 90 });
    s.addShape(pres.shapes.HEXAGON, { x: 7.55, y: 1.05, w: 1.6, h: 1.6, fill: { color: C.WHITE, transparency: 100 }, line: { color: "D9D9D9", width: 3 }, rotate: 90 });
    s.addShape(pres.shapes.HEXAGON, { x: 7.35, y: 4.45, w: 1.2, h: 1.2, fill: { color: "F2F2F2" }, line: { color: "F2F2F2", width: 0 }, rotate: 90 });
    s.addImage({ path: path.join(HERE, "img", "sih-bulb.png"), x: 8.85, y: 1.95, w: 3.3 * 521 / 600, h: 3.3 });
    const rows = [
      ["Problem Statement ID", "SIH26160"],
      ["Problem Statement Title", "AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework"],
      ["Theme", "Blockchain & Cybersecurity"],
      ["PS Category", "Software"],
      ["Team ID", fill(TEAM_ID)],
      ["Team Name (Registered on portal)", TEAM_NAME],
    ];
    const para = [];
    rows.forEach(([k, v], i) => {
      const last = i === rows.length - 1;
      para.push({ text: k + " – ", options: { bold: true, bullet: true } });
      if (v) para.push({ text: v, options: last ? {} : { breakLine: true } });
      else { const m = marker(k); m.options.breakLine = !last; para.push(m); }
    });
    t(s, para, { x: 0.7, y: 1.95, w: 6.9, h: 4.8, fontSize: 18, color: C.INK, paraSpaceAfter: 16 });
  }

  // ============ 2  Idea title
  { const s = pres.addSlide(); chrome(s, 2, "IDEA TITLE");
    t(s, [{ text: "IDEA/SOLUTION: ", options: { color: C.BLUE } }, { text: "TunnelScope – “Check how safe a VPN really is, just by watching its traffic”", options: { bold: true } }],
      { x: 0.5, y: 1.05, w: 12.3, h: 0.4, fontSize: 16 });

    const LX = 0.5, LW = 7.35, top = 1.55, bot = 7.0;
    frame(s, LX, top, LW, bot - top);
    t(s, [{ text: "TunnelScope", options: { bold: true } }, { text: " is a software tool for security analysts. It reads the traffic of an IPsec VPN and tells, in plain language, how the VPN is set up and whether that is safe. It works as follows:" }],
      { x: LX + 0.15, y: top + 0.1, w: LW - 0.3, h: 0.7, fontSize: 12.5 });
    t(s, bullets([
      ["Input: ", "a saved traffic capture (.pcap) or a live copy of network traffic."],
      ["Reads only the packet headers ", "with tshark; the encrypted data is never opened."],
      ["Finds the settings: ", "VPN protocol, IKE version, encryption, key exchange, tunnel or transport mode."],
      ["AI models trained by us ", "(Random Forest) tell the type of traffic inside (web, video, VoIP…) from packet size and timing."],
      ["Checks every setting ", "against security standards (RFC 8247, RFC 8221, DISA, India’s post-quantum report)."],
      ["Gives a risk score (0–100), threats and a fix ", "for each problem, in a report and a dashboard."],
    ]), { x: LX + 0.15, y: top + 0.82, w: LW - 0.3, h: 3.25, fontSize: 12, paraSpaceAfter: 5 });
    t(s, "Unique Value Propositions:", { x: LX + 0.15, y: top + 3.85, w: LW - 0.3, h: 0.3, fontSize: 14, color: C.BLUE });
    t(s, bullets(["Detects a post-quantum downgrade (safe option offered, weaker one used).", "Every verdict names the rule it is based on.",
      "Never guesses: what cannot be seen is marked “unknown”, never “safe”.", "Works offline by default."]),
      { x: LX + 0.15, y: top + 4.2, w: LW - 0.3, h: 1.2, fontSize: 12.5, bold: true, paraSpaceAfter: 5 });

    const RX = 8.1, RW = W - 0.5 - RX;
    frame(s, RX, top, RW, 1.3);
    t(s, "Problem Resolution:", { x: RX + 0.12, y: top + 0.08, w: RW - 0.24, h: 0.3, fontSize: 14, color: C.BLUE });
    t(s, bullets(["Today an expert reads VPN packets by hand.", "TunnelScope checks automatically and shows the evidence for every answer."]),
      { x: RX + 0.12, y: top + 0.4, w: RW - 0.24, h: 0.85, fontSize: 11.5, paraSpaceAfter: 2 });
    const iy = top + 1.42, ih = bot - 0.3 - iy, iw = ih * 1400 / 1341;
    s.addImage({ path: path.join(HERE, "img", "tunnel-view.jpg"), x: RX + (RW - iw) / 2, y: iy, w: iw, h: ih });
    t(s, "Our working prototype: risk score, threats and the rule behind each one", { x: RX, y: iy + ih + 0.03, w: RW, h: 0.24, fontSize: 9.5, italic: true, color: C.GREY, align: "center" });
  }

  // ============ 3  Technical approach: technologies + flowchart
  { const s = pres.addSlide(); chrome(s, 3, "TECHNICAL APPROACH");
    const LX = 0.5, LW = 3.95, top = 1.1, bot = 7.0;
    frame(s, LX, top, LW, bot - top);
    heading(s, "Technologies Used:", LX + 0.15, top + 0.1, LW - 0.3);
    t(s, bullets([
      ["Language: ", "Python 3.11"],
      ["Packet reading: ", "tshark (Wireshark)"],
      ["AI / ML: ", "scikit-learn – Random Forest, Isolation Forest"],
      ["Security rules: ", "YAML files, one per standard"],
      ["Dashboard: ", "React + TypeScript"],
      ["Test lab: ", "Docker and VMs: strongSwan, Libreswan, OpenBSD iked, MikroTik"],
    ]), { x: LX + 0.15, y: top + 0.48, w: LW - 0.3, h: 2.9, fontSize: 12, paraSpaceAfter: 6 });
    heading(s, "Methodology:", LX + 0.15, top + 3.45, LW - 0.3);
    t(s, bullets([
      "Built our own VPN lab and recorded 124 captures, checked against the VPNs’ own logs.",
      "Tested each feature in an experiment (20 so far) before adding it.",
      "Tested on real public IPsec traffic, not only lab traffic.",
    ]), { x: LX + 0.15, y: top + 3.82, w: LW - 0.3, h: 2.0, fontSize: 12, paraSpaceAfter: 6 });

    // flowchart, top to bottom, "no" branches to the right
    t(s, "Work Flow", { x: 9.45, y: 1.15, w: 3.35, h: 0.45, align: "center", fontFace: HEAD, fontSize: 22, bold: true, color: C.INK });
    const cx = 6.95, NW = 3.5, SX = 9.45, SW = 3.35;
    const X = cx - NW / 2, R = cx + NW / 2;
    const y = { start: 1.15, input: 1.7, read: 2.35, d1: 2.98, set: 3.86, ai: 4.46, d2: 5.08, rep: 5.96, end: 6.62 };
    node(s, pres.shapes.FLOWCHART_TERMINATOR, cx - 0.8, y.start, 1.6, 0.38, "Start", C.TERM, C.TERM_L, 11.5);
    line(s, cx, y.start + 0.38, cx, y.input);
    node(s, pres.shapes.FLOWCHART_DATA, X, y.input, NW, 0.46, "Input: VPN traffic capture (.pcap) or live feed", C.PROC, C.PROC_L);
    line(s, cx, y.input + 0.46, cx, y.read);
    node(s, pres.shapes.FLOWCHART_PROCESS, X, y.read, NW, 0.44, "Read packet headers with tshark (nothing is decrypted)", C.PROC, C.PROC_L);
    line(s, cx, y.read + 0.44, cx, y.d1);
    node(s, pres.shapes.FLOWCHART_DECISION, cx - 1.35, y.d1, 2.7, 0.7, "Is the VPN handshake in the capture?", C.DEC, C.DEC_L, 10.5);
    line(s, cx, y.d1 + 0.7, cx, y.set); tag(s, "Yes", cx + 0.08, y.d1 + 0.66);
    node(s, pres.shapes.FLOWCHART_PROCESS, X, y.set, NW, 0.44, "Read the settings: encryption, key exchange, quantum-safe or not", C.PROC, C.PROC_L);
    line(s, cx + 1.35, y.d1 + 0.35, SX, y.d1 + 0.35); tag(s, "No", cx + 1.45, y.d1 + 0.1);
    node(s, pres.shapes.FLOWCHART_PROCESS, SX, y.d1 + 0.13, SW, 0.44, "Mark those settings “unknown” (never guessed)", C.SIDE, C.SIDE_L);
    line(s, SX + SW / 2, y.d1 + 0.57, SX + SW / 2, y.ai + 0.22, false); line(s, SX + SW / 2, y.ai + 0.22, R, y.ai + 0.22);
    line(s, cx, y.set + 0.44, cx, y.ai);
    node(s, pres.shapes.FLOWCHART_PROCESS, X, y.ai, NW, 0.44, "AI models: type of traffic and tunnel mode, with a confidence", C.PROC, C.PROC_L);
    line(s, cx, y.ai + 0.44, cx, y.d2);
    node(s, pres.shapes.FLOWCHART_DECISION, cx - 1.35, y.d2, 2.7, 0.7, "Meets the security standards?", C.DEC, C.DEC_L, 10.5);
    line(s, cx, y.d2 + 0.7, cx, y.rep); tag(s, "Yes", cx + 0.08, y.d2 + 0.66);
    line(s, cx + 1.35, y.d2 + 0.35, SX, y.d2 + 0.35); tag(s, "No", cx + 1.45, y.d2 + 0.1);
    node(s, pres.shapes.FLOWCHART_PROCESS, SX, y.d2 + 0.1, SW, 0.5, "Flag the threat, raise the risk score, suggest a fix", C.SIDE, C.SIDE_L);
    line(s, SX + SW / 2, y.d2 + 0.6, SX + SW / 2, y.rep + 0.23, false); line(s, SX + SW / 2, y.rep + 0.23, R, y.rep + 0.23);
    node(s, pres.shapes.FLOWCHART_DOCUMENT, X, y.rep, NW, 0.5, "Report + dashboard: risk score, threats, fixes", C.PROC, C.PROC_L);
    line(s, cx, y.rep + 0.5, cx, y.end);
    node(s, pres.shapes.FLOWCHART_TERMINATOR, cx - 0.8, y.end, 1.6, 0.36, "End", C.TERM, C.TERM_L, 11.5);
  }

  // ============ 4  Feasibility and viability
  { const s = pres.addSlide(); chrome(s, 4, "FEASIBILITY AND VIABILITY");
    const LX = 0.5, LW = 5.6, top = 1.1, bot = 7.0;
    frame(s, LX, top, LW, bot - top); frame(s, 6.3, top, W - 0.5 - 6.3, bot - top);
    heading(s, "Feasibility of the Idea:", LX + 0.15, top + 0.12, LW - 0.3);
    t(s, bullets([
      ["Technical Feasibility: ", "already built and working. 531 automatic tests pass; one capture is checked in about 1.6 seconds."],
      ["Proven on real traffic: ", "on real IPsec traffic the traffic-type model improved from 0.174 to 0.757 (F1 score) and is right 99.8% of the time when it answers."],
      ["Operational Feasibility: ", "runs on one laptop, offline by default. Uses tshark, a tool analysts already know."],
      ["Economic Feasibility: ", "built only on free, open-source software; no licence cost."],
      ["Users: ", "NTRO analysts, security operations teams, VPN administrators, auditors."],
    ]), { x: LX + 0.15, y: top + 0.55, w: LW - 0.3, h: bot - top - 0.65, fontSize: 15, paraSpaceAfter: 16 });

    const RX = 6.45, RW = W - 0.65 - RX;
    heading(s, "Potential Challenges, Risks and its Overcomings:", RX, top + 0.12, RW);
    const pairs = [
      ["Encrypted data: ", "the encryption of the data part is hidden.", "Show the few possible options, clearly marked as a best guess."],
      ["AI can be wrong: ", "mixed traffic can confuse the model.", "The model says “uncertain” instead of guessing wrong."],
      ["Lab vs real world: ", "most testing used open-source VPNs.", "Tested on 4 VPN programs and real public traffic; vendor devices next."],
      ["Hidden risks: ", "weak passwords or a hacked device cannot be seen in traffic.", "Listed separately as “not checked”, never scored."],
      ["Sensitive data: ", "traffic must not leave the site.", "Works offline by default; nothing is uploaded unless an operator turns online extras on."],
    ];
    const runs = [];
    pairs.forEach(([lead, risk, fix], i) => {
      runs.push({ text: lead, options: { bold: true, bullet: { code: "27A4" } } });
      runs.push({ text: risk, options: { breakLine: true } });
      runs.push({ text: "Solution: ", options: { bold: true, bullet: { code: "2756" }, indentLevel: 1 } });
      runs.push({ text: fix, options: i === pairs.length - 1 ? {} : { breakLine: true } });
    });
    t(s, runs, { x: RX, y: top + 0.55, w: RW, h: bot - top - 0.65, fontSize: 14, paraSpaceAfter: 9 });
  }

  // ============ 5  Impact and benefits
  { const s = pres.addSlide(); chrome(s, 5, "IMPACT AND BENEFITS");
    const LX = 0.5, LW = 7.3, top = 1.1;
    const items = [
      ["Faster checks for analysts:", "Impact: a VPN is checked in seconds instead of reading packets by hand.", "Benefit: more VPNs checked, fewer missed problems."],
      ["Quantum-safe readiness:", "Impact: finds VPNs that still use old key exchange, or were pushed down from a quantum-safe one.", "Benefit: supports India’s post-quantum migration."],
      ["Clear fixes for administrators:", "Impact: every failed rule comes with a plain-language fix.", "Benefit: problems get fixed, not just reported."],
      ["Evidence for auditors:", "Impact: each verdict cites its standard (RFC, DISA, DST).", "Benefit: supports DPDP Rules 2025 and CERT-In audits."],
      ["Secure by design:", "Impact: works offline by default; nothing leaves the site.", "Benefit: suitable for sensitive government networks."],
    ];
    const runs = [];
    items.forEach(([h, a, b], i) => {
      runs.push({ text: h, options: { bold: true, breakLine: true } });
      runs.push({ text: a, options: { bullet: { code: "27A4" }, breakLine: true } });
      runs.push({ text: b, options: i === items.length - 1 ? { bullet: { code: "27A4" } } : { bullet: { code: "27A4" }, breakLine: true } });
    });
    t(s, runs, { x: LX, y: top, w: LW, h: 5.85, fontSize: 14, paraSpaceAfter: 5 });

    // right: a real result as a plain table
    const RX = 8.15, RW = W - 0.5 - RX;
    heading(s, "Example: result from our tool", RX, top, RW);
    const hd = { bold: true, fill: { color: "D9E2F3" }, fontFace: F, fontSize: 11.5, color: C.INK };
    const cell = { fontFace: F, fontSize: 11.5, color: C.INK };
    s.addTable([
      [{ text: "Capture file", options: hd }, { text: "pq-downgrade.pcap (lab)", options: hd }],
      [{ text: "Quantum-safe?", options: cell }, { text: "No – offered, but a weaker one was used", options: cell }],
      [{ text: "Risk score", options: cell }, { text: "90 / 100 (critical)", options: Object.assign({ bold: true, color: "C00000" }, cell) }],
      [{ text: "RFC 8247 score", options: cell }, { text: "100 / 100", options: cell }],
      [{ text: "DISA score", options: cell }, { text: "38.5 / 100", options: cell }],
      [{ text: "India PQ score", options: cell }, { text: "0 / 100", options: cell }],
    ], { x: RX, y: top + 0.42, w: RW, colW: [1.55, RW - 1.55], border: { type: "solid", color: "7F7F7F", pt: 0.75 }, rowH: 0.4, valign: "middle", margin: 0.06 });
    t(s, "The same VPN can pass one standard and fail another, so TunnelScope shows each standard separately.",
      { x: RX, y: top + 3.02, w: RW, h: 0.7, fontSize: 11, italic: true, color: C.GREY });
    heading(s, "Future scope:", RX, top + 3.85, RW);
    t(s, bullets(["Testing on vendor VPN devices", "Direct feeds from network sensors", "More real-world traffic for training"]),
      { x: RX, y: top + 4.22, w: RW, h: 1.5, fontSize: 12, paraSpaceAfter: 4 });
  }

  // ============ 6  Research and references
  { const s = pres.addSlide(); chrome(s, 6, "RESEARCH AND REFERENCES");
    const L = (label, url) => ({ text: label, options: { hyperlink: { url }, color: C.LINK, bullet: { code: "27A4" }, breakLine: true } });
    const P = (label) => ({ text: label, options: { bullet: { code: "27A4" }, breakLine: true } });
    const Hd = (label) => ({ text: label, options: { bold: true, fontSize: 15, color: C.INK, breakLine: true } });
    const left = [
      Hd("Security standards:"),
      L("RFC 7296 – IKEv2 protocol", "https://www.rfc-editor.org/rfc/rfc7296.html"),
      L("RFC 4303 – ESP protocol", "https://datatracker.ietf.org/doc/html/rfc4303"),
      L("RFC 8221 – ESP/AH algorithm rules", "https://www.rfc-editor.org/rfc/rfc8221"),
      L("RFC 8247 – IKEv2 algorithm rules", "https://www.rfc-editor.org/rfc/rfc8247.html"),
      L("RFC 9370 – post-quantum key exchange in IKEv2", "https://www.rfc-editor.org/info/rfc9370/"),
      L("RFC 9395 – IKEv1 deprecated", "https://datatracker.ietf.org/doc/rfc9395/"),
      L("NIST SP 800-77 Rev. 1 – Guide to IPsec VPNs", "https://csrc.nist.gov/pubs/sp/800/77/r1/final"),
      P("DISA VPN Security Requirements Guide V2R6"),
      L("DST – Quantum Safe Ecosystem in India, Task Force report (Feb 2026)", "https://dst.gov.in/sites/default/files/Report_TaskForce_PQMigration_4Feb26%20(v1).pdf"),
    ];
    const right = [
      Hd("Datasets (real traffic):"),
      L("USBVPN2022 – real IPsec tunnels (Zenodo 7301756)", "https://zenodo.org/records/7301756"),
      L("MIT Lincoln Laboratory – VNAT VPN dataset", "https://www.ll.mit.edu/r-d/datasets/vpnnonvpn-network-application-traffic-dataset-vnat"),
      L("WireGuard traffic flows (Zenodo 18945858)", "https://zenodo.org/records/18945858"),
      L("VNAT paper – arXiv:2205.05628", "https://arxiv.org/pdf/2205.05628"),
      { text: " ", options: { breakLine: true } },
      Hd("Research gap and Indian context:"),
      L("Wireshark issue #21072 – cannot decode post-quantum IKEv2", "https://gitlab.com/wireshark/wireshark/-/work_items/21072"),
      L("strongSwan 6.0.0 – VPNs already use post-quantum ML-KEM", "https://strongswan.org/blog/2024/12/03/strongswan-6.0.0-released.html"),
      P("DPDP Rules 2025 – G.S.R. 846(E), 13 Nov 2025"),
      L("CERT-In Guidelines for Government Entities (2023)", "https://www.pib.gov.in/PressReleaseIframePage.aspx?PRID=1936470"),
      { text: " ", options: { breakLine: true } },
      Hd("Our work:"),
      VIDEO_URL ? L("Demo video", VIDEO_URL) : Object.assign(marker("demo video link"), {}),
    ];
    if (!VIDEO_URL) right[right.length - 1].options = Object.assign({ bullet: { code: "27A4" }, breakLine: true }, right[right.length - 1].options, { breakLine: true });
    right.push(REPO_URL ? Object.assign(L("Source code", REPO_URL), {}) : Object.assign(marker("code link (only if public)"), {}));
    if (!REPO_URL) right[right.length - 1].options.bullet = { code: "27A4" };
    delete right[right.length - 1].options.breakLine;
    left[left.length - 1].options = Object.assign({}, left[left.length - 1].options); delete left[left.length - 1].options.breakLine;
    frame(s, 0.5, 1.1, 5.95, 5.9);
    t(s, left, { x: 0.68, y: 1.25, w: 5.6, h: 5.65, fontSize: 14, paraSpaceAfter: 10 });
    frame(s, 6.65, 1.1, 6.18, 5.9);
    t(s, right, { x: 6.83, y: 1.25, w: 5.85, h: 5.65, fontSize: 14, paraSpaceAfter: 6 });
  }

  // pptxgenjs writes a stray <a:pPr>…<a:buNone/></a:pPr> between the runs of a mixed bold/plain line, which
  // switches the ➤ bullet off; a pPr after a run is never valid inside a paragraph, so drop every such one
  const zip = await JSZip.loadAsync(await pres.write({ outputType: "nodebuffer" }));
  for (const name of Object.keys(zip.files).filter((n) => /^ppt\/slides\/slide\d+\.xml$/.test(n))) {
    const xml = await zip.file(name).async("string");
    zip.file(name, xml.replace(/(<\/a:r>)(?:<a:pPr[^>]*\/>|<a:pPr[^>]*>.*?<\/a:pPr>)/g, "$1"));
  }
  fs.writeFileSync(OUT, await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" }));
  console.log("wrote " + OUT);
})();
