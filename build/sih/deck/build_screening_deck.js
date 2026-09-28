// TunnelScope idea-submission deck for the SIH screening round: the official 6-slide idea template
// (Title, Proposed solution, Technical approach, Feasibility & viability, Impact & benefits, Research & references).
//   node build/sih/deck/build_screening_deck.js [out.pptx]
// Icons and technology logos come from img/icons and img/logos (build/sih/deck/make_icons.js renders them).
// Plain SIH-template look: white slides, Times New Roman headings, Arial text, thin-bordered boxes, ➤ bullets,
// icons in coloured circles. Owner's rules for this version: no model accuracy, no "x of y" results, no test
// counts, no typed confirmation codes, never the word "optional". Every number left has a source below.
// Fill TEAM_ID / VIDEO_URL / REPO_URL before exporting to PDF: while empty they render as a yellow marker.
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

// SOURCES (checked 2026-09-28)
//   ~1.6 s per capture ......... `tunnelscope report` on 4 lab captures: 1.58-1.67 s wall time each
//   risk score formula ......... tunnelscope/risk/risk.py (DEC-028): noisy-OR, 100 * (1 - prod(1 - 0.6*L*I/9))
//   4 VPN programs ............. strongSwan, Libreswan (EXP-07), OpenBSD iked (EXP-10), MikroTik RouterOS (EXP-26)
//   live gateways .............. testbed/live-gateway/e2e.py, DEC-047 (strongSwan over SSH, terms accepted first)
//   DST Task Force ............. research/registers/RESEARCH-LOG.md: CII by 2027, enterprises by 2028; vendor CBOM
//                                from FY 2027-28; names "downgrade or insecure fallback"
//   DPDP / CERT-In ............. build/06-INDIA-REGULATORY-MAPPING.md: Rule 6(1)(a) encryption, in force
//                                13 May 2027, penalty up to Rs 250 crore (PIB 17 Nov 2025); CERT-In 2023 s3.4
//                                internal audit at least every 6 months
//   lab vs real traffic ........ experiments/exp20-real-ipsec-and-users/RESULT.md, DEC-037: the lab-only model failed on
//                                real IPsec traffic and was retrained on USBVPN2022 + WireGuard (no numbers on the slide)
//   data leaving the site ...... remediate/gateways.py terms (rule text + proposal line to the AI provider when
//                                cloud drafting is on), intel/lookup.py (only product names), README

const C = { INK: "000000", TEXT: "1A1A1A", GREY: "595959", LINE: "7F7F7F", NAVY: "1F3864", BLUE: "2E75B6",
  BAR: "0070C0", WHITE: "FFFFFF", LINK: "0563C1", HL: "FFFF00", SOFT: "F2F6FB",
  PROC: "DEEBF7", PROC_L: "2E75B6", DEC: "FFF2CC", DEC_L: "BF9000", TERM: "E2F0D9", TERM_L: "548235", SIDE: "F2F2F2", SIDE_L: "7F7F7F" };
const HEAD = "Times New Roman", F = "Arial";
const W = 13.333, H = 7.5;
const ICON = (n) => path.join(HERE, "img", "icons", n + ".png");
const LOGO = (n) => path.join(HERE, "img", "logos", n + ".png");

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";
pres.title = "TunnelScope: SIH26160 idea submission";
pres.author = "Team " + TEAM_NAME;

function t(s, str, o) {
  s.addText(str, Object.assign({ fontFace: F, fontSize: 13, color: C.TEXT, isTextBox: true, margin: 0, valign: "top" }, o));
}
function frame(s, x, y, w, h, fillc = C.WHITE) {
  s.addShape(pres.shapes.RECTANGLE, { x, y, w, h, fill: { color: fillc }, line: { color: C.LINE, width: 1 } });
}
function fill(v) { return v ? v : null; }
function marker(what) { return { text: "FILL BEFORE EXPORT: " + what, options: { highlight: C.HL, bold: true, color: C.INK } }; }
function icon(s, name, x, y, d) { s.addImage({ path: ICON(name), x, y, w: d, h: d }); }

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
  t(s, title, { x: 2.2, y: 0.22, w: 8.7, h: 0.7, fontFace: HEAD, fontSize: 30, bold: true, align: "center", valign: "middle", color: C.INK });
  logo(s, 11.1, 0.14, 0.72);
  s.addShape(pres.shapes.RECTANGLE, { x: 0, y: 7.12, w: W, h: 0.38, fill: { color: C.BAR }, line: { color: C.BAR, width: 0 } });
  t(s, "@SIH Idea submission- Template", { x: 3.67, y: 7.12, w: 6, h: 0.38, fontSize: 10, color: C.WHITE, align: "center", valign: "middle" });
  t(s, String(num), { x: 12.3, y: 7.12, w: 0.6, h: 0.38, fontSize: 10, bold: true, color: C.WHITE, align: "right", valign: "middle" });
}
function logo(s, x, y, h) {
  s.addImage({ path: path.join(HERE, "img", "sih-bulb.png"), x, y, w: h * 521 / 600, h });
  t(s, "SMART INDIA\nHACKATHON\n2026", { x: x + h * 0.9, y: y + 0.02, w: 1.3, h, fontSize: 10.5, bold: true, color: "4F5F6A", valign: "middle", lineSpacingMultiple: 0.95 });
}

// ---- flowchart helpers (coordinates in inches)
function node(s, shape, x, y, w, h, label, fillc, linec, fs = 11) {
  s.addText(label, { shape, x, y, w, h, fill: { color: fillc }, line: { color: linec, width: 1.25 },
    fontFace: F, fontSize: fs, color: C.INK, align: "center", valign: "middle", margin: 2, isTextBox: false });
}
function line(s, x1, y1, x2, y2, arrow = true, color = "404040", dash) {
  s.addShape(pres.shapes.LINE, { x: Math.min(x1, x2), y: Math.min(y1, y2), w: Math.abs(x2 - x1) || 0.0001, h: Math.abs(y2 - y1) || 0.0001,
    flipH: x2 < x1, flipV: y2 < y1, line: { color, width: 1.25, dashType: dash, endArrowType: arrow ? "triangle" : undefined } });
}
function tag(s, str, x, y) { t(s, str, { x, y, w: 0.5, h: 0.22, fontSize: 10, bold: true, color: C.INK }); }

// an icon in a circle with a bold label and a short line under it, centred on xc
function iconItem(s, name, xc, y, label, sub, o = {}) {
  const d = o.d || 0.55, w = o.w || 1.95;
  icon(s, name, xc - d / 2, y, d);
  t(s, label, { x: xc - w / 2, y: y + d + 0.05, w, h: 0.26, fontSize: o.fs || 11, bold: true, align: "center", color: C.INK });
  if (sub) t(s, sub, { x: xc - w / 2, y: y + d + 0.31, w, h: 0.46, fontSize: o.sfs || 9.5, align: "center", color: C.GREY });
}

(async () => {
  // ============ 1  Title page
  { const s = pres.addSlide(); s.background = { color: C.WHITE };
    t(s, "SMART INDIA HACKATHON 2026", { x: 0.5, y: 0.3, w: 10.3, h: 0.75, fontFace: HEAD, fontSize: 36, bold: true, color: C.NAVY, align: "center", valign: "middle" });
    t(s, "TITLE PAGE", { x: 0.5, y: 1.15, w: 7.6, h: 0.5, fontFace: HEAD, fontSize: 24, bold: true, align: "center", color: C.INK });
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

  // ============ 2  Proposed solution: the idea, how it works as a 6-step flow, the problem, what is unique
  { const s = pres.addSlide(); chrome(s, 2, "PROPOSED SOLUTION");
    t(s, [{ text: "IDEA: ", options: { color: C.BLUE, bold: true } }, { text: "TunnelScope – “Check how safe a VPN really is, just by watching its traffic”", options: { bold: true } }],
      { x: 0.5, y: 1.02, w: 12.3, h: 0.36, fontSize: 16 });
    t(s, "How it works", { x: 0.5, y: 1.48, w: 4, h: 0.3, fontSize: 14, bold: true, color: C.NAVY });
    const steps = [
      ["Input", "Saved capture (.pcap) or live network traffic"],
      ["Read", "Packet headers read with tshark; nothing decrypted"],
      ["Understand", "Each setting marked observed, inferred or unknown"],
      ["Judge", "Checked against RFC 8247, RFC 8221, DISA and India’s PQ report"],
      ["Report", "Risk score (noisy-OR formula), threats, plain-English report"],
      ["Fix", "Approved fix applied; a bad change is rolled back automatically"],
    ];
    const sw = 2.2, step = 2.026, sy = 1.84;
    steps.forEach(([name, desc], i) => {
      const x = 0.5 + i * step;
      s.addText(`${i + 1}  ${name}`, { shape: i === 0 ? pres.shapes.PENTAGON : pres.shapes.CHEVRON, x, y: sy, w: sw, h: 0.62,
        fill: { color: i === steps.length - 1 ? "548235" : C.BLUE }, line: { color: C.WHITE, width: 1 },
        fontFace: F, fontSize: 13, bold: true, color: C.WHITE, align: "center", valign: "middle", margin: 0 });
      t(s, desc, { x: x + 0.12, y: sy + 0.72, w: sw - 0.3, h: 0.7, fontSize: 10.5, align: "center", color: C.TEXT });
    });

    const by = 3.5, bh = 3.45, bw = 6.05;
    const box = (x, title, items) => {
      frame(s, x, by, bw, bh, C.WHITE);
      t(s, title, { x: x + 0.22, y: by + 0.2, w: bw - 0.4, h: 0.4, fontSize: 15, bold: true, color: C.NAVY, valign: "middle" });
      t(s, bullets(items), { x: x + 0.2, y: by + 0.75, w: bw - 0.4, h: bh - 0.95, fontSize: 13.5, paraSpaceAfter: 9 });
    };
    box(0.5, "The problem today", [
      ["Slow and manual: ", "an expert reads VPN packet captures by hand."],
      ["Post-quantum blind spot: ", "VPNs now negotiate quantum-safe keys, but packet tools cannot decode them yet, so a downgrade goes unnoticed."],
      ["Config is not reality: ", "existing tools such as Titania Nipper audit configuration files, not what the VPN actually negotiates."],
      ["Found but not fixed: ", "changing a live VPN is risky, so weak settings stay for years."],
    ]);
    box(6.78, "What makes it unique", [
      "Detects a post-quantum downgrade: safe option offered, weaker one used.",
      "Every verdict names the rule and the evidence behind it.",
      "Never guesses: what cannot be seen is marked “unknown”, never “safe”.",
      "Fixes real gateways over SSH: human approval, verification, automatic rollback.",
      "Written terms and risks are accepted before any live change.",
    ]);
  }

  // ============ 3  Technical approach: two flowcharts (checking, fixing) + technology logos
  { const s = pres.addSlide(); chrome(s, 3, "TECHNICAL APPROACH");
    const sub = (str, x, w) => t(s, str, { x, y: 1.02, w, h: 0.36, fontFace: HEAD, fontSize: 17, bold: true, color: C.INK });
    sub("Flow 1: Checking a VPN", 0.5, 6.0); sub("Flow 2: Fixing it safely", 6.95, 5.9);
    const P = pres.shapes.FLOWCHART_PROCESS, D = pres.shapes.FLOWCHART_DECISION, T = pres.shapes.FLOWCHART_TERMINATOR;
    line(s, 6.72, 1.1, 6.72, 5.95, false, "A6A6A6", "dash");

    // flow 1: "no" branches go right and rejoin
    { const cx = 2.6, NW = 3.1, X = cx - NW / 2, R = cx + NW / 2, SX = 4.5, SW = 2.1, DW = 2.5;
      const y = { start: 1.45, input: 1.9, read: 2.44, d1: 2.98, set: 3.74, d2: 4.3, rep: 5.06, end: 5.64 };
      node(s, T, cx - 0.75, y.start, 1.5, 0.3, "Start", C.TERM, C.TERM_L, 10.5);
      line(s, cx, y.start + 0.3, cx, y.input);
      node(s, pres.shapes.FLOWCHART_DATA, X, y.input, NW, 0.4, "Input: VPN traffic capture or live feed", C.PROC, C.PROC_L, 10);
      line(s, cx, y.input + 0.4, cx, y.read);
      node(s, P, X, y.read, NW, 0.4, "Read packet headers (nothing decrypted)", C.PROC, C.PROC_L, 10);
      line(s, cx, y.read + 0.4, cx, y.d1);
      node(s, D, cx - DW / 2, y.d1, DW, 0.62, "Handshake in the capture?", C.DEC, C.DEC_L, 9.5);
      line(s, cx, y.d1 + 0.62, cx, y.set); tag(s, "Yes", cx + 0.07, y.d1 + 0.58);
      line(s, cx + DW / 2, y.d1 + 0.31, SX, y.d1 + 0.31); tag(s, "No", cx + DW / 2 + 0.05, y.d1 + 0.07);
      node(s, P, SX, y.d1 + 0.1, SW, 0.42, "Mark “unknown” (never guessed)", C.SIDE, C.SIDE_L, 9.5);
      line(s, SX + SW / 2, y.d1 + 0.52, SX + SW / 2, y.set + 0.2, false); line(s, SX + SW / 2, y.set + 0.2, R, y.set + 0.2);
      node(s, P, X, y.set, NW, 0.4, "Read settings; AI finds traffic type and mode", C.PROC, C.PROC_L, 10);
      line(s, cx, y.set + 0.4, cx, y.d2);
      node(s, D, cx - DW / 2, y.d2, DW, 0.62, "Meets the standards?", C.DEC, C.DEC_L, 9.5);
      line(s, cx, y.d2 + 0.62, cx, y.rep); tag(s, "Yes", cx + 0.07, y.d2 + 0.58);
      line(s, cx + DW / 2, y.d2 + 0.31, SX, y.d2 + 0.31); tag(s, "No", cx + DW / 2 + 0.05, y.d2 + 0.07);
      node(s, P, SX, y.d2 + 0.06, SW, 0.5, "Flag threat, raise risk score (go to Flow 2)", C.SIDE, C.SIDE_L, 9.5);
      line(s, SX + SW / 2, y.d2 + 0.56, SX + SW / 2, y.rep + 0.21, false); line(s, SX + SW / 2, y.rep + 0.21, R, y.rep + 0.21);
      node(s, P, X, y.rep, NW, 0.42, "Report + dashboard", C.PROC, C.PROC_L, 10);
      line(s, cx, y.rep + 0.42, cx, y.end);
      node(s, T, cx - 0.75, y.end, 1.5, 0.3, "End", C.TERM, C.TERM_L, 10.5);
    }

    // flow 2: the fix loop; a failed check means automatic rollback
    { const cx = 8.85, NW = 3.3, X = cx - NW / 2, SX = 10.8, SW = 2.05, DW = 2.7;
      const y = { start: 1.45, draft: 1.9, check: 2.48, ok: 3.06, apply: 3.58, d: 4.16, keep: 5.08 };
      node(s, T, cx - 0.9, y.start, 1.8, 0.3, "A rule failed", C.TERM, C.TERM_L, 10.5);
      line(s, cx, y.start + 0.3, cx, y.draft);
      node(s, P, X, y.draft, NW, 0.44, "Draft a fix: written by us, or by AI", C.PROC, C.PROC_L, 10);
      line(s, cx, y.draft + 0.44, cx, y.check);
      node(s, P, X, y.check, NW, 0.44, "Safety checks + preview the change on a copy", C.PROC, C.PROC_L, 10);
      line(s, cx, y.check + 0.44, cx, y.ok);
      node(s, pres.shapes.FLOWCHART_MANUAL_OPERATION, X, y.ok, NW, 0.38, "A person approves the exact change", C.PROC, C.PROC_L, 10);
      line(s, cx, y.ok + 0.38, cx, y.apply);
      node(s, P, X, y.apply, NW, 0.44, "Save a backup, apply, capture traffic again", C.PROC, C.PROC_L, 10);
      line(s, cx, y.apply + 0.44, cx, y.d);
      node(s, D, cx - DW / 2, y.d, DW, 0.72, "Rule passes and nothing else broke?", C.DEC, C.DEC_L, 9.5);
      line(s, cx, y.d + 0.72, cx, y.keep); tag(s, "Yes", cx + 0.07, y.d + 0.68);
      node(s, T, cx - 0.9, y.keep, 1.8, 0.32, "Fix kept", C.TERM, C.TERM_L, 10.5);
      line(s, cx + DW / 2, y.d + 0.36, SX, y.d + 0.36); tag(s, "No", cx + DW / 2 + 0.03, y.d + 0.12);
      node(s, P, SX, y.d - 0.02, SW, 0.76, "Automatic rollback: old files restored byte for byte, checked again", "FBE5D6", "C55A11", 9.5);
    }

    // technology stack: a few logos, not everything
    const logos = JSON.parse(fs.readFileSync(path.join(HERE, "img", "logos", "logos.json"), "utf8"));
    const names = ["python", "sklearn", "wireshark", "strongswan", "react", "typescript", "docker", "linux"];
    const bx = 0.65, by = 6.1, bw = W - 1.3, bh = 0.92, lead = 1.75;
    frame(s, bx, by, bw, bh);
    t(s, "Technology stack", { x: bx + 0.15, y: by, w: lead, h: bh, fontSize: 13, bold: true, color: C.NAVY, valign: "middle" });
    const cell = (bw - lead - 0.2) / names.length;
    names.forEach((n, i) => {
      const cxl = bx + lead + 0.1 + cell * i + cell / 2;
      const lh = 0.42, lw = Math.min(lh * logos[n].ratio, cell - 0.2), hh = lw / logos[n].ratio;
      s.addImage({ path: LOGO(n), x: cxl - lw / 2, y: by + 0.08 + (lh - hh) / 2, w: lw, h: hh });
      t(s, logos[n].label, { x: cxl - cell / 2, y: by + 0.56, w: cell, h: 0.28, fontSize: 9.5, align: "center", color: C.TEXT });
    });
  }

  // ============ 4  Feasibility (a grid of cards) and viability (a tree), challenges below the tree
  { const s = pres.addSlide(); chrome(s, 4, "FEASIBILITY AND VIABILITY");
    const CARD = "F7F9FC", EDGE = "D6DEEA";
    const pill = (label, xc, y) => s.addText(label, { shape: pres.shapes.ROUNDED_RECTANGLE, x: xc - 1.05, y, w: 2.1, h: 0.36, rectRadius: 0.18,
      fill: { color: C.NAVY }, line: { color: C.NAVY, width: 0 }, fontFace: F, fontSize: 12.5, bold: true, color: C.WHITE, align: "center", valign: "middle", charSpacing: 2 });
    const card = (x, y, w, h) => s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: 0.07, fill: { color: CARD }, line: { color: EDGE, width: 0.75 } });

    // left: feasibility, eight cards in two columns
    pill("FEASIBILITY", 3.55, 1.05);
    const feas = [
      ["technical", "Technical", "Complete pipeline built and working: capture, verdict, fix."],
      ["speed", "Speed", "A saved capture is analysed in under 2 seconds on a laptop."],
      ["security", "Security", "Reads packet headers only; never decrypts VPN traffic."],
      ["operational", "Operational", "Works from a saved capture or a live feed; no login to the VPN devices."],
      ["economic", "Economic", "Built on free, open-source software; no licence fee."],
      ["rollback", "Safe fixing", "Backup first; every fix is verified or rolled back automatically."],
      ["scalability", "Scalability", "Scans folders of captures and collects findings from site sensors."],
      ["integration", "Integration", "Exports reports, a CycloneDX CBOM, syslog alerts and a local API."],
    ];
    const cw = 2.98, chh = 1.2, gx = 0.14, gy = 0.13, x0 = 0.5, y0 = 1.55;
    feas.forEach(([ic, label, text], i) => {
      const x = x0 + (i % 2) * (cw + gx), y = y0 + Math.floor(i / 2) * (chh + gy);
      card(x, y, cw, chh);
      icon(s, ic, x + 0.14, y + 0.16, 0.58);
      t(s, label, { x: x + 0.86, y: y + 0.13, w: cw - 0.98, h: 0.3, fontSize: 12.5, bold: true, color: C.INK });
      t(s, text, { x: x + 0.86, y: y + 0.44, w: cw - 0.98, h: 0.7, fontSize: 10, color: C.GREY });
    });
    line(s, 6.85, 1.1, 6.85, 6.95, false, "BFBFBF", "dash");

    // right: viability tree
    const rc = 9.95, kids = [7.75, 9.2, 10.65, 12.1];
    pill("VIABILITY", rc, 1.05);
    line(s, rc, 1.41, rc, 1.58, false, C.NAVY);
    line(s, kids[0], 1.58, kids[3], 1.58, false, C.NAVY);
    const tree = [
      ["cost", "Cost effective", "No licence fee; runs on existing laptops"],
      ["ease", "Easy to use", "Plain-English reports and a dashboard"],
      ["market", "Market need", "DST post-quantum migration from 2027"],
      ["adoption", "Adoption", "Works with strongSwan and tshark"],
    ];
    tree.forEach(([ic, label, sub], i) => {
      line(s, kids[i], 1.58, kids[i], 1.72, false, C.NAVY);
      iconItem(s, ic, kids[i], 1.72, label, sub, { d: 0.52, w: 1.42, fs: 10.5, sfs: 9 });
    });

    // right, below: challenges and how we handle them
    const cx0 = 7.1, cy0 = 3.3, cwid = 5.75, ch = 3.65;
    card(cx0, cy0, cwid, ch);
    t(s, "Challenges and how we handle them", { x: cx0 + 0.2, y: cy0 + 0.12, w: cwid - 0.4, h: 0.34, fontSize: 13, bold: true, color: C.NAVY });
    const risks = [
      ["encrypted", "Encrypted data: ", "part of the settings is hidden, so the few possible options are shown, clearly marked as a best guess."],
      ["dataset", "Limited datasets: ", "few labelled public IPsec traffic datasets exist, so we combine our own lab captures with the public ones we found."],
      ["lesson", "Lab vs real traffic: ", "our first model, trained only on lab traffic, failed on real VPN traffic; we retrained it on real public IPsec traffic."],
      ["privacy", "Data privacy: ", "fix drafting uses cloud AI APIs for now (limited resources); a client can run its own models on-site so nothing leaves."],
    ];
    risks.forEach(([ic, lead, rest], i) => {
      const ry = cy0 + 0.58 + i * 0.75;
      icon(s, ic, cx0 + 0.2, ry + 0.08, 0.46);
      t(s, [{ text: lead, options: { bold: true, color: C.INK } }, { text: rest }], { x: cx0 + 0.8, y: ry, w: cwid - 1.0, h: 0.62, fontSize: 10.5, valign: "middle" });
    });
  }

  // ============ 5  Impact and benefits: short headed sections, each with its source
  { const s = pres.addSlide(); chrome(s, 5, "IMPACT AND BENEFITS");
    const parts = [
      ["quantum", "Quantum-Safe Readiness",
        "India’s post-quantum Task Force (DST, Feb 2026) asks critical infrastructure to inventory its cryptography and assess quantum risk by 2027, and enterprises by 2028. TunnelScope does this for every VPN tunnel, and flags a downgrade to classical key exchange, a risk the report names."],
      ["compliance", "Regulatory Compliance",
        "DPDP Rules 2025, Rule 6(1)(a): personal data must be protected with encryption; in force from 13 May 2027, with penalties up to ₹250 crore for weak security safeguards. Each verdict cites the RFC, DISA or DST rule it checks, ready for CERT-In audits (internal audit every 6 months)."],
      ["efficiency", "Speed & Efficiency",
        "One capture is checked in about 1.6 seconds instead of an expert reading packets by hand. A weak setting is fixed after one approval, and a bad change is undone automatically."],
      ["cbom", "Supply-Chain Assurance",
        "The Task Force recommends mandatory Cryptographic Bills of Materials (CBOM) from vendors from FY 2027-28. TunnelScope exports a CycloneDX 1.6 CBOM for every capture."],
      ["afford", "Affordability & Accessibility",
        "Built only on free, open-source software: no licence fee, runs on one laptop, and explains every result in plain English for non-experts."],
    ];
    parts.forEach(([ic, head, body], i) => {
      const y = 1.12 + i * 1.18;
      icon(s, ic, 0.7, y + 0.04, 0.52);
      t(s, head, { x: 1.45, y, w: 11.3, h: 0.32, fontSize: 15, bold: true, color: C.INK });
      t(s, body, { x: 1.45, y: y + 0.34, w: 11.3, h: 0.72, fontSize: 12.5, color: C.TEXT });
    });
  }

  // ============ 6  Research and references
  { const s = pres.addSlide(); chrome(s, 6, "RESEARCH AND REFERENCES");
    const L = (label, url) => ({ text: label, options: { hyperlink: { url }, color: C.LINK, bullet: { code: "27A4" }, breakLine: true } });
    const P = (label) => ({ text: label, options: { bullet: { code: "27A4" }, breakLine: true } });
    const Hd = (label) => ({ text: label, options: { bold: true, fontSize: 15, color: C.NAVY, breakLine: true } });
    const gap = () => ({ text: " ", options: { fontSize: 8, breakLine: true } });
    const colA = [
      Hd("Security standards"),
      L("RFC 7296 – IKEv2 protocol", "https://www.rfc-editor.org/rfc/rfc7296.html"),
      L("RFC 4303 – ESP protocol", "https://datatracker.ietf.org/doc/html/rfc4303"),
      L("RFC 8221 – ESP/AH algorithm rules", "https://www.rfc-editor.org/rfc/rfc8221"),
      L("RFC 8247 – IKEv2 algorithm rules", "https://www.rfc-editor.org/rfc/rfc8247.html"),
      L("RFC 9370 – post-quantum IKEv2", "https://www.rfc-editor.org/info/rfc9370/"),
      L("RFC 9395 – IKEv1 deprecated", "https://datatracker.ietf.org/doc/rfc9395/"),
      L("NIST SP 800-77r1 – IPsec VPN guide", "https://csrc.nist.gov/pubs/sp/800/77/r1/final"),
      P("DISA VPN Security Requirements Guide V2R6"),
    ];
    const colB = [
      Hd("Policy (India)"),
      L("DST post-quantum Task Force, 2026", "https://dst.gov.in/sites/default/files/Report_TaskForce_PQMigration_4Feb26%20(v1).pdf"),
      P("DPDP Rules 2025 – G.S.R. 846(E)"),
      L("CERT-In guidelines for Govt. entities, 2023", "https://www.pib.gov.in/PressReleaseIframePage.aspx?PRID=1936470"),
      gap(),
      Hd("Threat data"),
      L("NIST National Vulnerability Database (NVD)", "https://nvd.nist.gov/developers/vulnerabilities"),
      L("CISA Known Exploited Vulnerabilities (KEV)", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
      L("ENISA EU Vulnerability Database (EUVD)", "https://euvd.enisa.europa.eu"),
      L("MITRE ATT&CK", "https://attack.mitre.org"),
    ];
    const colC = [
      Hd("Datasets (real traffic)"),
      L("USBVPN2022 – real IPsec tunnels", "https://zenodo.org/records/7301756"),
      L("VNAT – MIT Lincoln Laboratory", "https://www.ll.mit.edu/r-d/datasets/vpnnonvpn-network-application-traffic-dataset-vnat"),
      L("WireGuard traffic flows", "https://zenodo.org/records/18945858"),
      gap(),
      Hd("Research gap"),
      L("Wireshark #21072 – no post-quantum IKEv2", "https://gitlab.com/wireshark/wireshark/-/work_items/21072"),
      L("strongSwan 6.0 – ships ML-KEM", "https://strongswan.org/blog/2024/12/03/strongswan-6.0.0-released.html"),
      gap(),
      Hd("Our work"),
      VIDEO_URL ? L("Demo video", VIDEO_URL) : Object.assign(marker("demo video link"), {}),
    ];
    if (!VIDEO_URL) colC[colC.length - 1].options = Object.assign({ bullet: { code: "27A4" } }, colC[colC.length - 1].options, { breakLine: true });
    colC.push(REPO_URL ? L("Source code", REPO_URL) : marker("code link (only if public)"));
    if (!REPO_URL) colC[colC.length - 1].options.bullet = { code: "27A4" };
    for (const col of [colA, colB, colC]) { col[col.length - 1].options = Object.assign({}, col[col.length - 1].options); delete col[col.length - 1].options.breakLine; }
    const cw = 3.95;
    [colA, colB, colC].forEach((col, i) => t(s, col, { x: 0.55 + i * (cw + 0.2), y: 1.25, w: cw, h: 5.7, fontSize: 13, paraSpaceAfter: 9 }));
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
