// TunnelScope judge deck (10 slides), built in the website's own design language (T-092).
//   node build/sih/deck/build_deck.js [out.pptx]
// Palette / type from fleet-dashboard/DESIGN.md: near-black surfaces, hairlines not shadows, ONE violet
// accent, green/yellow/red only for status. Fonts: Geist (text), Geist Mono (data), Kufica Bold (wordmark only).
const pptxgen = require("pptxgenjs");
const sharp = require("sharp");
const fs = require("fs");
const path = require("path");
const HERE = __dirname;
const OUT = process.argv[2] || path.join(process.env.HOME, "Downloads", "TunnelScope_SIH26160_Judge_Deck.pptx");

const C = { BG: "08080B", SURF: "101014", RAISED: "16161B", SEC: "1C1C22", HAIR: "27272E", INK: "F3F3F6", MUTED: "9C9CA8",
  FAINT: "66666F", SILVER: "C7CAD1", VIOLET: "8B5CF6", POS: "22C55E", WARN: "F2B33D", NEG: "EF4444" };
const HEAD = "Geist", MONO = "Geist Mono", DISPLAY = "Kufica Bold";
const W = 13.333, H = 7.5, M = 0.6, CW = W - 2 * M;

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE";
pres.title = "TunnelScope: SIH26160 judge deck";
pres.author = "Team Think2Thrive";
let n = 0;

// ---------------------------------------------------------------- helpers (fresh option objects every call)
function text(s, str, o) {
  s.addText(str, Object.assign({ fontFace: HEAD, fontSize: 14, color: C.INK, isTextBox: true, margin: 0, valign: "top" }, o));
}
function panel(s, x, y, w, h, o = {}) {
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: o.r ?? 0.14,
    fill: { color: o.fill ?? C.SURF, transparency: o.ft ?? 0 }, line: { color: o.line ?? C.HAIR, width: o.lw ?? 1, dashType: o.dash ?? "solid" } });
}
function chip(s, label, x, y, w, kind = "violet", h = 0.3, fs = 10) {
  const map = { violet: [C.VIOLET, C.VIOLET, 84], silver: [C.SILVER, C.SILVER, 88], pos: [C.POS, C.POS, 86], warn: [C.WARN, C.WARN, 86],
    neg: [C.NEG, C.NEG, 86], faint: [C.FAINT, C.MUTED, 100] };
  const [fillc, txt, tr] = map[kind];
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: h / 2, fill: { color: fillc, transparency: tr }, line: { color: kind === "faint" ? C.HAIR : fillc, width: 0.75, transparency: kind === "faint" ? 0 : 55 } });
  text(s, label, { x, y, w, h, fontFace: MONO, fontSize: fs, color: txt, align: "center", valign: "middle", charSpacing: 1 });
}
function arrow(s, x1, y1, x2, y2, color = C.MUTED, dash = "solid") {
  s.addShape(pres.shapes.LINE, { x: Math.min(x1, x2), y: Math.min(y1, y2), w: Math.abs(x2 - x1), h: Math.abs(y2 - y1),
    flipH: x2 < x1, flipV: y2 < y1, line: { color, width: 1.5, dashType: dash, endArrowType: "triangle" } });
}
function base(s, num, eyebrow, title) {
  s.background = { color: C.BG };
  text(s, eyebrow.toUpperCase(), { x: M, y: 0.42, w: 9, h: 0.28, fontFace: MONO, fontSize: 11, color: C.VIOLET, charSpacing: 3 });
  text(s, title, { x: M, y: 0.72, w: CW, h: 0.75, fontSize: 30, bold: true, color: C.INK });
  text(s, "TUNNELSCOPE  ·  SIH26160", { x: M, y: 7.03, w: 6, h: 0.25, fontFace: MONO, fontSize: 9, color: C.FAINT, charSpacing: 2 });
  text(s, String(num).padStart(2, "0"), { x: W - M - 1, y: 7.03, w: 1, h: 0.25, fontFace: MONO, fontSize: 9, color: C.FAINT, align: "right" });
}
// the product mark, extruded into depth: concentric rounded squares receding to a point
function tunnel(s, cx, cy, size, rings = 8) {
  for (let i = 0; i < rings; i++) {
    const k = Math.pow(0.7, i), sz = size * k, off = i * size * 0.012;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: cx - sz / 2, y: cy - sz / 2 + off, w: sz, h: sz, rectRadius: sz * 0.22,
      fill: { color: C.BG, transparency: 100 }, line: { color: C.VIOLET, width: Math.max(0.75, 2.4 - i * 0.22), transparency: Math.min(88, 18 + i * 9) } });
  }
  const core = size * Math.pow(0.7, rings) * 1.6 + 0.05;
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: cx - core / 2, y: cy - core / 2 + rings * size * 0.012, w: core, h: core, rectRadius: core * 0.3, fill: { color: C.VIOLET }, line: { color: C.VIOLET, width: 0.5 } });
}
async function rounded(file, w = 1700, r = 30) {
  const out = path.join(require("os").tmpdir(), "ts_" + path.basename(file, ".jpg") + ".png");
  const img = sharp(path.join(HERE, "img", file)).resize({ width: w });
  const meta = await img.clone().toBuffer({ resolveWithObject: true });
  const h = meta.info.height;
  const mask = Buffer.from(`<svg width="${w}" height="${h}"><rect width="${w}" height="${h}" rx="${r}" ry="${r}"/></svg>`);
  await sharp(meta.data).composite([{ input: mask, blend: "dest-in" }]).png({ compressionLevel: 9 }).toFile(out);
  return { path: out, ratio: h / w };
}

(async () => {
  const shots = {}; for (const k of ["fleet", "threats", "traffic", "explained"]) shots[k] = await rounded(k + ".jpg");
  const mix = JSON.parse(fs.readFileSync(path.join(HERE, "sizemix.json")));

  // ============ 1  Title
  { const s = pres.addSlide(); s.background = { color: C.BG };
    tunnel(s, 10.55, 3.75, 5.2, 9);
    text(s, "SMART INDIA HACKATHON 2026  ·  PS SIH26160  ·  NTRO", { x: M, y: 1.2, w: 6.9, h: 0.3, fontFace: MONO, fontSize: 11, color: C.VIOLET, charSpacing: 3 });
    text(s, "TUNNELSCOPE", { x: M, y: 1.95, w: 8, h: 1.1, fontFace: DISPLAY, fontSize: 60, color: C.SILVER });
    text(s, "IPsec and post-quantum posture, from the wire", { x: M, y: 3.15, w: 6.6, h: 0.95, fontSize: 24, bold: true, color: C.INK, lineSpacingMultiple: 1.05 });
    text(s, "AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework", { x: M, y: 4.3, w: 6.6, h: 0.7, fontSize: 15, color: C.MUTED });
    chip(s, "TEAM THINK2THRIVE", M, 5.4, 2.3, "violet"); chip(s, "BLOCKCHAIN & CYBERSECURITY", M + 2.45, 5.4, 3.3, "faint");
    text(s, "Never claim more than the evidence shows.", { x: M, y: 6.3, w: 7, h: 0.4, fontSize: 14, color: C.MUTED });
    s.addNotes("Open with the product name and the one-line promise. TunnelScope reads an IPsec VPN from the outside, says how it is configured, how secure that is, and what it cannot know. The rings on the right are our product mark: a tunnel receding into depth.");
  }


  const frame = (s, shot, x, y, w) => { const h = w * shot.ratio; panel(s, x - 0.05, y - 0.05, w + 0.1, h + 0.1, { fill: C.SURF, r: 0.16 }); s.addImage({ path: shot.path, x, y, w, h }); return h; };
  const dot = (s, x, y, d = 0.16) => s.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color: C.VIOLET }, line: { color: C.VIOLET, width: 0.5 } });

  // ============ 2  The problem, and what the brief asks for
  { const s = pres.addSlide(); base(s, 2, "The problem", "A VPN is only as secure as its settings");
    const pts = ["IPsec VPNs link offices, data centres and the cloud over the public internet.", "How secure one is depends on choices: cipher, key exchange, mode, authentication.",
      "A weak or outdated choice quietly weakens it, and nothing looks broken.", "Wireshark shows the packets, but an expert must read them by hand."];
    pts.forEach((p, i) => { const y = 1.75 + i * 0.93;
      s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: M, y, w: 0.42, h: 0.42, rectRadius: 0.21, fill: { color: C.VIOLET, transparency: 84 }, line: { color: C.VIOLET, width: 0.75, transparency: 50 } });
      text(s, String(i + 1), { x: M, y, w: 0.42, h: 0.42, fontFace: MONO, fontSize: 12, bold: true, color: C.VIOLET, align: "center", valign: "middle" });
      text(s, p, { x: M + 0.65, y: y - 0.03, w: 5.0, h: 0.8, fontSize: 14.5, color: C.INK, lineSpacingMultiple: 1.08 }); });
    panel(s, 6.85, 1.7, 5.88, 3.78);
    panel(s, 7.1, 2.0, 1.55, 0.95, { fill: C.SEC }); text(s, "Head office", { x: 7.1, y: 2.0, w: 1.55, h: 0.95, fontSize: 13, bold: true, align: "center", valign: "middle" });
    panel(s, 10.95, 2.0, 1.55, 0.95, { fill: C.SEC }); text(s, "Branch or cloud", { x: 10.95, y: 2.0, w: 1.55, h: 0.95, fontSize: 13, bold: true, align: "center", valign: "middle" });
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 8.65, y: 2.3, w: 2.3, h: 0.35, rectRadius: 0.17, fill: { color: C.VIOLET, transparency: 82 }, line: { color: C.VIOLET, width: 1.25 } });
    text(s, "IPsec tunnel", { x: 8.65, y: 2.3, w: 2.3, h: 0.35, fontFace: MONO, fontSize: 11, color: C.VIOLET, align: "center", valign: "middle" });
    text(s, "the public internet", { x: 8.65, y: 2.7, w: 2.3, h: 0.28, fontSize: 11, color: C.FAINT, align: "center" });
    s.addShape(pres.shapes.OVAL, { x: 9.55, y: 3.5, w: 0.38, h: 0.38, fill: { color: C.NEG, transparency: 82 }, line: { color: C.NEG, width: 1 } });
    text(s, "Observer", { x: 9.05, y: 3.93, w: 1.4, h: 0.28, fontSize: 12, bold: true, align: "center", color: C.NEG });
    arrow(s, 9.74, 3.47, 9.74, 2.98, C.NEG, "dash");
    text(s, "sees the packets, cannot read them", { x: 7.3, y: 4.25, w: 5.2, h: 0.28, fontSize: 12, color: C.MUTED, align: "center" });
    { let cx = 7.1; [["Cipher", 0.95], ["Key exchange", 1.5], ["Mode", 0.8], ["Authentication", 1.6]].forEach(([t, w]) => { chip(s, t, cx, 4.62, w, "silver", 0.32, 10); cx += w + 0.14; }); }
    text(s, "Which of these is weak? From outside, how would you know?", { x: 7.1, y: 5.05, w: 5.4, h: 0.28, fontSize: 11.5, color: C.MUTED });
    // the brief
    text(s, "THE BRIEF ASKS FOR", { x: M, y: 5.68, w: 6, h: 0.25, fontFace: MONO, fontSize: 10, color: C.FAINT, charSpacing: 2 });
    const br = [["a", "Lab", "many VPN configurations"], ["b", "Capture", "IKE, ESP, AH, live"], ["c", "Identify (AI)", "protocol, mode, traffic type"], ["d", "Assess", "strength, replay, PFS"], ["e", "Report", "risk score, threat matrix"]];
    const cw = (CW - 4 * 0.15) / 5;
    br.forEach((b, i) => { const x = M + i * (cw + 0.15); panel(s, x, 5.98, cw, 0.9);
      text(s, b[0], { x: x + 0.18, y: 6.05, w: 0.4, h: 0.4, fontFace: MONO, fontSize: 20, bold: true, color: C.VIOLET });
      text(s, b[1], { x: x + 0.62, y: 6.08, w: cw - 0.75, h: 0.3, fontSize: 13.5, bold: true }); text(s, b[2], { x: x + 0.18, y: 6.48, w: cw - 0.3, h: 0.3, fontSize: 11, color: C.MUTED }); });
    s.addNotes("About 45 seconds. Two sites talk through an encrypted tunnel over the public internet; an observer on the path sees packets but cannot read them. Whether the tunnel is really secure depends on the settings someone chose, and wrong settings break nothing visibly, so they persist. Today an expert reads packets by hand. The brief asks for an AI platform that does this automatically: a lab (a), captures (b), AI identification (c), security assessment (d) and reports (e), plus a working prototype, dashboard, video and dataset.");
  }

  // ============ 3  A tunnel hides most of itself
  { const s = pres.addSlide(); base(s, 3, "Why it is hard", "A tunnel hides most of itself");
    const ph = [["1", "IKE_SA_INIT", "READABLE", "violet", "Algorithms offered and chosen, the key-exchange group, post-quantum support"],
      ["2", "IKE_AUTH", "ENCRYPTED", "faint", "Who authenticated and how. The tunnel's parameters are negotiated in here"],
      ["3", "ESP data", "SHAPE ONLY", "silver", "Content is hidden. Packet sizes, timing and direction remain visible"],
      ["4", "Rekey", "PARTLY", "warn", "Whether a fresh key exchange happened shows up as a size difference"]];
    const bw = (CW - 3 * 0.55) / 4;
    ph.forEach((p, i) => { const x = M + i * (bw + 0.55); panel(s, x, 1.85, bw, 3.2);
      text(s, "PHASE " + p[0], { x: x + 0.22, y: 2.05, w: bw - 0.4, h: 0.25, fontFace: MONO, fontSize: 10, color: C.FAINT, charSpacing: 2 });
      text(s, p[1], { x: x + 0.22, y: 2.38, w: bw - 0.4, h: 0.45, fontFace: MONO, fontSize: 18, bold: true });
      chip(s, p[2], x + 0.22, 3.0, 1.5, p[3], 0.3, 10);
      text(s, p[4], { x: x + 0.22, y: 3.5, w: bw - 0.44, h: 1.45, fontSize: 13.5, color: C.MUTED, lineSpacingMultiple: 1.1 });
      if (i < 3) arrow(s, x + bw + 0.06, 3.45, x + bw + 0.49, 3.45, C.FAINT); });
    panel(s, M, 5.4, CW, 1.4, { fill: C.VIOLET, ft: 90, line: C.VIOLET });
    text(s, "So a tool must know exactly what it can and cannot claim.", { x: M + 0.35, y: 5.55, w: CW - 0.7, h: 0.5, fontSize: 21, bold: true });
    text(s, "Much of what the brief asks for is encrypted by design. A tool that guesses to fill the gaps gives false assurance, the worst failure a security tool can have. This shaped everything we built.", { x: M + 0.35, y: 6.1, w: CW - 0.7, h: 0.65, fontSize: 13.5, color: C.MUTED });
    s.addNotes("About 45 seconds. This is the key insight of the project. An IPsec connection has phases, and only the first handshake message is readable. After that everything is encrypted, though packet sizes and timing still leak. So many things the brief asks for cannot be read from outside. The design question was how to be useful without guessing.");
  }

  // ============ 4  The gap and our problem statement
  { const s = pres.addSlide(); base(s, 4, "The gap and our framing", "Existing tools stop short of a verdict");
    const tools = [["Wireshark, tshark", "Parses every packet. Never judges it."], ["Zeek, Suricata", "Logs fields, fires alerts. No cited standard."], ["ike-scan and wrappers", "Probe a gateway actively. Not passive."], ["Other SIH26160 repos", "Score and classify. None we read publishes a reproducible evaluation."]];
    const tw = (CW - 3 * 0.2) / 4;
    tools.forEach((t, i) => { const x = M + i * (tw + 0.2); panel(s, x, 1.75, tw, 1.3);
      text(s, t[0], { x: x + 0.2, y: 1.88, w: tw - 0.4, h: 0.32, fontSize: 14, bold: true }); text(s, t[1], { x: x + 0.2, y: 2.25, w: tw - 0.4, h: 0.75, fontSize: 11.5, color: C.MUTED, lineSpacingMultiple: 1.06 }); });
    arrow(s, W / 2, 3.1, W / 2, 3.42, C.VIOLET);
    panel(s, M, 3.5, CW, 3.3, { fill: C.VIOLET, ft: 90, line: C.VIOLET, lw: 1.25 });
    text(s, "OUR PROBLEM STATEMENT", { x: M + 0.35, y: 3.62, w: 6, h: 0.28, fontFace: MONO, fontSize: 10.5, color: C.VIOLET, charSpacing: 3 });
    text(s, "Given only what a passive observer can see of an IPsec tunnel, automatically determine how it is configured, judge how secure that is against named standards, say exactly what cannot be known, and turn it into actions an analyst can take.",
      { x: M + 0.35, y: 3.95, w: CW - 0.7, h: 1.2, fontSize: 16.5, bold: true, lineSpacingMultiple: 1.08 });
    const five = [["Identify", "read the plaintext handshake and headers"], ["Infer, with limits", "traffic type and mode, with a stated confidence"], ["Assess", "against written standards, every verdict cited"], ["Stay honest", "every fact labelled; unknown is never safe"], ["Act", "threat matrix, risk score, plain-English reports"]];
    const fw = (CW - 0.7 - 4 * 0.15) / 5;
    five.forEach((f, i) => { const x = M + 0.35 + i * (fw + 0.15); panel(s, x, 5.3, fw, 1.35, { fill: C.BG, ft: 30 });
      text(s, [{ text: (i + 1) + "  ", options: { fontFace: MONO, color: C.VIOLET, bold: true } }, { text: f[0], options: { bold: true } }], { x: x + 0.15, y: 5.4, w: fw - 0.3, h: 0.3, fontSize: 12.5 });
      text(s, f[1], { x: x + 0.15, y: 5.78, w: fw - 0.3, h: 0.8, fontSize: 10.5, color: C.MUTED, lineSpacingMultiple: 1.06 }); });
    s.addNotes("About 60 seconds. Wireshark and Zeek read packets, Suricata alerts, ike-scan probes actively, and the other hackathon repos we read score and classify without publishing a reproducible evaluation. The missing layer is a passive assessment that cites its standard and is honest about limits. Read our problem statement slowly; it is the whole project, and the five boxes are its five sub-problems.");
  }

  // ============ 5  One rule, one pipeline
  { const s = pres.addSlide(); base(s, 5, "The solution", "One rule and one pipeline");
    const st = [["Capture", "pcap file or live stream", "tcpdump, dumpcap"], ["Read", "tshark reads IKE, ESP and AH headers", "tshark"], ["Evidence", "labelled findings, each with its packet", "Python"], ["Judge", "5 written baselines, cited verdicts", "YAML rules"], ["Score", "12 threats, risk score, confidence", "scikit-learn"], ["Deliver", "dashboard, reports, CBOM, lab fixes", "React, TypeScript"]];
    const bw = 1.72, gap = (CW - 6 * bw) / 5;
    st.forEach((b, i) => { const x = M + i * (bw + gap); const hi = i === 2 || i === 4;
      panel(s, x, 1.75, bw, 1.8, { fill: hi ? C.VIOLET : C.SURF, ft: hi ? 90 : 0, line: hi ? C.VIOLET : C.HAIR });
      text(s, String(i + 1).padStart(2, "0"), { x: x + 0.16, y: 1.85, w: 0.6, h: 0.22, fontFace: MONO, fontSize: 9.5, color: C.FAINT });
      text(s, b[0], { x: x + 0.16, y: 2.1, w: bw - 0.3, h: 0.35, fontSize: 16, bold: true });
      text(s, b[1], { x: x + 0.16, y: 2.5, w: bw - 0.3, h: 0.7, fontSize: 11, color: C.MUTED, lineSpacingMultiple: 1.06 });
      text(s, b[2], { x: x + 0.16, y: 3.22, w: bw - 0.3, h: 0.24, fontFace: MONO, fontSize: 9, color: C.VIOLET });
      if (i < 5) arrow(s, x + bw + 0.03, 2.5, x + bw + gap - 0.03, 2.5, C.FAINT); });
    text(s, "THE ONE RULE: EVERY FACT CARRIES A LABEL", { x: M, y: 3.75, w: 8, h: 0.25, fontFace: MONO, fontSize: 10, color: C.FAINT, charSpacing: 2 });
    const rows = [["OBSERVED", "violet", "Read straight from the packets", "IKE cipher: AES-CBC-256"], ["INFERRED", "silver", "Deduced, with a confidence", "Traffic: web, 91%"], ["MEASURED", "violet", "Computed from the traffic", "Leakage: 4.0 bits/packet"],
      ["UNKNOWN", "faint", "Not in this capture", "Rekey interval, no rekey seen"], ["NOT OBSERVABLE", "faint", "Cannot be seen from outside", "How peers authenticated"]];
    const cw = (CW - 4 * 0.15) / 5;
    rows.forEach((r, i) => { const x = M + i * (cw + 0.15); panel(s, x, 4.05, cw, 1.65);
      chip(s, r[0], x + 0.15, 4.2, cw - 0.3, r[1], 0.28, 9.5);
      text(s, r[2], { x: x + 0.15, y: 4.6, w: cw - 0.3, h: 0.55, fontSize: 12, bold: true, lineSpacingMultiple: 1.04 });
      text(s, r[3], { x: x + 0.15, y: 5.17, w: cw - 0.3, h: 0.45, fontFace: MONO, fontSize: 9.5, color: C.MUTED }); });
    panel(s, M, 5.92, CW, 0.88, { fill: C.VIOLET, ft: 90, line: C.VIOLET, lw: 1.25 });
    text(s, [{ text: "Unknown is never scored as safe.  ", options: { bold: true, fontSize: 18 } }, { text: "Fully offline, never decrypts, and every verdict names its rule.", options: { color: C.MUTED, fontSize: 14 } }], { x: M + 0.35, y: 5.92, w: CW - 0.7, h: 0.88, valign: "middle" });
    s.addNotes("About 60 seconds. Under each box is what it is built with (Python, tshark, scikit-learn, YAML rules, React and TypeScript). Walk left to right. A capture or live stream goes in; tshark reads only headers; we turn packets into labelled findings, judge them against five written baselines, then score them into a threat matrix and risk score. The row of five labels is the principle the whole tool is built on: observed and measured come straight from the capture, inferred carries a confidence, and unknown and not observable are real answers that are never quietly turned into a pass. This is enforced in code: an unknown finding cannot carry a value.");
  }

  // ============ 6  Standards and the AI
  { const s = pres.addSlide(); base(s, 6, "Rules and models", "Judged by standards, read by models we trained");
    panel(s, M, 1.75, 5.7, 4.35);
    text(s, "FIVE WRITTEN BASELINES", { x: M + 0.28, y: 1.92, w: 5, h: 0.25, fontFace: MONO, fontSize: 10, color: C.VIOLET, charSpacing: 3 });
    const rb = [["DISA VPN SRG", "US DoD requirements for VPN gateways"], ["RFC 8247", "which IKEv2 algorithms to use or avoid"], ["RFC 8221 / 4303", "ESP and AH algorithms, replay counters"], ["DST / NQM post-quantum", "India's post-quantum migration baseline"], ["CVE-2026-78135", "a pre-authentication attack pattern"]];
    rb.forEach((r, i) => { const y = 2.3 + i * 0.66; dot(s, M + 0.28, y + 0.09);
      text(s, r[0], { x: M + 0.6, y, w: 2.6, h: 0.4, fontSize: 13, bold: true, valign: "middle" }); text(s, r[1], { x: M + 3.3, y, w: 2.25, h: 0.4, fontSize: 10.5, color: C.MUTED, valign: "middle", lineSpacingMultiple: 1.0 }); });
    text(s, "Indian context: DPDP Rules 2025 and CERT-In are shown as evidence, never as a compliance verdict.", { x: M + 0.28, y: 5.55, w: 5.2, h: 0.5, fontSize: 11, color: C.FAINT, lineSpacingMultiple: 1.05 });
    const m = [["Traffic type", "Random Forest", "Sizes, timing and direction of 2-second slices give 1 of 8 types and a confidence, or uncertain."], ["Mixed traffic", "Random Forest", "Spots tunnels carrying several kinds of traffic at once."],
      ["Tunnel or transport", "Random Forest", "Separates the two modes where packets allow. Abstains otherwise."], ["Change detection", "Isolation Forest", "Learns each tunnel's normal, flags downgrades."]];
    const mw = 3.0, mh = 2.05;
    m.forEach((c, i) => { const x = 6.55 + (i % 2) * (mw + 0.18), y = 1.75 + Math.floor(i / 2) * (mh + 0.25); panel(s, x, y, mw, mh);
      text(s, String(i + 1), { x: x + 0.2, y: y + 0.12, w: 0.4, h: 0.4, fontFace: MONO, fontSize: 18, bold: true, color: C.VIOLET });
      text(s, c[0], { x: x + 0.6, y: y + 0.16, w: mw - 0.75, h: 0.34, fontSize: 14, bold: true });
      chip(s, c[1].toUpperCase(), x + 0.2, y + 0.62, 1.55, "silver", 0.25, 8.5);
      text(s, c[2], { x: x + 0.2, y: y + 1.0, w: mw - 0.4, h: 1.0, fontSize: 11, color: C.MUTED, lineSpacingMultiple: 1.06 }); });
    panel(s, M, 6.3, CW, 0.55, { fill: C.VIOLET, ft: 90, line: C.VIOLET });
    text(s, [{ text: "All four trained by us; the traffic model also on real VPN traffic (MIT). ", options: { bold: true } }, { text: "No outside model decides a verdict; an offline one only rewords.", options: { color: C.MUTED } }], { x: M + 0.3, y: 6.3, w: CW - 0.6, h: 0.55, fontSize: 11.5, valign: "middle" });
    s.addNotes("About 60 seconds. Left: the five written baselines behind every verdict, and the Indian regulations shown as context only, because they require encryption without naming algorithms, so a capture can support an audit but never prove compliance. Right: the four models. Be direct about where the AI is: fields in the plaintext handshake are read exactly, because guessing them would be worse. AI is used where the wire is silent: what kind of traffic is inside, whether several kinds are mixed, which mode, and whether the tunnel changed. All four are standard Random Forest or Isolation Forest models trained by us on our own captures; the traffic-type model is also trained on real VPN traffic recorded by MIT Lincoln Laboratory (the public VNAT dataset: video, VoIP, chat, SSH and file transfer inside real OpenVPN tunnels). No pretrained or third-party model decides anything. An optional language model that runs offline on the laptop may reword the explanations; we also tested it for drafting fixes, it failed our pre-registered test, so that stays switched off.");
  }

  // ============ 7  Encryption hides content, not shape (chart)
  { const s = pres.addSlide(); base(s, 7, "How the AI reads encrypted traffic", "Encryption hides content, not shape");
    panel(s, M, 1.75, 7.7, 5.05);
    const cls = [["icmp", "ICMP (ping)"], ["voip", "VoIP call"], ["interactive", "Interactive (SSH)"], ["messaging", "Messaging"], ["email", "E-mail"], ["web", "Web"], ["video", "Video"], ["bulk", "File transfer"]];
    const bins = ["under 128 B", "128-256 B", "256-512 B", "512-1024 B", "over 1024 B"];
    const data = bins.map((b, bi) => ({ name: b, labels: cls.map((c) => c[1]), values: cls.map((c) => mix[c[0]][bi]) }));
    text(s, "Share of packets by size, per traffic type", { x: M + 0.3, y: 1.9, w: 7, h: 0.3, fontSize: 12.5, bold: true });
    s.addChart(pres.charts.BAR, data, { x: M + 0.15, y: 2.2, w: 7.4, h: 4.5, barDir: "bar", barGrouping: "percentStacked", barGapWidthPct: 40,
      chartColors: ["2E2160", "5B3FB0", C.VIOLET, "B8A0FA", "E9E2FD"], catAxisOrientation: "maxMin", catAxisLabelColor: C.INK, catAxisLabelFontFace: HEAD, catAxisLabelFontSize: 12,
      valAxisLabelColor: C.MUTED, valAxisLabelFontSize: 10, valAxisLabelFontFace: MONO, valAxisLabelFormatCode: "0%", valGridLine: { color: C.HAIR, size: 0.5 }, catGridLine: { style: "none" },
      showLegend: true, legendPos: "b", legendColor: C.MUTED, legendFontSize: 10.5, legendFontFace: HEAD, plotArea: { fill: { color: C.SURF } }, chartArea: { fill: { color: C.SURF } } });
    const pts = [["Encryption hides the content, not the shape.", "A VoIP call sends one packet size every 20 ms. A file transfer sends full-size packets. An SSH session sends tiny ones."],
      ["Every 2 seconds becomes 31 numbers of shape.", "How many packets, how big, how evenly spaced, and in which direction."], ["The model turns them into a type and a confidence.", "Or says uncertain, when the numbers fit nothing it knows."]];
    pts.forEach((p, i) => { const y = 1.8 + i * 1.6; text(s, p[0], { x: 8.6, y, w: 4.13, h: 0.65, fontSize: 15, bold: true, lineSpacingMultiple: 1.0 });
      text(s, p[1], { x: 8.6, y: y + 0.68, w: 4.13, h: 0.85, fontSize: 12.5, color: C.MUTED, lineSpacingMultiple: 1.08 }); });
    text(s, "Data: 469 windows from our clean AES-GCM sessions. Trained on 9,369 windows, 4,702 of them real VPN traffic (MIT).", { x: 8.6, y: 6.4, w: 4.13, h: 0.45, fontSize: 10, color: C.FAINT, lineSpacingMultiple: 1.05 });
    s.addNotes("About 60 seconds. This chart is real data from our training set, not an illustration. Each bar is one traffic type and the colours are packet-size bands. A VoIP call sits entirely in one band, ping in another, an SSH session is mostly tiny packets, and web, video and file transfer mix small acknowledgements with full-size packets and are told apart by timing and direction. That is why an encrypted tunnel still leaks what kind of traffic is inside, and why the model can predict it. Every 2-second slice becomes 31 numbers; the model returns a type with a confidence, or says uncertain.");
  }

  // ============ 8  The product
  { const s = pres.addSlide(); base(s, 8, "The product", "A dashboard an analyst can act on");
    const w = 5.95; const h1 = frame(s, shots.fleet, M, 1.75, w);
    const fx = M + w + 0.25;
    panel(s, fx - 0.05, 1.7, w + 0.1, h1 + 0.1, { fill: C.SURF, r: 0.16 });
    const steps = [["Propose", "a written fix for the rule that failed"], ["Preview", "the real diff on copies; strongSwan loads it in a throwaway container"],
      ["Approve", "a person approves that exact diff"], ["Apply", "only what was previewed, lab only"],
      ["Verify", "fresh capture: rule passes, nothing new fails, survives a rekey"], ["Undo", "if not, restored byte for byte, automatically"]];
    const rh = (h1 - 0.3) / steps.length;
    steps.forEach((st, i) => { const ry = 1.9 + i * rh; const undo = i === 5;
      s.addShape(pres.shapes.OVAL, { x: fx + 0.2, y: ry + (rh - 0.38) / 2, w: 0.38, h: 0.38, fill: { color: undo ? C.WARN : C.VIOLET, transparency: 84 }, line: { color: undo ? C.WARN : C.VIOLET, width: 0.75, transparency: 40 } });
      text(s, String(i + 1), { x: fx + 0.2, y: ry + (rh - 0.38) / 2, w: 0.38, h: 0.38, fontFace: MONO, fontSize: 11, bold: true, color: undo ? C.WARN : C.VIOLET, align: "center", valign: "middle" });
      text(s, st[0], { x: fx + 0.72, y: ry, w: 1.15, h: rh, fontSize: 14, bold: true, valign: "middle" });
      text(s, st[1], { x: fx + 1.9, y: ry, w: w - 2.05, h: rh, fontSize: 11.5, color: C.MUTED, valign: "middle", lineSpacingMultiple: 1.02 });
      if (i < steps.length - 1) arrow(s, fx + 0.39, ry + (rh + 0.38) / 2 + 0.02, fx + 0.39, ry + rh + (rh - 0.38) / 2 - 0.02, C.FAINT); });
    const y = 1.75 + h1 + 0.22;
    text(s, "Risk at a glance", { x: M, y, w, h: 0.3, fontSize: 14.5, bold: true }); text(s, "A 0-100 risk score with what drives it, and a threat matrix of 12 threats by likelihood and impact.", { x: M, y: y + 0.32, w, h: 0.5, fontSize: 11.5, color: C.MUTED, lineSpacingMultiple: 1.04 });
    text(s, "Fix it in the lab, safely", { x: fx, y, w, h: 0.3, fontSize: 14.5, bold: true }); text(s, "Only a proven fix is kept. A local AI model can draft fixes too; it failed our test (0 of 16), so it stays off.", { x: fx, y: y + 0.32, w, h: 0.5, fontSize: 11.5, color: C.MUTED, lineSpacingMultiple: 1.04 });
    const tabs = ["Explained", "Threats", "Traffic & exposure", "Changes", "Verdicts", "Evidence", "Not visible from here", "Live"]; let x = M;
    tabs.forEach((t) => { const tw = 0.3 + t.length * 0.078; chip(s, t, x, 6.62, tw, t === "Not visible from here" ? "violet" : "silver", 0.28, 9); x += tw + 0.1; });
    s.addNotes("About 2 minutes, and this is where you demo live using the demo kit: drop in 01-weak-cipher, then 02-pq-downgrade, then 04-ah-no-encryption, then 06-traffic-messaging, then run the live demo (play_live.sh). Kit guide: DEMO-GUIDE.pdf. Real dashboard, real captures. Steps: run ./start.sh, drop in a weak-cipher capture, and show the risk score and threat matrix. Open a tunnel and read the plain-English explanation of every failed check. Open the Traffic tab: predicted type, confidence, runners-up. Then the Live tab: a tunnel that re-negotiates with weaker settings is flagged as changed, with the downgrades named. Then the fix loop on the right (needs the Docker lab running): on a failed rule press Propose fix, Approve, Preview change to show the real diff, then Apply in lab; the tool captures again and says Confirmed fixed only if the rule now passes, nothing else got worse and the tunnel survives a rekey, otherwise it undoes the change by itself. It only ever touches the lab, never a real VPN. Always end on Not visible from here, the list of what the capture cannot show.");
  }

  // ============ 9  Measured, not claimed
  { const s = pres.addSlide(); base(s, 9, "Evidence", "Measured, not claimed");
    const stats = [["392", "unit tests pass, plus 60 browser checks"], ["85 / 85", "captures match the VPN endpoints"], ["0.986", "accuracy on runs it never saw (clean lab)"], ["1.000", "on a second IPsec software"]];
    stats.forEach((st, i) => { const x = M + (i % 2) * 2.95, y = 1.75 + Math.floor(i / 2) * 1.85; panel(s, x, y, 2.8, 1.7);
      text(s, st[0], { x: x + 0.2, y: y + 0.15, w: 2.4, h: 0.75, fontFace: MONO, fontSize: i === 1 ? 28 : 36, bold: true, color: C.VIOLET, valign: "middle" }); text(s, st[1], { x: x + 0.2, y: y + 0.98, w: 2.4, h: 0.65, fontSize: 12, color: C.MUTED, lineSpacingMultiple: 1.05 }); });
    panel(s, 6.85, 1.75, 5.88, 3.55);
    text(s, "Accuracy by test (macro-F1, 1.0 is perfect)", { x: 7.1, y: 1.88, w: 5.4, h: 0.3, fontSize: 12.5, bold: true });
    s.addChart(pres.charts.BAR, [{ name: "macro-F1", labels: ["Held-out runs", "Other IPsec software", "Real apps", "Delayed network", "Lossy network", "Real VPN traffic (MIT)", "Synthetic only, real apps", "Lab only, real VPN (MIT)"], values: [0.986, 1.0, 0.995, 0.984, 0.914, 0.741, 0.461, 0.472] }],
      { x: 6.95, y: 2.2, w: 5.7, h: 3.05, barDir: "col", barGapWidthPct: 35, chartColors: [C.VIOLET, C.VIOLET, C.VIOLET, C.VIOLET, C.VIOLET, C.WARN, C.NEG, C.NEG], valAxisHidden: true, valAxisMaxVal: 1.2, valAxisMinVal: 0,
        valGridLine: { style: "none" }, catGridLine: { style: "none" }, catAxisLabelColor: C.MUTED, catAxisLabelFontFace: HEAD, catAxisLabelFontSize: 8.5, showValue: true, dataLabelColor: C.INK,
        dataLabelFontFace: MONO, dataLabelFontSize: 10, dataLabelFormatCode: "0.000", dataLabelPosition: "outEnd", showLegend: false, plotArea: { fill: { color: C.SURF } }, chartArea: { fill: { color: C.SURF } } });
    const fx = [["Lab-trained model scored 0.472 on real VPN traffic (MIT)", "Added 4,702 real windows: 0.741, below our 0.80 bar"], ["A local AI model drafting fixes passed 0 of 16", "Kept off; our checks stopped all 32 bad drafts"], ["Video plus SSH misread as web, 8 of 8", "Mixed-traffic detector catches 92.9%"]];
    const fw = (CW - 2 * 0.2) / 3;
    fx.forEach((f, i) => { const x = M + i * (fw + 0.2); panel(s, x, 5.55, fw, 1.25);
      chip(s, "PROBLEM", x + 0.18, 5.67, 0.95, "neg", 0.24, 8.5); text(s, f[0], { x: x + 1.2, y: 5.65, w: fw - 1.35, h: 0.5, fontSize: 11, valign: "middle", lineSpacingMultiple: 1.0 });
      chip(s, "FIX", x + 0.18, 6.3, 0.95, "pos", 0.24, 8.5); text(s, f[1], { x: x + 1.2, y: 6.22, w: fw - 1.35, h: 0.5, fontSize: 11, valign: "middle", lineSpacingMultiple: 1.0 }); });
    s.addNotes("About 60 seconds. Numbers that can be checked. 392 unit tests and 60 browser checks; every capture in our ground-truth check matches what the VPN endpoints themselves reported; the classifier scored 0.986 on runs it never trained on in the clean lab and 1.000 on a different IPsec implementation, and after retraining with delayed and lossy links it holds 0.984 and 0.914 on held-out runs under those conditions. The red bars matter most. A model trained only on synthetic traffic scored 0.461 on real applications, so we retrained on real applications in our lab (0.995). Then we tested on traffic we did not make: real VPN traffic recorded by MIT Lincoln Laboratory (the public VNAT dataset). Our lab-trained model scored only 0.472 there. Adding 4,702 real windows raised it to 0.741 on real capture files it never saw, without hurting our lab results; that is still below the 0.80 we wrote down in advance, and we say so. Also honest: that real traffic is OpenVPN, not IPsec, and on its own it does not teach IPsec (0.378). Below, three things that went wrong and what we did. The middle one: we let a small local AI model draft fixes and tested it before switching it on. It got 0 of 16 right, so it stays off, and the checks stopped every one of 32 deliberately bad drafts. We wrote our predictions down before every experiment, and where they failed we kept the failure on the record. Tested by leaving whole recording runs out, so the model is never scored on data it trained on.");
  }

  // ============ 10  How it all works: the end-to-end flow
  { const s = pres.addSlide(); base(s, 10, "How it works, end to end", "From a capture to a verified fix");
    const box = (x, y, w, h, title, sub, tag, hi = false) => {
      panel(s, x, y, w, h, { fill: hi ? C.VIOLET : C.SURF, ft: hi ? 88 : 0, line: hi ? C.VIOLET : C.HAIR });
      text(s, title, { x: x + 0.14, y: y + 0.1, w: w - 0.28, h: 0.3, fontSize: 13.5, bold: true });
      text(s, sub, { x: x + 0.14, y: y + 0.42, w: w - 0.28, h: h - 0.72, fontSize: 10, color: C.MUTED, lineSpacingMultiple: 1.04 });
      if (tag) text(s, tag, { x: x + 0.14, y: y + h - 0.28, w: w - 0.28, h: 0.2, fontFace: MONO, fontSize: 8.5, color: C.VIOLET });
    };
    // row 1: the analysis pipeline
    const top = 1.62, bh = 1.28, bw = 1.92, gx = (CW - 6 * bw) / 5;
    const row = [["1  Capture", "a pcap file, or a live stream from a span port", "tcpdump"],
      ["2  Read", "IKE, ESP and AH headers only; nothing is decrypted", "tshark"],
      ["3  Evidence", "every fact labelled, from observed to not observable", "Python"],
      ["4  Judge", "against 5 written standards; every verdict cites its rule", "YAML rules"],
      ["5  Score", "12-threat matrix, 0-100 risk score, evidence confidence", "scikit-learn"],
      ["6  Show", "dashboard, plain-English reports, CBOM, live mode", "React"]];
    row.forEach((r, i) => { const x = M + i * (bw + gx); box(x, top, bw, bh, r[0], r[1], r[2], i === 2 || i === 3);
      if (i < 5) arrow(s, x + bw + 0.02, top + bh / 2, x + bw + gx - 0.02, top + bh / 2, C.FAINT); });
    // row 2: what feeds the middle of the pipeline
    const r2 = top + bh + 0.45, h2 = 1.22;
    const xE = M + 2 * (bw + gx), xJ = M + 3 * (bw + gx);
    box(M, r2, xE + bw - M, h2, "4 models we trained", "traffic type, mixed traffic, tunnel or transport (Random Forests), and change detection (Isolation Forest), all from packet sizes and timing", "our captures + real VPN traffic (MIT)");
    arrow(s, xE + bw / 2, r2 - 0.02, xE + bw / 2, top + bh + 0.04, C.VIOLET);
    box(xJ, r2, 2 * bw + gx, h2, "5 written standards", "DISA VPN SRG, RFC 8247 (IKEv2), RFC 8221/4303 (ESP, AH), DST post-quantum, CVE-2026-78135", "an unknown is never scored as a pass");
    arrow(s, xJ + bw / 2, r2 - 0.02, xJ + bw / 2, top + bh + 0.04, C.VIOLET);
    box(M + 5 * (bw + gx), r2, bw, h2, "Not visible", "each capture lists what it cannot show", "honest by design");
    arrow(s, M + 5 * (bw + gx) + bw / 2, top + bh + 0.04, M + 5 * (bw + gx) + bw / 2, r2 - 0.02, C.FAINT);
    // row 3: the lab fix loop, from a failed verdict
    const r3 = r2 + h2 + 0.5, h3 = 1.08;
    text(s, "7  FIX, IN THE LAB (A PERSON APPROVES EVERY CHANGE)", { x: M, y: r3 - 0.3, w: 8, h: 0.24, fontFace: MONO, fontSize: 9.5, color: C.VIOLET, charSpacing: 2 });
    const fix = [["Propose", "a written fix for the failed rule"], ["Preview", "real diff; strongSwan loads it in a throwaway copy"], ["Approve", "a person approves that exact diff"],
      ["Apply", "only what was previewed"], ["Verify", "capture again with traffic, then force a rekey"], ["Keep or undo", "kept only if proven; else restored byte for byte"]];
    const fw = (CW - 5 * 0.22) / 6;
    fix.forEach((f, i) => { const x = M + i * (fw + 0.22); const last = i === 5;
      panel(s, x, r3, fw, h3, { fill: last ? C.WARN : C.SURF, ft: last ? 90 : 0, line: last ? C.WARN : C.HAIR });
      text(s, f[0], { x: x + 0.12, y: r3 + 0.08, w: fw - 0.24, h: 0.28, fontSize: 12.5, bold: true, color: last ? C.WARN : C.INK });
      text(s, f[1], { x: x + 0.12, y: r3 + 0.38, w: fw - 0.24, h: h3 - 0.45, fontSize: 9.5, color: C.MUTED, lineSpacingMultiple: 1.02 });
      if (i < 5) arrow(s, x + fw + 0.01, r3 + h3 / 2, x + fw + 0.21, r3 + h3 / 2, C.FAINT); });
    // the team, kept from the old closing slide
    text(s, [{ text: "Team Think2Thrive:  ", options: { fontFace: MONO, color: C.VIOLET } }, { text: "Kishore K (lead)  ·  Balachandran R  ·  Ajay R  ·  Akilan M  ·  Agalya R  ·  Jayavanadhi V", options: { bold: true } }],
      { x: M, y: 6.72, w: CW - 3.2, h: 0.28, fontSize: 11 });
    text(s, "Evidence for every answer.", { x: W - M - 3.2, y: 6.68, w: 3.2, h: 0.34, fontSize: 14, bold: true, align: "right" });
    s.addNotes("About 90 seconds. This is the whole system on one page; walk it left to right, top to bottom. 1 A capture goes in, from a file or live. 2 tshark reads only the headers; nothing is decrypted. 3 Every packet fact becomes a labelled finding. The four models we trained feed in here (the traffic model on our captures plus real VPN traffic from MIT's public VNAT dataset): they read packet sizes and timing to say what kind of traffic is inside, whether it is mixed, which mode, and whether the tunnel changed. 4 The findings are judged against five written standards, and an unknown is never scored as a pass. 5 The verdicts become a threat matrix, a risk score and a confidence. 6 The analyst sees it in the dashboard, reports and live mode, always ending with what the capture cannot show. 7 For a failed rule, the lab fix loop: propose a written fix, preview the real change in a throwaway copy, a person approves it, apply only what was previewed, verify with a fresh capture and a forced rekey, and keep it only if it is proven; otherwise it is undone automatically. Close: evidence for every answer.");
  }

  await pres.writeFile({ fileName: OUT });
  console.log("wrote", OUT);
})().catch((e) => { console.error(e); process.exit(1); });
