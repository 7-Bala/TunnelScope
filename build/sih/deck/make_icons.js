// Renders the icons and technology logos the screening deck uses into img/icons and img/logos (PNG, 256 px).
//   NODE_PATH=<modules with react, react-dom, react-icons, simple-icons, sharp> node build/sih/deck/make_icons.js
// Icons: Phosphor duotone (react-icons/pi), one navy colour on a soft rounded tile. Logos: Simple Icons, in each
// brand's colour.
const fs = require("fs");
const path = require("path");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const pi = require("react-icons/pi");
const si = require("simple-icons");
const sharp = require("sharp");

const HERE = __dirname;

// name -> Phosphor duotone icon
const ICONS = {
  technical: "PiGearSixDuotone", speed: "PiTimerDuotone", security: "PiShieldCheckDuotone", operational: "PiBroadcastDuotone",
  economic: "PiCurrencyInrDuotone", rollback: "PiArrowCounterClockwiseDuotone", scalability: "PiTreeStructureDuotone",
  integration: "PiPlugsConnectedDuotone",
  viability: "PiHandshakeDuotone", cost: "PiCoinsDuotone", ease: "PiThumbsUpDuotone", market: "PiTrendUpDuotone",
  adoption: "PiUsersThreeDuotone",
  quantum: "PiAtomDuotone", compliance: "PiScalesDuotone", efficiency: "PiTimerDuotone", cbom: "PiFileLockDuotone",
  afford: "PiCurrencyInrDuotone",
  encrypted: "PiLockKeyDuotone", dataset: "PiDatabaseDuotone", privacy: "PiCloudArrowUpDuotone", lesson: "PiFlaskDuotone",
};
const INK = "1F3864", TILE = "E8EEF7";

// name -> [simple-icons key, label]
const LOGOS = {
  python: ["siPython", "Python"], sklearn: ["siScikitlearn", "scikit-learn"], wireshark: ["siWireshark", "Wireshark (tshark)"],
  strongswan: ["siStrongswan", "strongSwan"], react: ["siReact", "React"], typescript: ["siTypescript", "TypeScript"],
  docker: ["siDocker", "Docker"], linux: ["siLinux", "Linux"],
};

async function png(svg, out) {
  await sharp(Buffer.from(svg)).resize(256, 256).png().toFile(out);
}

(async () => {
  for (const d of ["icons", "logos"]) fs.mkdirSync(path.join(HERE, "img", d), { recursive: true });
  for (const f of fs.readdirSync(path.join(HERE, "img", "icons"))) fs.unlinkSync(path.join(HERE, "img", "icons", f));
  for (const [name, icon] of Object.entries(ICONS)) {
    const inner = renderToStaticMarkup(React.createElement(pi[icon], { size: 160 }))
      .replace(/currentColor/g, "#" + INK).replace(/ (width|height|style)="[^"]*"/g, "")
      .replace(/<svg /, '<svg x="48" y="48" width="160" height="160" ');
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256"><rect width="256" height="256" rx="60" fill="#${TILE}"/>${inner}</svg>`;
    await png(svg, path.join(HERE, "img", "icons", name + ".png"));
  }
  const meta = {};
  for (const [name, [key]] of Object.entries(LOGOS)) {
    const s = si[key];
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="512" height="512"><path fill="#${s.hex}" d="${s.path}"/></svg>`;
    // trimmed to the logo itself, so wide wordmarks are not shrunk into a square
    const out = path.join(HERE, "img", "logos", name + ".png");
    const info = await sharp(Buffer.from(svg)).trim().png().toFile(out);
    meta[name] = { label: LOGOS[name][1], ratio: +(info.width / info.height).toFixed(3) };
  }
  fs.writeFileSync(path.join(HERE, "img", "logos", "logos.json"), JSON.stringify(meta, null, 1));
  console.log(`wrote ${Object.keys(ICONS).length} icons and ${Object.keys(LOGOS).length} logos`);
})();
