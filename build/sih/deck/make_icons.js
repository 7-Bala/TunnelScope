// Renders the icons and technology logos the screening deck uses into img/icons and img/logos (PNG, 256 px).
//   NODE_PATH=<modules with react, react-dom, react-icons, simple-icons, sharp> node build/sih/deck/make_icons.js
// Icons: Font Awesome 6 (react-icons/fa6), white on a coloured circle. Logos: Simple Icons, in each brand's colour.
const fs = require("fs");
const path = require("path");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const fa = require("react-icons/fa6");
const si = require("simple-icons");
const sharp = require("sharp");

const HERE = __dirname;
const C = { BLUE: "2E75B6", GREEN: "548235", ORANGE: "C55A11", TEAL: "0E7C86", NAVY: "1F3864", RED: "C00000", GOLD: "BF9000", SLATE: "44546A" };

// name -> [Font Awesome icon, circle colour]
const ICONS = {
  technical: ["FaGears", C.BLUE], operational: ["FaLaptop", C.TEAL], economic: ["FaIndianRupeeSign", C.GREEN],
  speed: ["FaGaugeHigh", C.ORANGE], security: ["FaShieldHalved", C.NAVY], scalability: ["FaSitemap", C.TEAL],
  rollback: ["FaRotateLeft", C.RED], integration: ["FaPlug", C.GOLD],
  viability: ["FaHandshake", C.NAVY], cost: ["FaCoins", C.GREEN], ease: ["FaThumbsUp", C.BLUE],
  market: ["FaChartLine", C.ORANGE], adoption: ["FaUsers", C.TEAL],
  problem: ["FaTriangleExclamation", C.RED], unique: ["FaLightbulb", C.GOLD],
  quantum: ["FaAtom", C.NAVY], compliance: ["FaScaleBalanced", C.BLUE], efficiency: ["FaStopwatch", C.ORANGE],
  cbom: ["FaFileShield", C.TEAL], afford: ["FaIndianRupeeSign", C.GREEN],
  hidden: ["FaEyeSlash", C.SLATE], privacy: ["FaLock", C.NAVY], vendor: ["FaServer", C.BLUE], encrypted: ["FaUserShield", C.TEAL],
};

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
  for (const [name, [icon, color]] of Object.entries(ICONS)) {
    const inner = renderToStaticMarkup(React.createElement(fa[icon], { size: 128 }))
      .replace(/currentColor/g, "#FFFFFF").replace(/ (width|height|style)="[^"]*"/g, "")
      .replace(/<svg /, '<svg x="64" y="64" width="128" height="128" ');
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256"><circle cx="128" cy="128" r="128" fill="#${color}"/>${inner}</svg>`;
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
