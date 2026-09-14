# TunnelScope Fleet — local instrument dashboard

A real, locally-running fleet console for TunnelScope. Runs with **Vite + React +
TypeScript** and **shadcn/ui** primitives (Collapsible, restyled crisp).

## Design direction — black, violet, silver-white, and a strict green/yellow/red indicator system

- **Palette:** near-black `#08080B`, hairline silver-tinted borders `#27272E`, silver-white
  text `#F3F3F6`, and a *single* brand/interactive accent — violet `#8B5CF6` — for the
  wordmark, the signal trace, active filters and focus states. Green `#22C55E` / yellow
  `#F2B33D` / red `#EF4444` are reserved strictly as the status-indicator vocabulary
  (posture chips, severity labels, chart colors) and never used decoratively: green =
  post-quantum/clean, yellow = classical/medium-severity, red = downgrade/CVE/high-severity.
- **Type:** the **Geist** superfamily for UI text and all data (IPs, SPIs, rule IDs, the
  dissection tree).
- **Wordmark as logo:** no separate icon — "Tunnel" in Geist, "Scope" in **Bungee**
  (Google Fonts, OFL), a bold geometric display face. This stands in for the commercial
  **Kufica** font (Artegra, sold via Creative Fabrica) referenced as the target look —
  Kufica has no free-license distribution, so it isn't bundled here. To use the real
  Kufica, drop its licensed woff2 files under `src/assets/fonts/` and repoint
  `--font-display` in `src/index.css`.
- **Signal trace** (`SignalTrace.tsx`): the fleet as a violet posture waveform, each
  gateway a pulse whose height = its weighted finding load, marker ringed by posture
  color (green/yellow/red). A quiet reveal sweep draws it on load.
- **Fleet register:** a rounded-card list where expanding a gateway opens a real
  protocol-dissection tree (`├ └`), each verdict cited to its baseline, severity
  color-coded red/yellow/silver.
- **Corners:** all card-level containers use a visibly rounded `rounded-2xl` (18px);
  chips and pills stay fully rounded.
- **Motion** is a single gentle rise-in on load, from a visible rest state — no
  fade-in-on-scroll, respects `prefers-reduced-motion`.

## Data

`src/gateways.json` is real `tunnelscope fleet <dir> --json` output over 10 of the
project's actual validated captures (classical baselines, the PQ-downgrade tunnel, the
ML-KEM hybrid, the real CVE-2026-78135 exploit capture, the OpenBSD `iked`
cross-implementation capture), relabeled with Indian gateway city names.

## Run

```bash
npm install
npm run dev      # http://localhost:5173
```
