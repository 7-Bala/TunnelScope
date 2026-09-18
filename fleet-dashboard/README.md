# TunnelScope Fleet — local instrument dashboard

A real, locally-running fleet console for TunnelScope. Runs with **Vite + React +
TypeScript** and **shadcn/ui** primitives (Collapsible, restyled crisp).

## Design direction — black, violet, silver-white, and a strict green/yellow/red indicator system

- **Palette:** near-black `#08080B`, hairline silver-tinted borders `#27272E`, silver-white
  body text `#F3F3F6`, a dedicated metallic silver `#C7CAD1` for the wordmark, and a
  *single* brand/interactive accent — violet `#8B5CF6` — for the signal trace, active
  filters and focus states. Green `#22C55E` / yellow `#F2B33D` / red `#EF4444` are
  reserved strictly as the status-indicator vocabulary (posture chips, severity labels,
  chart colors) and never used decoratively: green = post-quantum/clean, yellow =
  classical/medium-severity, red = downgrade/CVE/high-severity.
- **Type:** the **Geist** superfamily for UI text and all data (IPs, SPIs, rule IDs, the
  dissection tree).
- **Wordmark as logo:** no separate icon — "TunnelScope" set as one word in a single
  silver tone, in **Kufica Bold** — the user's exact pick, a commercial display face
  (Artegra/Creative Fabrica) with no free CDN distribution. The user supplied the
  licensed `woff2` directly; it's checked into `src/assets/fonts/KuficaBold.woff2` and
  wired via `@font-face` in `src/index.css` (`--font-display`).
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

## Data and running it

The dashboard has two data sources, switched in the top bar:

- **Your captures** (default): drop `.pcap`/`.pcapng` files anywhere on the page. Each is sent to the
  local engine's `POST /api/analyze`, analysed by the real pipeline, and deleted right after. Results
  include every verdict, every finding with its status and vantage, and what the capture can't show.
- **Sample fleet**: `src/gateways.json`, real `tunnelscope fleet --json` output over 10 of the project's
  validated lab captures. Gateway names are illustrative; the page says so.

```bash
# the normal way: build once, then one command serves the dashboard and the engine
npm install && npm run build      # writes dist/
tunnelscope serve                 # http://127.0.0.1:8765, 127.0.0.1 only

# while working on the UI: Vite dev server, proxied to the engine
tunnelscope serve --no-browser    # terminal 1
npm run dev                       # terminal 2 → http://localhost:5173
```

Without a `dist/` build, `tunnelscope serve` falls back to a single built-in page (also at `/basic`).

## Design

`DESIGN.md` is the design system (tokens, components, motion rules, do's and don'ts), in the DESIGN.md
format. The intake's 3D tunnel is `src/components/dashboard/TunnelField.tsx` (three.js), lazy-loaded
and static under reduced motion.
