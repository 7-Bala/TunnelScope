# TunnelScope Fleet — local instrument dashboard

A real, locally-running fleet console for TunnelScope. Runs with **Vite + React +
TypeScript**, **shadcn/ui** (Collapsible, restyled crisp) and one **ReactBits**
component (`CountUp`, as an instrument readout).

## Design direction — clean, modern, minimal (and deliberately not AI-slop)

The design avoids the documented "AI-generated" tells — no indigo/violet gradient, no
generic Inter, no rounded-card-with-icon-and-two-lines cluster
([the purple gradient problem](https://dev.to/james_anderson_h/the-purple-gradient-problem-why-ai-ui-all-looks-alike-and-how-to-fix-it-3j65),
[AI slop design tells](https://www.925studios.co/blog/ai-slop-design-tells)) — while
staying genuinely minimal:

- **Palette:** cool graphite `#0B0D0F`, hairline borders, and a *single* restrained accent
  — teal `#4FD1C5` — for brand, the signal trace and interactive state. Color carries
  meaning, negative space carries the design. Status is minimal: green = PQ/pass, red =
  downgrade/CVE/high, neutral steel = classical/informational.
- **Type:** the **Geist** superfamily — Geist Sans (UI) + Geist Mono (all data: IPs, SPIs,
  rule IDs, the dissection tree). One cohesive, modern face across weights.
- **Logo:** a clean geometric tunnel aperture — concentric rounded squares receding to a
  point ("look down the tunnel"), single-weight teal stroke.
- **Signal trace** (bespoke canvas, `SignalTrace.tsx`): the fleet as a teal posture
  waveform, each gateway a pulse whose height = its weighted finding load, marker ringed
  by posture. A quiet reveal sweep draws it on load.
- **Fleet register:** a minimal list where expanding a gateway opens a real
  protocol-dissection tree (`├ └`), each verdict cited to its baseline.
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
