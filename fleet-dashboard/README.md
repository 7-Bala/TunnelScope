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
