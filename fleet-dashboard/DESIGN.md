---
version: 1
name: TunnelScope
description: A dark, instrument-grade operations surface for reading IPsec and post-quantum posture off the wire. Cool graphite, one restrained teal, three status colours that carry meaning, and one authored 3D moment (the tunnel) whose motion reports analysis state.

colors:
  background: "#0B0D0F"
  surface: "#0F1214"
  surface-raised: "#12161A"
  secondary: "#161A1E"
  hairline: "#20252B"
  ink: "#E9EDF1"
  ink-muted: "#8B949E"
  ink-faint: "#566069"
  accent-teal: "#4FD1C5"
  on-accent: "#052623"
  status-pos: "#45D483"
  status-neg: "#FF5C6C"
  status-steel: "#7D8894"
  teal-wash: "rgba(79, 209, 197, .10)"
  pos-wash: "rgba(69, 212, 131, .10)"
  neg-wash: "rgba(255, 92, 108, .11)"
  steel-wash: "rgba(125, 136, 148, .10)"

typography:
  family-ui: "Geist Variable, -apple-system, Segoe UI, sans-serif"
  family-data: "Geist Mono Variable, SF Mono, monospace"
  headline: { size: 32px, weight: 600, lineHeight: 1.15, letterSpacing: -0.02em }
  section: { size: 20px, weight: 600, lineHeight: 1.2, letterSpacing: -0.02em }
  panel-title: { size: 14px, weight: 600, letterSpacing: -0.01em }
  body: { size: 13.5px, weight: 400, lineHeight: 1.6 }
  label: { size: 12.5px, weight: 500 }
  data: { size: 12px, family: family-data, numerals: tabular }
  readout: { size: 28px, weight: 600, numerals: tabular }

radius: { control: 6px, panel: 8px, section: 12px, pill: 999px }
spacing: { gutter-mobile: 16px, gutter: 24px, panel-pad: 20px, section-gap: 32px }
---

# TunnelScope design system

## Overview

TunnelScope is an Operate surface: an analyst is mid-task, often in a dark room, deciding whether a
tunnel is compliant and post-quantum. The design serves that scene. It is quiet by default, precise
in detail, and it never decorates a claim it cannot back. One element is allowed to be expressive:
the tunnel in the intake panel, which is the product mark extruded into depth.

## Colors

### Accent
Teal `#4FD1C5` is the only accent. It marks the primary action, the current selection, focus, and
the tunnel. It never decorates an inactive state.

### Surface
Three graphite steps: page `#0B0D0F`, panel `#0F1214`, raised/popover `#12161A`. Separation comes
from 1px hairlines `#20252B`, not shadows.

### Text
Ink `#E9EDF1` for content, muted `#8B949E` for labels and prose, faint `#566069` for metadata.

### Semantic
Status colours carry meaning and nothing else:
- **pos** `#45D483`: post-quantum selected, a passed check.
- **neg** `#FF5C6C`: PQ offered but not selected, high severity, the CVE pattern, errors.
- **steel** `#7D8894`: classical key exchange, medium severity.
Each has a 10% wash for chips. Never pair a status colour with a status it doesn't mean.

## Typography

One family. Geist Sans carries headings, labels and prose. Geist Mono is for things that are data:
IPs, SPIs, rule IDs, finding values, byte sizes. It is never used as a "technical" costume. All
numerals in data are tabular. The scale is fixed rem, ratio about 1.2, not fluid.

## Layout

- Container `max-w-[1240px]`, gutters 16px on mobile, 24px from `sm`.
- Top to bottom: topbar (identity, data source, engine status) → intake → headline → trace →
  instrument bar → posture and severity column + register.
- Responsive changes are structural: the intake stacks, the instrument bar goes 2+2+1 → 3+2 → 5,
  register rows move their counts under the title below `sm`.

## Elevation & depth

Flat. Elevation is declared by one hairline border, never a border plus a wide shadow. The only
depth in the product is real depth: the WebGL tunnel.

## Shapes

Controls 6px, panels 8px, the intake section 12px, pills for status chips and filters only.
Status chips in the register have a fixed width so row titles align.

## Components

### Topbar
Mark + name, a two-option data-source switch ("Your captures" / "Sample fleet") with counts, the
time of the last real analysis (only once one exists), and an engine status pill that reflects a
real `/health` check. No "live" claim: TunnelScope analyses files, it does not monitor.

### Intake
Left: section title, one sentence on what happens to the file, primary button "Choose captures",
limits, then the queue. Right: the tunnel. The whole page is a drop target; the panel re-titles to
"Release to analyse" while a file is over the page.

### Queue row
Status icon, file name, size in mono. States: waiting, analysing (thin shimmer bar, no spinner in
content), done (SA count and high-severity count), error (the engine's own message, Retry, Remove).

### Instrument bar
One bordered bar split by 1px gaps, five readouts. Not a row of identical cards.

### Register
Rows: fixed-width status chip, name, `src → dst` in mono, failed-check counts. Expanding an uploaded
capture shows three panes: Verdicts (every rule with its baseline), Evidence (every finding with
status chip and vantage), Not visible from here (UNKNOWN / NOT_OBSERVABLE findings with the
engine's reason). Status chips: observed/measured teal wash, inferred steel wash, unknown and not
observable as an outline, contradictory neg wash.

### The tunnel (three.js)
Concentric rounded squares receding to a solid core, drifting toward the viewer. Motion reports
state: idle drift; faster and brighter while a file is dragged over the page; fastest with a slow
twist while analysing; the rings take the posture colour for a moment when a result lands (neg if
any high-severity or PQ-not-selected result, pos if all PQ, steel otherwise); red when a file is
refused. Lazy-loaded, capped at 2x device pixel ratio, paused when off-screen or the tab is hidden,
static under `prefers-reduced-motion`, and replaced by the SVG mark when WebGL is unavailable.

## Motion

State only: analysis running, a result landing, a queue row arriving (200ms), a button press
(1px translate). No page-load choreography, no scroll reveals. Transitions 150–250ms, exponential
ease-out.

## Do's and don'ts

### Do
- Say what the engine could not see, in the engine's words.
- Label sample data as sample data.
- Compute every headline from the data on screen.
- Use "PQ offered, classical selected" or "PQ not selected" for that finding.

### Don't
- Claim live monitoring, a scan time that isn't one, or an attack where only a policy selection or an
  attempt is observed.
- Add a second accent, gradient text, glows, eyebrow labels above headings, or a modal where an
  inline pane will do.
- Use emoji or unicode glyphs as icons (icons are lucide, 1.75–2px stroke).

## Responsive behavior

Breakpoints `sm` 640, `md` 768, `lg` 1024. Verified at 375px and 1440px with no horizontal scroll.
Tables inside the register detail scroll horizontally inside their own container.

## Iteration guide

Keep the world: graphite, one teal, three meaningful status colours, Geist. New surfaces should read
as the same instrument. If a new finding type appears, give it a status chip from the existing
vocabulary before inventing a colour.
