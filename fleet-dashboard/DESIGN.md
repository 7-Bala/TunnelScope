---
version: 2
name: TunnelScope
description: A dark, instrument-grade operations surface for reading IPsec and post-quantum posture off the wire. Near-black, one violet accent, a silver Kufica wordmark, a green/yellow/red triad used only for status, and one authored 3D moment (the tunnel) whose motion reports analysis state.

colors:
  background: "#08080B"
  surface: "#101014"
  surface-raised: "#16161B"
  secondary: "#1C1C22"
  hairline: "#27272E"
  ink: "#F3F3F6"
  ink-muted: "#9C9CA8"
  ink-faint: "#66666F"
  wordmark-silver: "#C7CAD1"
  accent-violet: "#8B5CF6"
  on-accent: "#FFFFFF"
  status-pos: "#22C55E"
  status-warn: "#F2B33D"
  status-neg: "#EF4444"
  violet-wash: "rgba(139, 92, 246, .12)"
  pos-wash: "rgba(34, 197, 94, .12)"
  warn-wash: "rgba(242, 179, 61, .13)"
  neg-wash: "rgba(239, 68, 68, .13)"

typography:
  family-display: "Kufica Bold (wordmark only), Geist Variable fallback"
  family-ui: "Geist Variable, -apple-system, Segoe UI, sans-serif"
  family-data: "Geist Mono Variable, SF Mono, monospace"
  wordmark: { size: 34px, family: family-display, case: uppercase, color: wordmark-silver }
  headline: { size: 32px, weight: 600, lineHeight: 1.15, letterSpacing: -0.02em }
  section: { size: 20px, weight: 600, lineHeight: 1.2, letterSpacing: -0.02em }
  panel-title: { size: 14px, weight: 600, letterSpacing: -0.01em }
  body: { size: 13.5px, weight: 400, lineHeight: 1.6 }
  label: { size: 12.5px, weight: 500 }
  data: { size: 12px, family: family-data, numerals: tabular }
  readout: { size: 28px, weight: 600, numerals: tabular }

radius: { control: 6px, panel: 16px, section: 16px, pill: 999px }
spacing: { gutter-mobile: 16px, gutter: 24px, panel-pad: 20px, section-gap: 32px }
---

> **v2 (2026-09-18 merge).** The palette and wordmark come from the black/violet redesign on GitHub
> `main` (T-062…T-065); the structure below (intake, data-source switch, instrument bar, register
> panes, the tunnel) comes from T-060. v1 described the earlier graphite/teal look.

# TunnelScope design system

## Overview

TunnelScope is an Operate surface: an analyst is mid-task, often in a dark room, deciding whether a
tunnel is compliant and post-quantum. The design serves that scene. It is quiet by default, precise
in detail, and it never decorates a claim it cannot back. One element is allowed to be expressive:
the tunnel in the intake panel, which is the product mark extruded into depth.

## Colors

### Accent
Violet `#8B5CF6` is the only accent. It marks the primary action, the current selection, focus, and
the tunnel. It never decorates an inactive state.

### Surface
Three near-black steps: page `#08080B`, panel `#101014`, raised/popover `#16161B`. Separation comes
from 1px hairlines `#27272E`, not shadows.

### Text
Ink `#F3F3F6` for content, muted `#9C9CA8` for labels and prose, faint `#66666F` for metadata.
Silver `#C7CAD1` is the wordmark and the *inferred* evidence chip: a meta tone, never a status.

### Semantic
Green / yellow / red carry status and nothing else (never decoration):
- **pos** `#22C55E`: post-quantum selected, a passed check.
- **warn** `#F2B33D`: classical key exchange, medium severity, the PQ-not-selected count.
- **neg** `#EF4444`: PQ offered but not selected (chips, donut), high severity, the CVE pattern, errors.
Each has a 10% wash for chips. Never pair a status colour with a status it doesn't mean.

## Typography

Two faces. Kufica Bold is the wordmark and nothing else (licensed file in `src/assets/fonts/`).
Geist Sans carries headings, labels and prose. Geist Mono is for things that are data:
IPs, SPIs, rule IDs, finding values, byte sizes. It is never used as a "technical" costume. All
numerals in data are tabular. The scale is fixed rem, ratio about 1.2, not fluid.

## Layout

- Container `max-w-[1240px]`, gutters 16px on mobile, 24px from `sm`.
- Top to bottom: topbar (identity, data source, engine status) → intake → headline → trace →
  instrument bar → posture and severity column + register.
- Responsive changes are structural: the intake stacks, the instrument bar goes 2+2+1 → 3+2 → 5,
  register rows move their counts under the title below `sm`.

## Elevation & depth

Liquid glass, never blur (user, 2026-09-19). Cards are the `.glass` class in `index.css`: a clear
pane tinted `rgb(16 16 20 / .62)` that the background corridor shows through undistorted, a rim
(gradient border) brightest along the top-left edge where light would catch it, an inset top
highlight, a faint 135° sheen, and a soft drop shadow. **No `backdrop-filter`, no blur, anywhere.**
The KPI bar is one glass pane with hairline light dividers (inset shadows), since glass cells are not
opaque. The only other depth is real depth: the WebGL corridor behind the top of the page.

## Shapes

Controls 6px, panels and sections 16px (`rounded-2xl`), pills for status chips and filters only.
Status chips in the register have a fixed width so row titles align.

## Components

### Topbar
The TunnelScope wordmark (the wordmark is the mark; no icon), a two-option data-source switch ("Your captures" / "Sample fleet") with counts, the
time of the last real analysis (only once one exists), and, only after a real analysis, its time. There is no engine status badge (removed 2026-09-19); if the
engine can't be reached, a red banner says so and how to start it. No "live" claim: TunnelScope
analyses files, it does not monitor.

### Intake
Liquid glass (`.glass`, no blur), so the background corridor shows through it clearly. Left:
section title, one sentence on what happens to the file, primary button "Choose captures", limits,
then the queue. Right: a dashed drop zone (the mark, "Drop captures here", "or click to choose"),
itself a button that opens the file picker, with the engine's status line under it. The whole page is
a drop target; the panel and the zone turn violet and re-title to "Release to analyse" while a file
is over the page.

### Queue row
Status icon, file name, size in mono. States: waiting, analysing (thin shimmer bar, no spinner in
content), done (SA count and high-severity count), error (the engine's own message, Retry, Remove).

### Instrument bar
One bordered bar split by 1px gaps, five readouts. Not a row of identical cards.

### Register
Rows: fixed-width status chip, name, `src → dst` in mono, failed-check counts. Expanding an uploaded
capture shows three panes: Verdicts (every rule with its baseline), Evidence (every finding with
status chip and vantage), Not visible from here (UNKNOWN / NOT_OBSERVABLE findings with the
engine's reason). Status chips: observed/measured violet wash, inferred silver on secondary, unknown and not
observable as an outline, contradictory neg wash.

### The tunnel (three.js), the page background
The intro's corridor stays after the intro as the page background
(`src/components/tunnel/BackgroundTunnel.tsx`): the same rings (`tunnel/layout.ts`), shaped to the
window (up to 1.8x wider than tall), dimmed to about 30% brightness in the deep corridor; the five
rings nearest the viewer (the largest on screen, the ones crossing the header text) taper down to 22%
of that, so the glow sits behind the upload panel rather than across the words. It sits behind the top of the
page only: a vertical mask fades it out by 80% of the screen height, a vignette darkens the edges,
and it fades to nothing as the page scrolls (gone by 85% of a screen), then stops rendering. The data
below always sits on plain black.

Hand-over: while the intro plays, it holds the intro's final frame (every ring lit, vanishing point
centred) underneath; when the intro leaves, the same rings dim over 1.9s (wall-clock, so slow devices
don't stretch it) and the vanishing point drifts up to about a third of the way down, behind the
upload panel.

Motion still reports state: idle drift and a faint pulse every 6s; the whole corridor brightens and
speeds up while a file is dragged over the page; faster, with a slow twist and packets of light
streaming out, while analysing; it takes the posture colour when a result lands. A slight lean toward
the pointer (window-wide, clamped). Canvas capped at 1.5x pixel ratio, paused when the tab is hidden
or it has scrolled away, static under `prefers-reduced-motion`, absent without WebGL (plain black).

### Intro (every load)
A full-screen title sequence before the dashboard (`src/components/intro/`). Pitch black, the unlit
ring fixtures barely visible; the core at the far end flickers on, then each ring flickers two or
three times and holds, farthest first, faster as they approach (like corridor lights coming on
toward a character in a horror film), while the camera creeps forward. One light a little past the
middle is faulty: it catches, dies with a sputter, sits dark while the rest of the corridor waits,
then catches again (`FAILING_RING`, `FAIL_STALL_S` in `timeline.ts`; pattern in `flicker.ts`). The last ring frames the
screen like a doorway, the wordmark resolves over a pool of dark, and the overlay fades into the
page (about 5.6s). Plays on every load (user's choice), any key or tap skips, never under `prefers-reduced-motion`, gives up after 2.5s if WebGL or the chunk isn't
ready (e.g. a background tab). `?intro=hold` stops on the final frame for stills.
Glow is a canvas-blurred texture drawn additively behind each tube.

## Motion

State, the one-time intro, and the chart draws: analysis running, a result landing, a queue row arriving (200ms), a
button press (1px translate); the signal trace draws in (1.8s) and the donut and bars grow once,
all off under `prefers-reduced-motion`. No scroll reveals. Transitions 150–250ms, exponential
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

Keep the world: near-black, one violet, a silver Kufica wordmark, three meaningful status colours, Geist. New surfaces should read
as the same instrument. If a new finding type appears, give it a status chip from the existing
vocabulary before inventing a colour.
