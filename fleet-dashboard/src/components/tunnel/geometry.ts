import { CanvasTexture, Path, Shape, ShapeGeometry } from "three"

// Shared by the intro corridor and the intake tunnel, so both draw the same
// glowing tube: the TunnelScope mark's rounded square.

export function roundedSquarePath<T extends Shape | Path>(size: number, radius: number, target: T, reverse = false): T {
  const h = size / 2
  const r = Math.min(radius, h)
  const pts: [number, number][] = []
  const corners: [number, number, number][] = [
    [h - r, h - r, 0],
    [-(h - r), h - r, Math.PI / 2],
    [-(h - r), -(h - r), Math.PI],
    [h - r, -(h - r), (3 * Math.PI) / 2],
  ]
  for (const [cx, cy, start] of corners) {
    for (let i = 0; i <= 10; i++) {
      const a = start + (i / 10) * (Math.PI / 2)
      pts.push([cx + r * Math.cos(a), cy + r * Math.sin(a)])
    }
  }
  if (reverse) pts.reverse()
  target.moveTo(pts[0][0], pts[0][1])
  pts.slice(1).forEach(([x, y]) => target.lineTo(x, y))
  return target
}

/** A rounded-square band (outer minus inner): a line with real thickness that
 *  scales with perspective. WebGL lines are always 1px wide. */
export function band(size: number, radius: number, thickness: number) {
  const shape = roundedSquarePath(size + thickness, radius + thickness / 2, new Shape())
  shape.holes.push(roundedSquarePath(size - thickness, Math.max(radius - thickness / 2, 0.05), new Path(), true))
  return new ShapeGeometry(shape)
}

export function roundedSquare(size: number, radius: number) {
  return new ShapeGeometry(roundedSquarePath(size, radius, new Shape()))
}

/** The light a tube throws, drawn once with the 2D canvas's real blur and used
 *  as an additive texture on a plane of side `size + 2 * pad` behind the tube.
 *  (A flat translucent band reads as a solid frame, not as light.) */
export function glowTexture(size: number, radius: number, pad: number, px = 512) {
  const c = document.createElement("canvas")
  c.width = c.height = px
  const g = c.getContext("2d")!
  const scale = px / (size + pad * 2)
  const side = size * scale
  const o = (px - side) / 2
  g.strokeStyle = "#ffffff"
  g.shadowColor = "#ffffff"
  g.lineWidth = 3
  for (const blur of [34, 18, 8]) {
    g.shadowBlur = blur
    g.beginPath()
    g.roundRect(o, o, side, side, radius * scale)
    g.stroke()
  }
  const tex = new CanvasTexture(c)
  tex.needsUpdate = true
  return tex
}

/** A soft round dot (packets, the core's halo). */
export function dotTexture(px = 64) {
  const c = document.createElement("canvas")
  c.width = c.height = px
  const g = c.getContext("2d")!
  const grad = g.createRadialGradient(px / 2, px / 2, 0, px / 2, px / 2, px / 2)
  grad.addColorStop(0, "rgba(255,255,255,1)")
  grad.addColorStop(0.25, "rgba(255,255,255,.55)")
  grad.addColorStop(1, "rgba(255,255,255,0)")
  g.fillStyle = grad
  g.fillRect(0, 0, px, px)
  const tex = new CanvasTexture(c)
  tex.needsUpdate = true
  return tex
}
