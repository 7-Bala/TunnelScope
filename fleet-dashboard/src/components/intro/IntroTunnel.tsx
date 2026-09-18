import { useEffect, useRef } from "react"
import {
  AdditiveBlending,
  CanvasTexture,
  Color,
  Mesh,
  MeshBasicMaterial,
  Path,
  PerspectiveCamera,
  PlaneGeometry,
  Scene,
  Shape,
  ShapeGeometry,
  WebGLRenderer,
} from "three"
import { CORE_ON_S, FAILING_RING, RING_COUNT, ringOnAt, SEQUENCE_S } from "./timeline"
import { FAILING_PATTERN, flickerPattern, intensityAt } from "./flicker"

// The intro's corridor: the TunnelScope mark's rings, standing still in the
// dark, switched on one by one from the far end toward the viewer, like a row
// of old ceiling lights coming on down a hallway. Driven purely by elapsed
// time, so a slow first frame never desyncs it from the wordmark.

const VIOLET = new Color("#8B5CF6")
const HOT = new Color("#DDD2FE") // the tube's white-hot moment as it catches
const FAR_Z = -24
const NEAR_Z = 1.55 // the last ring frames the screen like a doorway
const SIZE = 2.6

function roundedSquarePath(size: number, radius: number, target: Shape | Path, reverse = false) {
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

// A rounded-square band (outer square minus inner square): a line with real
// thickness that scales with perspective. WebGL lines are always 1px wide.
function band(size: number, thickness: number) {
  const shape = roundedSquarePath(size + thickness, 0.6 + thickness / 2, new Shape()) as Shape
  shape.holes.push(roundedSquarePath(size - thickness, Math.max(0.6 - thickness / 2, 0.05), new Path(), true) as Path)
  return new ShapeGeometry(shape)
}

// The light a tube throws: drawn once with the 2D canvas's real blur, then
// used as an additive texture behind every ring. A flat translucent band (the
// first attempt) read as a solid purple frame, not as light.
const GLOW_PAD = 0.9 // world units of glow around the tube
function glowTexture() {
  const px = 512
  const c = document.createElement("canvas")
  c.width = c.height = px
  const g = c.getContext("2d")!
  const scale = px / (SIZE + GLOW_PAD * 2)
  const side = SIZE * scale
  const o = (px - side) / 2
  g.strokeStyle = "#ffffff"
  g.shadowColor = "#ffffff"
  g.lineWidth = 3
  for (const blur of [34, 18, 8]) {
    g.shadowBlur = blur
    g.beginPath()
    g.roundRect(o, o, side, side, 0.6 * scale)
    g.stroke()
  }
  const tex = new CanvasTexture(c)
  tex.needsUpdate = true
  return tex
}

export default function IntroTunnel({ onReady, onUnsupported }: { onReady: () => void; onUnsupported: () => void }) {
  const hostRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const host = hostRef.current
    if (!host) return
    let renderer: WebGLRenderer
    try {
      renderer = new WebGLRenderer({ antialias: true, alpha: true })
    } catch {
      onUnsupported()
      return
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    renderer.setClearColor(0x000000, 0)
    renderer.domElement.setAttribute("aria-hidden", "true")
    renderer.domElement.style.display = "block"
    host.appendChild(renderer.domElement)

    const scene = new Scene()
    const camera = new PerspectiveCamera(46, 1, 0.1, 100)

    const tube = band(SIZE, 0.036)
    const halo = new PlaneGeometry(SIZE + GLOW_PAD * 2, SIZE + GLOW_PAD * 2)
    const glow = glowTexture()
    const rings = Array.from({ length: RING_COUNT }, (_, i) => {
      // i = 0 is the FARTHEST ring: it lights first
      const z = FAR_Z + (i / (RING_COUNT - 1)) * (NEAR_Z - FAR_Z)
      const tubeMat = new MeshBasicMaterial({ color: VIOLET.clone(), transparent: true, opacity: 0 })
      const haloMat = new MeshBasicMaterial({
        map: glow, color: VIOLET.clone(), transparent: true, opacity: 0, blending: AdditiveBlending, depthWrite: false,
      })
      const t = new Mesh(tube, tubeMat)
      const hl = new Mesh(halo, haloMat)
      t.position.z = hl.position.z = z
      scene.add(hl, t)
      return { tubeMat, haloMat, onAt: ringOnAt(i), pattern: i === FAILING_RING ? FAILING_PATTERN : flickerPattern(i + 7) }
    })

    // the solid core at the far end: the source the light comes from
    const coreShape = roundedSquarePath(0.55, 0.17, new Shape()) as Shape
    const coreGeo = new ShapeGeometry(coreShape)
    const coreMat = new MeshBasicMaterial({ color: VIOLET.clone(), transparent: true, opacity: 0 })
    const core = new Mesh(coreGeo, coreMat)
    core.position.z = FAR_Z - 3
    scene.add(core)
    const corePattern = flickerPattern(3)

    const resize = () => {
      const w = host.clientWidth || 1
      const h = host.clientHeight || 1
      renderer.setSize(w, h, false)
      renderer.domElement.style.width = "100%"
      renderer.domElement.style.height = "100%"
      camera.aspect = w / h
      // keep the doorway ring framing a portrait phone as well as a wide screen
      camera.fov = w / h < 1 ? 62 : 46
      camera.updateProjectionMatrix()
    }

    const draw = (s: number) => {
      // a slow creep down the corridor while the lights come on
      const p = Math.min(1, s / SEQUENCE_S)
      camera.position.set(0, 0, 4.7 - 0.55 * (1 - Math.pow(1 - p, 3)))
      camera.lookAt(0, 0, FAR_Z)

      const c = intensityAt(s - CORE_ON_S, corePattern)
      coreMat.opacity = Math.min(1, 0.06 + c)
      coreMat.color.copy(VIOLET).lerp(HOT, Math.max(0, c - 1))

      for (const r of rings) {
        const k = intensityAt(s - r.onAt, r.pattern)
        // unlit fixtures stay faintly visible in the dark, as in the films
        r.tubeMat.opacity = Math.min(1, 0.07 + 0.93 * k)
        r.tubeMat.color.copy(VIOLET).lerp(HOT, Math.min(1, Math.max(0, k - 1) * 1.2))
        r.haloMat.opacity = 0.55 * Math.min(k, 1.9)
      }
      renderer.render(scene, camera)
    }

    let started = 0
    let ready = false
    renderer.setAnimationLoop((now) => {
      if (!started) started = now
      draw((now - started) / 1000)
      if (!ready) {
        ready = true
        onReady()
      }
    })
    const ro = new ResizeObserver(resize)
    ro.observe(host)
    resize()

    return () => {
      renderer.setAnimationLoop(null)
      ro.disconnect()
      rings.forEach((r) => (r.tubeMat.dispose(), r.haloMat.dispose()))
      tube.dispose()
      halo.dispose()
      glow.dispose()
      coreGeo.dispose()
      coreMat.dispose()
      renderer.dispose()
      renderer.domElement.remove()
    }
  }, [onReady, onUnsupported])

  return <div ref={hostRef} className="absolute inset-0" />
}
