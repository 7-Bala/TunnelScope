import { useEffect, useRef } from "react"
import {
  AdditiveBlending,
  Color,
  Mesh,
  MeshBasicMaterial,
  PerspectiveCamera,
  PlaneGeometry,
  Scene,
  WebGLRenderer,
} from "three"
import { band, glowTexture, roundedSquare } from "../tunnel/geometry"
import { CAMERA_Z, CORE_Z, fitCamera, GLOW_PAD, RADIUS, RING_H, ringWidth, ringZ, TUBE } from "../tunnel/layout"
import { CORE_ON_S, FAILING_RING, RING_COUNT, ringOnAt, SEQUENCE_S } from "./timeline"
import { FAILING_PATTERN, flickerPattern, intensityAt } from "./flicker"

// The intro's corridor: the TunnelScope mark's rings, standing still in the
// dark, switched on one by one from the far end toward the viewer, like a row
// of old ceiling lights coming on down a hallway. Driven purely by elapsed
// time, so a slow first frame never desyncs it from the wordmark.

const VIOLET = new Color("#8B5CF6")
const HOT = new Color("#DDD2FE") // the tube's white-hot moment as it catches

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

    // rings shaped to the window at start (the intro is short; no rebuild on resize)
    const W = ringWidth((host.clientWidth || 1) / (host.clientHeight || 1))
    const tube = band(W, RING_H, RADIUS, TUBE)
    const halo = new PlaneGeometry(W + GLOW_PAD * 2, RING_H + GLOW_PAD * 2)
    const glow = glowTexture(W, RING_H, RADIUS, GLOW_PAD)
    const rings = Array.from({ length: RING_COUNT }, (_, i) => {
      // i = 0 is the FARTHEST ring: it lights first
      const z = ringZ(i)
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
    const coreGeo = roundedSquare(0.55, 0.17)
    const coreMat = new MeshBasicMaterial({ color: VIOLET.clone(), transparent: true, opacity: 0 })
    const core = new Mesh(coreGeo, coreMat)
    core.position.z = CORE_Z
    scene.add(core)
    const corePattern = flickerPattern(3)

    const resize = () => {
      const w = host.clientWidth || 1
      const h = host.clientHeight || 1
      renderer.setSize(w, h, false)
      renderer.domElement.style.width = "100%"
      renderer.domElement.style.height = "100%"
      fitCamera(camera, w, h)
    }

    const draw = (s: number) => {
      // a slow creep down the corridor while the lights come on
      const p = Math.min(1, s / SEQUENCE_S)
      // ends exactly where the page-background tunnel's camera rests
      camera.position.set(0, 0, CAMERA_Z + 0.55 * Math.pow(1 - p, 3))
      camera.lookAt(0, 0, CORE_Z)

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
