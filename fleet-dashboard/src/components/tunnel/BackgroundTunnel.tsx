import { useEffect, useRef } from "react"
import {
  AdditiveBlending,
  BufferAttribute,
  BufferGeometry,
  Color,
  Group,
  Mesh,
  MeshBasicMaterial,
  PerspectiveCamera,
  PlaneGeometry,
  Points,
  PointsMaterial,
  Scene,
  WebGLRenderer,
} from "three"
import { band, dotTexture, glowTexture, roundedSquare } from "./geometry"
import {
  CAMERA_Z, CORE_Z, FAR_Z, fitCamera, GLOW_PAD, NEAR_Z, RADIUS, RING_COUNT, RING_H, ringWidth, ringZ, SPACING, TUBE,
} from "./layout"

// The page background: the intro's corridor, still there after the intro,
// dimmed to a whisper and sitting behind the top of the page. It fades out
// lower on screen and as the page scrolls, so the data below always sits on
// plain black, and it stops rendering once it can't be seen.
//
// Its motion still reports state:
//   idle     slow drift, a faint pulse of light every few seconds
//   over     a capture is dragged over the page: the whole corridor brightens
//   busy     analysing: faster, a slow twist, packets of light streaming out
//   pos/neg/warn   a result just landed: the corridor takes the posture colour
//   error    the file was refused or could not be parsed
//
// Hand-over: while the intro plays (`lit`), this holds the intro's final frame
// (every ring fully lit, vanishing point centred) underneath it; when the
// intro leaves, the same rings dim and the vanishing point drifts up behind
// the upload panel.
export type TunnelState = "idle" | "over" | "busy" | "pos" | "neg" | "warn" | "error"

const COLOR: Record<TunnelState, string> = {
  // index.css tokens (WebGL cannot read CSS variables): --violet, --pos, --neg, --warn
  idle: "#8B5CF6",
  over: "#8B5CF6",
  busy: "#8B5CF6",
  pos: "#22C55E",
  neg: "#EF4444",
  warn: "#F2B33D",
  error: "#EF4444",
}
const HOT = new Color("#E4DAFF")
const SPEED: Record<TunnelState, number> = { idle: 0.35, over: 1.6, busy: 2.6, pos: 0.5, neg: 0.5, warn: 0.5, error: 0.3 }
const TWIST: Record<TunnelState, number> = { idle: 0, over: 0.012, busy: 0.045, pos: 0, neg: 0, warn: 0, error: 0 }
/** brightness at rest, relative to the resting level */
const GAIN: Record<TunnelState, number> = { idle: 1, over: 2.3, busy: 1.8, pos: 1.9, neg: 1.9, warn: 1.7, error: 1.6 }
/** seconds between pulses of light coming out of the tunnel */
const PULSE_EVERY: Record<TunnelState, number> = { idle: 6, over: 1.1, busy: 0.6, pos: 2.5, neg: 2.5, warn: 2.5, error: 99 }

/** the resting brightness: a whisper behind the page */
const REST = 0.3 // raised from 0.17 on request (2026-09-18); see NEAR_DIM for why that stays readable
/** the vanishing point at rest: NDC y, i.e. about a third of the way down, behind the upload panel */
const REST_VP = 0.3
/** at rest, the rings nearest the viewer are the largest on screen and cross
 *  the header text, so they are toned down to this fraction; the brightness
 *  lives in the deep corridor behind the upload panel instead */
const NEAR_DIM = 0.22
const NEAR_DIM_SPAN = SPACING * 5
const WRAP = RING_COUNT * SPACING
const PACKETS = 60
const WAVE_SPEED = 13
const WAVE_WIDTH = 1.6

const smooth = (x: number) => {
  const t = Math.min(1, Math.max(0, x))
  return t * t * (3 - 2 * t)
}
const clamp = (v: number, lo = -1, hi = 1) => Math.min(hi, Math.max(lo, v))
const mix = (a: number, b: number, t: number) => a + (b - a) * t

type Wave = { z: number; strength: number }

export default function BackgroundTunnel({
  state,
  lit,
  className,
  style,
}: {
  state: TunnelState
  /** true while the intro is playing on top: hold its final, fully lit frame */
  lit: boolean
  className?: string
  style?: React.CSSProperties
}) {
  const hostRef = useRef<HTMLDivElement>(null)
  const stateRef = useRef<TunnelState>(state)
  const litRef = useRef(lit)
  const kickRef = useRef<() => void>(() => {})

  useEffect(() => {
    stateRef.current = state
    kickRef.current()
  }, [state])
  useEffect(() => {
    litRef.current = lit
    kickRef.current()
  }, [lit])

  useEffect(() => {
    const host = hostRef.current
    if (!host) return

    let renderer: WebGLRenderer
    try {
      renderer = new WebGLRenderer({ antialias: true, alpha: true, powerPreference: "low-power" })
    } catch {
      return // no WebGL: the page is simply plain black behind, which is fine
    }
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches
    // a full-screen canvas at 2x on a large display is a lot of pixels for a
    // background this dim; 1.5x is indistinguishable at this brightness
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5))
    renderer.setClearColor(0x000000, 0)
    renderer.domElement.setAttribute("aria-hidden", "true")
    renderer.domElement.style.display = "block"
    host.appendChild(renderer.domElement)

    const scene = new Scene()
    const camera = new PerspectiveCamera(46, 1, 0.1, 100)
    camera.position.set(0, 0, CAMERA_Z)
    const world = new Group()
    scene.add(world)

    // --- rings (geometry rebuilt when the window's shape changes) ---
    let ringW = 0
    let tubeGeo: BufferGeometry | null = null
    let glowGeo: BufferGeometry | null = null
    let glowTex: ReturnType<typeof glowTexture> | null = null
    const rings = Array.from({ length: RING_COUNT }, (_, i) => {
      const tubeMat = new MeshBasicMaterial({ color: COLOR.idle, transparent: true, opacity: 0, depthWrite: false })
      const glowMat = new MeshBasicMaterial({
        color: COLOR.idle, transparent: true, opacity: 0, blending: AdditiveBlending, depthWrite: false,
      })
      const tube = new Mesh(undefined, tubeMat)
      const glow = new Mesh(undefined, glowMat)
      const ring = new Group()
      ring.add(glow, tube)
      ring.position.z = ringZ(i) // exactly where the intro left each ring
      world.add(ring)
      return { ring, tube, glow, tubeMat, glowMat }
    })
    const shapeRings = (aspect: number) => {
      const w = ringWidth(aspect)
      if (Math.abs(w - ringW) < 0.01) return
      ringW = w
      tubeGeo?.dispose()
      glowGeo?.dispose()
      glowTex?.dispose()
      tubeGeo = band(w, RING_H, RADIUS, TUBE)
      glowGeo = new PlaneGeometry(w + GLOW_PAD * 2, RING_H + GLOW_PAD * 2)
      glowTex = glowTexture(w, RING_H, RADIUS, GLOW_PAD)
      for (const r of rings) {
        r.tube.geometry = tubeGeo
        r.glow.geometry = glowGeo
        r.glowMat.map = glowTex
        r.glowMat.needsUpdate = true
      }
    }

    // --- the core at the far end, with a breathing halo ---
    const dotTex = dotTexture()
    const coreGeo = roundedSquare(0.55, 0.17)
    const coreMat = new MeshBasicMaterial({ color: COLOR.idle, transparent: true, opacity: 1 })
    const core = new Mesh(coreGeo, coreMat)
    core.position.z = CORE_Z
    const haloGeo = new PlaneGeometry(3.4, 3.4)
    const haloMat = new MeshBasicMaterial({
      map: dotTex, color: COLOR.idle, transparent: true, opacity: 0, blending: AdditiveBlending, depthWrite: false,
    })
    const halo = new Mesh(haloGeo, haloMat)
    halo.position.z = CORE_Z - 0.05
    world.add(halo, core)

    // --- packets of light: only while a capture is being analysed ---
    const pos = new Float32Array(PACKETS * 3)
    const col = new Float32Array(PACKETS * 3)
    const pace = new Float32Array(PACKETS)
    const seed = (i: number, anywhere: boolean) => {
      const a = Math.random() * Math.PI * 2
      const r = 0.35 + Math.sqrt(Math.random()) * 0.6
      pos[i * 3] = Math.cos(a) * r * (ringW || RING_H) * 0.45
      pos[i * 3 + 1] = Math.sin(a) * r * RING_H * 0.45
      pos[i * 3 + 2] = anywhere ? mix(FAR_Z, NEAR_Z, Math.random()) : FAR_Z - SPACING
      pace[i] = 1.6 + Math.random() * 1.8
    }
    const packetGeo = new BufferGeometry()
    packetGeo.setAttribute("position", new BufferAttribute(pos, 3))
    packetGeo.setAttribute("color", new BufferAttribute(col, 3))
    const packetMat = new PointsMaterial({
      map: dotTex, size: 0.09, sizeAttenuation: true, vertexColors: true,
      transparent: true, blending: AdditiveBlending, depthWrite: false,
    })
    world.add(new Points(packetGeo, packetMat))

    // --- live state ---
    const color = new Color(COLOR.idle)
    const target = new Color(COLOR.idle)
    const scratch = new Color()
    let settle = litRef.current ? 0 : 1 // 0 = the intro's lit frame, 1 = at rest
    let speed = 0
    let twist = 0
    let gain = 1
    let packets = 0
    let clock = 0
    let nextPulse = 2.5
    let fadeByScroll = 1
    const waves: Wave[] = []
    const pointer = { x: 0, y: 0, tx: 0, ty: 0 }

    const resize = () => {
      const w = host.clientWidth || 1
      const h = host.clientHeight || 1
      renderer.setSize(w, h, false)
      renderer.domElement.style.width = "100%"
      renderer.domElement.style.height = "100%"
      fitCamera(camera, w, h)
      shapeRings(w / h)
      for (let i = 0; i < PACKETS; i++) seed(i, true)
    }

    const waveBoost = (z: number) => {
      let b = 0
      for (const w of waves) b += w.strength * Math.exp(-(((z - w.z) / WAVE_WIDTH) ** 2))
      return b
    }

    /** dt drives motion, capped so a stall doesn't jump the rings */
    const draw = (dt: number) => {
      const s = stateRef.current
      const k = 1 - Math.exp(-dt * 4)
      clock += dt
      // T-080: the intro now exits by rushing into the core and cutting to the
      // page, so the corridor is simply at rest from the cut (the old 1.9s
      // dim-and-drift hand-over read as the background lagging behind)
      if (!litRef.current) settle = 1
      const u = smooth(settle) // ease of the hand-over
      target.set(COLOR[s])
      color.lerp(target, k)
      speed += ((u < 1 ? SPEED.idle * u : SPEED[s]) - speed) * k
      twist += (TWIST[s] - twist) * k
      gain += (GAIN[s] - gain) * k
      packets += ((s === "busy" ? 1 : 0) - packets) * k

      if (!reduceMotion && u === 1 && clock >= nextPulse) {
        waves.push({ z: CORE_Z, strength: 1 })
        nextPulse = clock + PULSE_EVERY[s]
      }
      for (let i = waves.length - 1; i >= 0; i--) {
        waves[i].z += WAVE_SPEED * dt
        if (waves[i].z > NEAR_Z + 3) waves.splice(i, 1)
      }

      // brightness: the intro's lit level, easing down to a whisper
      const level = mix(1, REST * gain, u)
      for (const { ring, tubeMat, glowMat } of rings) {
        if (!reduceMotion) {
          ring.position.z += speed * dt
          if (ring.position.z > NEAR_Z + SPACING * 0.6) ring.position.z -= WRAP
        }
        const z = ring.position.z
        // fade out as a ring passes the viewer, fade in at the far end; while
        // lit, every ring the intro showed is fully on (no seam at hand-over)
        const nearFade = smooth((NEAR_Z + SPACING * 0.6 - z) / (SPACING * 0.6))
        const farFade = mix(1, smooth((z - (FAR_Z - SPACING * 0.4)) / SPACING), u)
        const b = u === 1 ? waveBoost(z) : 0
        const nearDim = mix(1, NEAR_DIM + (1 - NEAR_DIM) * smooth((NEAR_Z - z) / NEAR_DIM_SPAN), u)
        const f = nearFade * farFade * nearDim
        tubeMat.opacity = Math.min(1, f * level * (1 + b * 1.4))
        glowMat.opacity = f * 0.55 * level * (1 + b * 2)
        tubeMat.color.copy(color).lerp(HOT, Math.min(1, b * 0.25 * u))
        glowMat.color.copy(color)
        ring.rotation.z = z * twist
      }

      const breathe = reduceMotion ? 0 : Math.sin(clock * 1.5) * 0.06
      coreMat.color.copy(color)
      coreMat.opacity = mix(1, 0.55 + gain * 0.1, u)
      haloMat.color.copy(color)
      haloMat.opacity = (0.35 + breathe) * mix(1, 0.4 * gain, u)
      core.rotation.z = halo.rotation.z = CORE_Z * twist

      for (let i = 0; i < PACKETS; i++) {
        if (!reduceMotion) {
          pos[i * 3 + 2] += speed * pace[i] * dt
          if (pos[i * 3 + 2] > NEAR_Z) seed(i, false)
        }
        const z = pos[i * 3 + 2]
        const fade = smooth((z - FAR_Z) / (SPACING * 3)) * smooth((NEAR_Z - z) / 1.2)
        scratch.copy(color).lerp(HOT, 0.35).multiplyScalar(fade * packets * 0.9)
        col[i * 3] = scratch.r
        col[i * 3 + 1] = scratch.g
        col[i * 3 + 2] = scratch.b
      }
      packetGeo.attributes.position.needsUpdate = true
      packetGeo.attributes.color.needsUpdate = true

      // a slight lean toward the pointer, only once settled
      pointer.x += (pointer.tx - pointer.x) * k
      pointer.y += (pointer.ty - pointer.y) * k
      camera.position.x = pointer.x * 0.12 * u
      camera.position.y = pointer.y * 0.08 * u
      camera.lookAt(0, 0, CORE_Z)
      // move the vanishing point up by shearing the projection (P[9]); the
      // camera itself stays on the corridor's axis
      camera.updateProjectionMatrix()
      camera.projectionMatrix.elements[9] = -REST_VP * u
      renderer.render(scene, camera)
    }

    let last = performance.now()
    let running = false
    const loop = () => {
      const now = performance.now()
      const raw = (now - last) / 1000
      last = now
      draw(Math.min(0.05, raw))
    }
    const shouldRun = () => !reduceMotion && !document.hidden && fadeByScroll > 0.001
    const start = () => {
      if (running || !shouldRun()) return
      running = true
      last = performance.now()
      renderer.setAnimationLoop(loop)
    }
    const stop = () => {
      running = false
      renderer.setAnimationLoop(null)
    }
    // reduced motion: no loop; a state change repaints once, straight to rest
    kickRef.current = () => {
      if (reduceMotion) {
        settle = litRef.current ? 0 : 1
        draw(1)
      } else start()
    }

    const onPointer = (e: PointerEvent) => {
      if (reduceMotion) return
      pointer.tx = clamp((e.clientX / window.innerWidth - 0.5) * 2)
      pointer.ty = clamp(-(e.clientY / window.innerHeight - 0.5) * 2)
    }
    // fade with scroll: gone by the time the data below reaches the top
    const onScroll = () => {
      fadeByScroll = 1 - smooth(window.scrollY / (window.innerHeight * 0.85))
      host.style.opacity = String(fadeByScroll)
      if (shouldRun()) start()
      else stop()
    }
    const onVisibility = () => (shouldRun() ? start() : stop())
    window.addEventListener("pointermove", onPointer, { passive: true })
    window.addEventListener("scroll", onScroll, { passive: true })
    document.addEventListener("visibilitychange", onVisibility)
    const ro = new ResizeObserver(() => {
      resize()
      if (!running) draw(0)
    })
    ro.observe(host)

    resize()
    onScroll()
    draw(reduceMotion ? 1 : 0)
    start()

    return () => {
      stop()
      kickRef.current = () => {}
      window.removeEventListener("pointermove", onPointer)
      window.removeEventListener("scroll", onScroll)
      document.removeEventListener("visibilitychange", onVisibility)
      ro.disconnect()
      rings.forEach(({ tubeMat, glowMat }) => (tubeMat.dispose(), glowMat.dispose()))
      ;[tubeGeo, glowGeo, coreGeo, haloGeo, packetGeo].forEach((g) => g?.dispose())
      ;[coreMat, haloMat, packetMat].forEach((m) => m.dispose())
      glowTex?.dispose()
      dotTex.dispose()
      renderer.dispose()
      renderer.domElement.remove()
    }
  }, [])

  return <div ref={hostRef} className={className} style={style} />
}
