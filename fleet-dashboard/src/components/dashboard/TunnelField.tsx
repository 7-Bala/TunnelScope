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
import { band, dotTexture, glowTexture, roundedSquare } from "../tunnel/geometry"

// The TunnelScope mark (concentric rounded squares receding to a solid core)
// as a lit tunnel, the drop target's one authored moment. Its motion reports
// state, never decoration:
//   idle     slow drift toward the viewer; a pulse of light every few seconds
//   over     a capture is being dragged over the page: faster, brighter
//   busy     analysing: fastest, a slow twist, pulses and packets streaming
//   pos/neg/warn   a result just landed: the tunnel takes the posture colour
//   error    the file was refused or could not be parsed
// Interactive: it leans toward the pointer (bounded, eases back when the
// pointer leaves), and a click sends a pulse down to the core, which flashes.
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
const SPEED: Record<TunnelState, number> = { idle: 0.55, over: 1.9, busy: 3.4, pos: 0.7, neg: 0.7, warn: 0.7, error: 0.4 }
const TWIST: Record<TunnelState, number> = { idle: 0, over: 0.02, busy: 0.075, pos: 0, neg: 0, warn: 0, error: 0 }
const GAIN: Record<TunnelState, number> = { idle: 0.85, over: 1.3, busy: 1.15, pos: 1.15, neg: 1.15, warn: 1, error: 1 }
/** seconds between ambient pulses of light coming out of the tunnel */
const PULSE_EVERY: Record<TunnelState, number> = { idle: 3.4, over: 1.1, busy: 0.55, pos: 2.2, neg: 2.2, warn: 2.2, error: 99 }

const RINGS = 20
const SPAN = 26 // depth of the tunnel, world units
const NEAR = 2.6 // rings recycle once they pass this z
const SIZE = 2.2
const RADIUS = 0.6
const GLOW_PAD = 0.7
const CORE_Z = -SPAN * 0.62
const PACKETS = 70
const WAVE_SPEED = 15 // world units / s
const WAVE_WIDTH = 1.4

function smooth(x: number) {
  const t = Math.min(1, Math.max(0, x))
  return t * t * (3 - 2 * t)
}
const clamp = (v: number, lo = -1, hi = 1) => Math.min(hi, Math.max(lo, v))

type Wave = { z: number; dir: 1 | -1; strength: number; ping: boolean }

export default function TunnelField({
  state,
  onUnsupported,
  className,
}: {
  state: TunnelState
  onUnsupported?: () => void
  className?: string
}) {
  const hostRef = useRef<HTMLDivElement>(null)
  const stateRef = useRef<TunnelState>(state)
  const kickRef = useRef<() => void>(() => {})

  useEffect(() => {
    stateRef.current = state
    kickRef.current()
  }, [state])

  useEffect(() => {
    const host = hostRef.current
    if (!host) return

    let renderer: WebGLRenderer
    try {
      renderer = new WebGLRenderer({ antialias: true, alpha: true, powerPreference: "low-power" })
    } catch {
      onUnsupported?.()
      return
    }
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    renderer.setClearColor(0x000000, 0)
    renderer.domElement.setAttribute("aria-hidden", "true")
    renderer.domElement.style.display = "block"
    host.appendChild(renderer.domElement)

    const scene = new Scene()
    const camera = new PerspectiveCamera(46, 1, 0.1, 100)
    camera.position.set(0, 0, 4.2)
    const world = new Group() // leans toward the pointer
    scene.add(world)

    // --- rings: a thin lit tube, and its glow behind it ---
    const tubeGeo = band(SIZE, RADIUS, 0.024)
    const glowGeo = new PlaneGeometry(SIZE + GLOW_PAD * 2, SIZE + GLOW_PAD * 2)
    const glowTex = glowTexture(SIZE, RADIUS, GLOW_PAD)
    const rings = Array.from({ length: RINGS }, (_, i) => {
      const tubeMat = new MeshBasicMaterial({ color: COLOR.idle, transparent: true, opacity: 0, depthWrite: false })
      const glowMat = new MeshBasicMaterial({
        map: glowTex, color: COLOR.idle, transparent: true, opacity: 0, blending: AdditiveBlending, depthWrite: false,
      })
      const ring = new Group()
      ring.add(new Mesh(glowGeo, glowMat), new Mesh(tubeGeo, tubeMat))
      ring.position.z = NEAR - (i / RINGS) * (SPAN + NEAR)
      world.add(ring)
      return { ring, tubeMat, glowMat }
    })

    // --- the core at the far end, with a breathing halo ---
    const dotTex = dotTexture()
    const coreGeo = roundedSquare(0.5, 0.16)
    const coreMat = new MeshBasicMaterial({ color: COLOR.idle, transparent: true, opacity: 0.95 })
    const core = new Mesh(coreGeo, coreMat)
    core.position.z = CORE_Z
    const haloGeo = new PlaneGeometry(3.2, 3.2)
    const haloMat = new MeshBasicMaterial({
      map: dotTex, color: COLOR.idle, transparent: true, opacity: 0.3, blending: AdditiveBlending, depthWrite: false,
    })
    const halo = new Mesh(haloGeo, haloMat)
    halo.position.z = CORE_Z - 0.05
    world.add(halo, core)

    // --- packets: specks of light travelling out of the tunnel ---
    const pos = new Float32Array(PACKETS * 3)
    const col = new Float32Array(PACKETS * 3)
    const pace = new Float32Array(PACKETS)
    const seed = (i: number, anywhere: boolean) => {
      // somewhere inside the tunnel's cross-section, biased toward the walls
      const a = Math.random() * Math.PI * 2
      const r = 0.35 + Math.sqrt(Math.random()) * 0.6
      pos[i * 3] = Math.cos(a) * r * (SIZE / 2) * 0.9
      pos[i * 3 + 1] = Math.sin(a) * r * (SIZE / 2) * 0.9
      pos[i * 3 + 2] = anywhere ? NEAR - Math.random() * (SPAN + NEAR) : -SPAN
      pace[i] = 1.6 + Math.random() * 1.8
    }
    for (let i = 0; i < PACKETS; i++) seed(i, true)
    const packetGeo = new BufferGeometry()
    packetGeo.setAttribute("position", new BufferAttribute(pos, 3))
    packetGeo.setAttribute("color", new BufferAttribute(col, 3))
    const packetMat = new PointsMaterial({
      map: dotTex, size: 0.085, sizeAttenuation: true, vertexColors: true,
      transparent: true, blending: AdditiveBlending, depthWrite: false,
    })
    world.add(new Points(packetGeo, packetMat))

    // --- live state ---
    const color = new Color(COLOR.idle)
    const target = new Color(COLOR.idle)
    const scratch = new Color()
    let speed = SPEED.idle
    let twist = 0
    let gain = GAIN.idle
    let hover = 0
    let flash = 0
    let clock = 0
    let nextPulse = 1.2
    const waves: Wave[] = []
    const pointer = { x: 0, y: 0, tx: 0, ty: 0, inside: false }

    const resize = () => {
      const w = host.clientWidth || 1
      const h = host.clientHeight || 1
      renderer.setSize(w, h, false)
      renderer.domElement.style.width = "100%"
      renderer.domElement.style.height = "100%"
      camera.aspect = w / h
      camera.updateProjectionMatrix()
    }

    const waveBoost = (z: number) => {
      let b = 0
      for (const w of waves) b += w.strength * Math.exp(-(((z - w.z) / WAVE_WIDTH) ** 2))
      return b
    }

    const draw = (dt: number) => {
      const s = stateRef.current
      const k = 1 - Math.exp(-dt * 4) // exponential ease toward the state's targets
      clock += dt
      target.set(COLOR[s])
      color.lerp(target, k)
      speed += (SPEED[s] - speed) * k
      twist += (TWIST[s] - twist) * k
      gain += (GAIN[s] - gain) * k
      hover += ((pointer.inside ? 1 : 0) - hover) * k
      flash *= Math.exp(-dt * 3.5)

      // ambient pulses come out of the tunnel; clicks go in (ping)
      if (!reduceMotion && clock >= nextPulse) {
        waves.push({ z: CORE_Z, dir: 1, strength: 0.55, ping: false })
        nextPulse = clock + PULSE_EVERY[s]
      }
      for (let i = waves.length - 1; i >= 0; i--) {
        const w = waves[i]
        w.z += w.dir * WAVE_SPEED * dt
        if (w.ping && w.z <= CORE_Z) {
          flash = 1 // the ping reached the core
          waves.splice(i, 1)
        } else if (w.z > NEAR + 2 || w.z < CORE_Z - 2) waves.splice(i, 1)
      }

      const lit = gain * (1 + hover * 0.18)
      for (const { ring, tubeMat, glowMat } of rings) {
        if (!reduceMotion) {
          ring.position.z += speed * dt
          if (ring.position.z > NEAR) ring.position.z -= SPAN + NEAR
        }
        const z = ring.position.z
        const depth = (z + SPAN) / SPAN // 0 far … 1 near
        const fade = smooth(depth * 1.4) * smooth((NEAR - z) / 1.6)
        const b = waveBoost(z)
        tubeMat.opacity = Math.min(1, fade * (0.5 + b * 0.9) * lit)
        glowMat.opacity = fade * (0.16 + b * 0.75) * lit
        tubeMat.color.copy(color).lerp(HOT, Math.min(1, b * 0.7))
        glowMat.color.copy(color)
        ring.rotation.z = z * twist
      }

      const breathe = reduceMotion ? 0 : Math.sin(clock * 1.7) * 0.08
      coreMat.color.copy(color).lerp(HOT, flash * 0.8)
      haloMat.color.copy(color)
      haloMat.opacity = (0.28 + breathe + flash * 0.9) * lit
      halo.scale.setScalar(1 + flash * 0.6 + breathe)
      core.rotation.z = halo.rotation.z = CORE_Z * twist

      for (let i = 0; i < PACKETS; i++) {
        if (!reduceMotion) {
          pos[i * 3 + 2] += speed * pace[i] * dt
          if (pos[i * 3 + 2] > NEAR) seed(i, false)
        }
        const z = pos[i * 3 + 2]
        const fade = smooth(((z + SPAN) / SPAN) * 1.6) * smooth((NEAR - z) / 1.2)
        const bright = fade * (0.45 + waveBoost(z) * 1.2) * lit
        scratch.copy(color).lerp(HOT, 0.35).multiplyScalar(bright)
        col[i * 3] = scratch.r
        col[i * 3 + 1] = scratch.g
        col[i * 3 + 2] = scratch.b
      }
      packetGeo.attributes.position.needsUpdate = true
      packetGeo.attributes.color.needsUpdate = true

      // lean toward the pointer, bounded, easing home when it leaves
      pointer.x += (pointer.tx - pointer.x) * k
      pointer.y += (pointer.ty - pointer.y) * k
      camera.position.x = pointer.x * 0.32
      camera.position.y = pointer.y * 0.22
      world.rotation.y = pointer.x * 0.06
      world.rotation.x = -pointer.y * 0.045
      camera.lookAt(0, 0, -SPAN * 0.5)
      renderer.render(scene, camera)
    }

    let last = performance.now()
    let running = false
    const loop = () => {
      const now = performance.now()
      const dt = Math.min(0.05, (now - last) / 1000)
      last = now
      draw(dt)
    }
    const start = () => {
      if (running || reduceMotion) return
      running = true
      last = performance.now()
      renderer.setAnimationLoop(loop)
    }
    const stop = () => {
      running = false
      renderer.setAnimationLoop(null)
    }
    // reduced motion: no loop, but a state change still repaints (colour and gain snap)
    kickRef.current = () => {
      if (reduceMotion) draw(1)
    }

    // Pointer: normalised to the tunnel panel and CLAMPED, so a pointer far
    // outside it (over the button, across the page) can't swing the camera off
    // centre; outside the panel it eases back home.
    const onPointer = (e: PointerEvent) => {
      if (reduceMotion) return
      const r = host.getBoundingClientRect()
      const inside = e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom
      pointer.inside = inside
      pointer.tx = inside ? clamp(((e.clientX - r.left) / r.width - 0.5) * 2) : 0
      pointer.ty = inside ? clamp(-((e.clientY - r.top) / r.height - 0.5) * 2) : 0
    }
    const onLeave = () => {
      pointer.inside = false
      pointer.tx = pointer.ty = 0
    }
    const onClick = () => {
      if (reduceMotion) return
      waves.push({ z: NEAR + 0.5, dir: -1, strength: 1.1, ping: true })
    }
    window.addEventListener("pointermove", onPointer, { passive: true })
    document.documentElement.addEventListener("pointerleave", onLeave)
    host.addEventListener("click", onClick)

    const ro = new ResizeObserver(() => {
      resize()
      if (!running) draw(0)
    })
    ro.observe(host)
    let visible = true
    const io = new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting
      if (visible && !document.hidden) start()
      else stop()
    })
    io.observe(host)
    const onVisibility = () => (document.hidden || !visible ? stop() : start())
    document.addEventListener("visibilitychange", onVisibility)

    resize()
    draw(reduceMotion ? 1 : 0)
    start()

    return () => {
      stop()
      kickRef.current = () => {}
      window.removeEventListener("pointermove", onPointer)
      document.documentElement.removeEventListener("pointerleave", onLeave)
      host.removeEventListener("click", onClick)
      document.removeEventListener("visibilitychange", onVisibility)
      ro.disconnect()
      io.disconnect()
      rings.forEach(({ tubeMat, glowMat }) => (tubeMat.dispose(), glowMat.dispose()))
      ;[tubeGeo, glowGeo, coreGeo, haloGeo, packetGeo].forEach((g) => g.dispose())
      ;[coreMat, haloMat, packetMat].forEach((m) => m.dispose())
      glowTex.dispose()
      dotTex.dispose()
      renderer.dispose()
      renderer.domElement.remove()
    }
  }, [onUnsupported])

  return <div ref={hostRef} className={className} style={{ cursor: "pointer" }} title="Click to send a pulse down the tunnel" />
}
