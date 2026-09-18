import { useEffect, useRef } from "react"
import {
  BufferGeometry,
  Color,
  LineBasicMaterial,
  LineLoop,
  Mesh,
  MeshBasicMaterial,
  PerspectiveCamera,
  Scene,
  Shape,
  ShapeGeometry,
  Vector3,
  WebGLRenderer,
} from "three"

// The TunnelScope mark (concentric rounded squares receding to a solid core)
// extruded into real depth. It is the drop target's one authored moment, and its
// motion reports state, never decoration:
//   idle     slow drift toward the viewer
//   over     a capture is being dragged over the page: faster, brighter
//   busy     analysing: fastest, with a slow twist down the tunnel
//   pos/neg/warn   a result just landed: the rings take the posture colour
//   error    the file was refused or could not be parsed
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
const SPEED: Record<TunnelState, number> = { idle: 0.55, over: 1.9, busy: 3.4, pos: 0.7, neg: 0.7, warn: 0.7, error: 0.4 }
const TWIST: Record<TunnelState, number> = { idle: 0, over: 0.02, busy: 0.075, pos: 0, neg: 0, warn: 0, error: 0 }
const GAIN: Record<TunnelState, number> = { idle: 0.8, over: 1.25, busy: 1.1, pos: 1.15, neg: 1.15, warn: 1, error: 1 }

const RINGS = 22
const SPAN = 26 // depth of the tunnel, world units
const NEAR = 2.6 // rings recycle once they pass this z

function roundedSquare(size: number, radius: number, perCorner = 10): Vector3[] {
  const h = size / 2
  const r = Math.min(radius, h)
  const corners: [number, number, number][] = [
    [h - r, h - r, 0],
    [-(h - r), h - r, Math.PI / 2],
    [-(h - r), -(h - r), Math.PI],
    [h - r, -(h - r), (3 * Math.PI) / 2],
  ]
  const pts: Vector3[] = []
  for (const [cx, cy, start] of corners) {
    for (let i = 0; i <= perCorner; i++) {
      const a = start + (i / perCorner) * (Math.PI / 2)
      pts.push(new Vector3(cx + r * Math.cos(a), cy + r * Math.sin(a), 0))
    }
  }
  return pts
}

function smooth(x: number) {
  const t = Math.min(1, Math.max(0, x))
  return t * t * (3 - 2 * t)
}

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

    const ringGeometry = new BufferGeometry().setFromPoints(roundedSquare(2.2, 0.6))
    const rings: { line: LineLoop; material: LineBasicMaterial }[] = []
    for (let i = 0; i < RINGS; i++) {
      const material = new LineBasicMaterial({ color: COLOR.idle, transparent: true, opacity: 0 })
      const line = new LineLoop(ringGeometry, material)
      line.position.z = NEAR - (i / RINGS) * (SPAN + NEAR)
      scene.add(line)
      rings.push({ line, material })
    }

    // the solid core at the far end of the tunnel (the logo's centre square)
    const coreShape = new Shape()
    const core = roundedSquare(0.5, 0.16, 6)
    coreShape.moveTo(core[0].x, core[0].y)
    core.slice(1).forEach((p) => coreShape.lineTo(p.x, p.y))
    const coreGeometry = new ShapeGeometry(coreShape)
    const coreMaterial = new MeshBasicMaterial({ color: COLOR.idle, transparent: true, opacity: 0.9 })
    const coreMesh = new Mesh(coreGeometry, coreMaterial)
    coreMesh.position.z = -SPAN * 0.62
    scene.add(coreMesh)

    const color = new Color(COLOR.idle)
    const target = new Color(COLOR.idle)
    let speed = SPEED.idle
    let twist = 0
    let gain = GAIN.idle
    const pointer = { x: 0, y: 0 }

    const resize = () => {
      const w = host.clientWidth || 1
      const h = host.clientHeight || 1
      renderer.setSize(w, h, false)
      renderer.domElement.style.width = "100%"
      renderer.domElement.style.height = "100%"
      camera.aspect = w / h
      camera.updateProjectionMatrix()
    }

    const draw = (dt: number) => {
      const s = stateRef.current
      const k = 1 - Math.exp(-dt * 4) // exponential ease toward the state's targets
      target.set(COLOR[s])
      color.lerp(target, k)
      speed += (SPEED[s] - speed) * k
      twist += (TWIST[s] - twist) * k
      gain += (GAIN[s] - gain) * k

      for (const { line, material } of rings) {
        if (!reduceMotion) {
          line.position.z += speed * dt
          if (line.position.z > NEAR) line.position.z -= SPAN + NEAR
        }
        const z = line.position.z
        const depth = (z + SPAN) / SPAN // 0 far … 1 near
        material.opacity = smooth(depth * 1.4) * smooth((NEAR - z) / 1.6) * 0.62 * gain
        material.color.copy(color)
        line.rotation.z = z * twist
      }
      coreMaterial.color.copy(color)
      coreMesh.rotation.z = coreMesh.position.z * twist

      camera.position.x += (pointer.x * 0.35 - camera.position.x) * k
      camera.position.y += (pointer.y * 0.25 - camera.position.y) * k
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

    const onPointer = (e: PointerEvent) => {
      if (reduceMotion) return
      const r = host.getBoundingClientRect()
      pointer.x = ((e.clientX - r.left) / r.width - 0.5) * 2
      pointer.y = -((e.clientY - r.top) / r.height - 0.5) * 2
    }
    window.addEventListener("pointermove", onPointer, { passive: true })

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
      document.removeEventListener("visibilitychange", onVisibility)
      ro.disconnect()
      io.disconnect()
      rings.forEach(({ material }) => material.dispose())
      ringGeometry.dispose()
      coreGeometry.dispose()
      coreMaterial.dispose()
      renderer.dispose()
      renderer.domElement.remove()
    }
  }, [onUnsupported])

  return <div ref={hostRef} className={className} />
}
