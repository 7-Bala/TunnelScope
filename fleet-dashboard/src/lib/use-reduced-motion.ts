import { useEffect, useState } from "react"

// Recharts' own draw-in animation is imperative JS (react-smooth, driven by
// requestAnimationFrame), not a CSS animation/transition — so the blanket
// `prefers-reduced-motion` rule in index.css (which forces CSS animation/
// transition durations to ~0) cannot reach it. Charts gate their own
// `isAnimationActive` on this hook so reduced-motion users see the resting
// state immediately, same intent as the CSS rule, for the one thing CSS
// can't cover.
export function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(
    () => typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches,
  )
  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)")
    const onChange = () => setReduced(mq.matches)
    mq.addEventListener("change", onChange)
    return () => mq.removeEventListener("change", onChange)
  }, [])
  return reduced
}
