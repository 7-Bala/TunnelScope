// Plays on every load (user's choice, 2026-09-18); never under reduced motion.
// Read once by App so the page-background tunnel knows to wait, lit, under it.
export function shouldPlayIntro(): boolean {
  try {
    return !window.matchMedia("(prefers-reduced-motion: reduce)").matches
  } catch {
    return false
  }
}
