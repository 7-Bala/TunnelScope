// How each tube switches on, as intensity over time since its turn (0 = off,
// 1 = steady, above 1 = the bloom as it catches). Pure, so it can be checked
// without WebGL.

// Deterministic per-ring flicker: 2-3 stutters, then the tube holds. Seeded so
// every visit looks the same (it is a title sequence, not noise).
export function flickerPattern(seed: number): [number, number][] {
  let x = seed * 9301 + 49297
  const rand = () => ((x = (x * 9301 + 49297) % 233280) / 233280)
  const stutters = 2 + Math.floor(rand() * 2)
  const out: [number, number][] = [] // [duration s, intensity]
  for (let i = 0; i < stutters; i++) {
    out.push([0.025 + rand() * 0.035, 0.55 + rand() * 0.45])
    out.push([0.03 + rand() * 0.06, 0])
  }
  return out
}

// A segment at this level is a catch: the over-bright bloom settling to steady.
const CATCH = -1

// The faulty tube: stutters, catches, dies with a couple of weak sputters,
// sits dark, then stutters again and catches for good. About 1.2s against the
// usual 0.2s; the rings behind it wait (timeline FAIL_STALL_S).
export const FAILING_PATTERN: [number, number][] = [
  [0.04, 0.8], [0.05, 0], [0.03, 0.7], [0.06, 0], // first attempt
  [0.28, CATCH],                                   // it catches...
  [0.05, 0.35], [0.07, 0], [0.04, 0.2], [0.1, 0],  // ...and dies, sputtering
  [0.3, 0],                                        // dark: will it come back?
  [0.03, 0.6], [0.08, 0], [0.04, 0.9], [0.05, 0], // second attempt
]                                                  // then it holds (final catch)

const bloom = (since: number) => 1 + 0.9 * Math.exp(-since / 0.16)

export function intensityAt(t: number, pattern: [number, number][]): number {
  if (t < 0) return 0
  let acc = 0
  for (const [dur, level] of pattern) {
    if (t < acc + dur) return level === CATCH ? bloom(t - acc) : level
    acc += dur
  }
  // held: a short over-bright bloom as the tube catches, settling to steady
  return bloom(t - acc)
}
