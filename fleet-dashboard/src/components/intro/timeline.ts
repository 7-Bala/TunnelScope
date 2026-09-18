// One clock for the intro: the WebGL corridor and the HTML wordmark both read
// these, so the words land exactly as the last light catches.

export const RING_COUNT = 16
/** the core at the far end flickers on first: the source the light comes from */
export const CORE_ON_S = 0.35
const FIRST_RING_S = 0.8
const RINGS_SPAN_S = 1.6

/**
 * The faulty light, a little past the middle: it catches, dies, then catches
 * again. The rings nearer the viewer wait for it (the corridor stalls), so
 * FAIL_STALL_S is its longer pattern (1.22s, IntroTunnel) minus the usual gap to
 * the next ring, so the next light starts just after it finally catches.
 */
export const FAILING_RING = 9
export const FAIL_STALL_S = 1.15

/**
 * When ring i (0 = farthest) starts to flicker on. The gaps shrink as the
 * lights approach: slow and uncertain far away, then rushing at the viewer.
 */
export function ringOnAt(i: number): number {
  const x = i / (RING_COUNT - 1)
  const stall = i > FAILING_RING ? FAIL_STALL_S : 0
  return FIRST_RING_S + RINGS_SPAN_S * (1 - Math.pow(1 - x, 1.7)) + stall
}

/** last ring switched on plus its flicker */
export const SEQUENCE_S = ringOnAt(RING_COUNT - 1) + 0.3
export const WORDMARK_S = SEQUENCE_S - 0.05
export const LEAVE_S = SEQUENCE_S + 1.7 // long enough to read the wordmark once it has fully resolved
export const FADE_MS = 550
