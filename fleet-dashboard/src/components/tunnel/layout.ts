import { PerspectiveCamera } from "three"

// The one corridor. The intro lights it; the page background is the same
// corridor dimmed, so the hand-over between them is the same rings settling,
// not two scenes cross-fading.

export const RING_COUNT = 16
export const FAR_Z = -24
export const NEAR_Z = 1.55 // the nearest ring frames the screen like a doorway
export const SPACING = (NEAR_Z - FAR_Z) / (RING_COUNT - 1)
export const RING_H = 2.6
export const RADIUS = 0.6
export const TUBE = 0.036
export const GLOW_PAD = 0.9
export const CORE_Z = FAR_Z - 3
/** where the intro's camera ends, and the background's camera rests */
export const CAMERA_Z = 4.15

/** rings stretch to the window, within limits: a wide screen gets a wide
 *  corridor, a phone keeps a square one */
export function ringWidth(aspect: number) {
  return RING_H * Math.min(1.8, Math.max(1, aspect))
}

export function ringZ(i: number) {
  return FAR_Z + i * SPACING
}

export function fitCamera(camera: PerspectiveCamera, w: number, h: number) {
  camera.aspect = w / h
  camera.fov = w / h < 1 ? 62 : 46
  camera.updateProjectionMatrix()
}
