// The browser around the app: iOS's storage eviction and persistent storage.

/** iOS and iPadOS (which reports itself as a Mac with a touch screen). */
export function isIOS(): boolean {
  return /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1)
}

/** Running from the home screen, not in a browser tab. */
export function isStandalone(): boolean {
  return matchMedia('(display-mode: standalone)').matches || (navigator as unknown as { standalone?: boolean }).standalone === true
}

/** Safari on iOS deletes a site's storage after seven days without a visit unless the site is
 * installed to the home screen: the app makes no device key there until it runs installed. */
export function mayHoldKeys(): boolean {
  return !isIOS() || isStandalone()
}

/** Asks the browser to keep this site's storage (it may say no). */
export async function persist(): Promise<boolean> {
  if (!navigator.storage?.persist) return false
  if (await navigator.storage.persisted()) return true
  return navigator.storage.persist()
}

export async function persisted(): Promise<boolean | undefined> {
  return navigator.storage?.persisted ? navigator.storage.persisted() : undefined
}
