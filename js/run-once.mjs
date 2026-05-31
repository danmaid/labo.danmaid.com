export function runOnce(fn, delay = 0) {
  runOnce.timers ??= new WeakMap()
  const timers = runOnce.timers
  clearTimeout(timers.get(fn))
  timers.set(fn, setTimeout(fn, delay))
}
