export class ZatsuMap extends Map {
  set(key, value) {
    return super.set(key, new WeakRef(value))
  }

  get(key) {
    const ref = super.get(key)
    if (!ref) return undefined

    const value = ref.deref()
    if (!value) {
      super.delete(key) // ゴミ掃除
      return undefined
    }
    return value
  }

  *keys() {
    for (const [key, ref] of super.entries()) {
      if (!ref.deref()) super.delete(key) // ゴミ掃除
      else yield key
    }
  }


  // iteration 系は「使うついでに掃除」
  *values() {
    for (const [key, ref] of super.entries()) {
      const value = ref.deref()
      if (!value) {
        super.delete(key)
        continue
      }
      yield value
    }
  }

  // ---- ここから「使わせない API」 ----

  has() {
    throw new Error('ZatsuMap does not support has(). Use get() only.')
  }

  entries() {
    throw new Error('ZatsuMap does not support entries().')
  }

  forEach() {
    throw new Error('ZatsuMap does not support forEach().')
  }
}
