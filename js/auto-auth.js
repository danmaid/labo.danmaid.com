{
  const credentials = new class Credentials extends EventTarget {
    get(key) {
      return localStorage.getItem('credentials.' + key)
    }
    set(key, value) {
      localStorage.setItem('credentials.' + key, value)
      this.dispatchEvent(new CustomEvent('change', { detail: { key } }))
    }
    has(key) {
      return localStorage.getItem('credentials.' + key) !== null
    }
  }

  /** @type {Record<string, (url: URL, args: Parameters<typeof fetch>) => void>} */
  const handlers = {
    'http://localhost:8080': async (url, args) => {
      // ここで認証などなど
    }
  }
  const proxy = new Proxy(window.fetch, {
    async apply(target, thisArg, args) {
      const [input] = args
      const url = new URL(input?.url ?? input, location.href)
      await handlers[url.origin]?.(url, args)
      return Reflect.apply(target, thisArg, args)
    }
  })
  globalThis.fetch = proxy
}
