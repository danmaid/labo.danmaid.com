customElements.define('dm-sdwan', class DmSdwan extends HTMLElement {
  static observedAttributes = ['manager']
  #manager = ''
  get manager() { return this.#manager }
  token = ''
  cred

  attributeChangedCallback(name, oldValue, newValue) {
    if (name === 'manager') return this.#manager = newValue
  }

  constructor() {
    super()
    const shadow = this.attachShadow({ mode: 'open' })
    shadow.innerHTML = `
      <label>username: <input type="text" id="user"></label>
      <label>password: <input type="password" id="pass"></label>
      <button id="set">SET</button>
    `
    const user = shadow.querySelector('#user')
    const pass = shadow.querySelector('#pass')
    this.cred = JSON.parse(localStorage.getItem('dm-sdwan'))
    if (this.cred) {
      user.value = this.cred.j_username
      pass.value = '************'
    }
    shadow.querySelector('#set').addEventListener('click', () => {
      this.cred = { j_username: user.value, j_password: pass.value }
      localStorage.setItem('dm-sdwan', JSON.stringify(this.cred))
    })
  }

  /** @type {(path: string, init?: RequestInit) => Promise<Response>} */
  async fetch(path, init, ctx = {}) {
    const url = this.manager + '/dataservice' + path
    const headers = new Headers(init?.headers)
    if (!headers.has('X-XSRF-Token')) headers.set('X-XSRF-Token', this.token)
    if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
    const res = await fetch(url, { ...init, headers, credentials: 'include' })
    if (res.headers.get('Content-Type')?.includes('text/html')) {
      if (!ctx?.retry) return this.auth().then(() => this.fetch(path, init, { retry: true }))
    }
    return res
  }

  async auth() {
    const r = await fetch(this.manager + '/dataservice/j_security_check', {
      method: 'POST',
      body: new URLSearchParams(this.cred),
      credentials: 'include'
    })
    if (!r.ok) throw r
    this.token = await fetch(this.manager + '/dataservice/client/token', {
      credentials: 'include'
    }).then(r => r.text())
  }

  /**
   * example:
   * ```
   * const r = await sdwan.ssh('1.1.1.1')
   * const socket = new SdwanSshSocket(r.url) // like WebSocket
   * ```
   */
  async ssh(systemIp) {
    const r = await this.fetch(`/newssh/connection/${systemIp}`, {
      method: 'POST',
      body: JSON.stringify({
        username: 'dummy',
        password: 'dummy',
        height: 1000,
        width: 945.33
      })
    })
    if (!r.ok) throw r
    return await r.json()
  }
})

// ShellInABoxConnector
class SdwanSshSocket extends EventTarget {
  constructor(url) {
    super()
    const u = new URL(url)
    this.url = u.origin + u.pathname
    this.params = u.searchParams
    this.params.set('width', 100)
    this.params.set('height', 30)
    this.abort = new AbortController()
    this.open().then(() => this.poll())
      .catch(err => this.dispatchEvent(new ErrorEvent('error', { error: err })))
  }

  async open() {
    const body = new URLSearchParams(this.params)
    body.set('rooturl', this.url)
    const r = await fetch(this.url, {
      method: 'POST',
      body,
      credentials: 'include',
      signal: this.abort.signal,
    })
    if (!r.ok) throw new Error(`HTTP ${r.status}`)
    const { session } = await r.json()
    this.params.set('session', session)
    this.dispatchEvent(new Event('open'))
  }

  close() {
    this.abort.abort()
  }

  async poll() {
    while (!this.abort.signal.aborted) {
      try {
        const data = await this.receive()
        if (data) this.dispatchEvent(new MessageEvent('message', { data }))
      } catch (err) {
        if (err?.name === 'TimeoutError') continue
        if (err?.name === 'AbortError') break
        this.dispatchEvent(new ErrorEvent('error', { error: err }))
        this.close()
      }
    }
  }

  async receive() {
    const r = await fetch(this.url, {
      method: 'POST',
      body: this.params,
      credentials: 'include',
      signal: AbortSignal.any([this.abort.signal, AbortSignal.timeout(30000)])
    })
    if (!r.ok) throw new Error(`HTTP ${r.status}`)
    const d = await r.json()
    return d.data
  }

  queue = Promise.resolve()

  send(data) {
    return this.queue = this.queue
      .catch(() => { })
      .then(() => this._send(data))
  }

  async _send(data) {
    let hex = ''
    for (let i = 0; i < data.length; i++) {
      hex += data.charCodeAt(i).toString(16).toUpperCase().padStart(2, '0')
    }
    const body = new URLSearchParams(this.params)
    body.set('keys', hex)
    const r = await fetch(this.url, {
      method: 'POST',
      body,
      credentials: 'include',
      signal: this.abort.signal
    })
    if (!r.ok) throw new Error(`HTTP ${r.status}`)
  }
}
