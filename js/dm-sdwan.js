customElements.define('dm-sdwan', class DmSdwan extends HTMLElement {
  static observedAttributes = ['manager']
  #manager
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
    const r = await fetch(this.manager + '/j_security_check', {
      method: 'POST',
      body: new URLSearchParams(this.cred),
      credentials: 'include'
    })
    if (!r.ok) throw r
    this.token = await fetch(this.manager + '/dataservice/client/token', {
      credentials: 'include'
    }).then(r => r.text())
  }
})
