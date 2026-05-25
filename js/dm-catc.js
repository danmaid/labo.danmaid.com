customElements.define('dm-catc', class DmCatC extends HTMLElement {
  static observedAttributes = ['server']
  #server = ''
  get server() { return this.#server }
  token = ''
  cred

  attributeChangedCallback(name, oldValue, newValue) {
    if (name === 'server') return this.#server = newValue
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
    this.cred = JSON.parse(localStorage.getItem('dm-catc'))
    if (this.cred) {
      user.value = this.cred.username
      pass.value = '************'
    }
    shadow.querySelector('#set').addEventListener('click', () => {
      this.cred = { username: user.value, password: pass.value }
      localStorage.setItem('dm-catc', JSON.stringify(this.cred))
    })
  }

  /** @type {(path: string, init?: RequestInit) => Promise<Response>} */
  async fetch(path, init, ctx = {}) {
    const url = this.server + path
    const headers = new Headers(init?.headers)
    if (!headers.has('X-Auth-Token')) headers.set('X-Auth-Token', this.token)
    if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
    const res = await fetch(url, { ...init, headers, credentials: 'include' })
    if (res.status === 401) {
      if (!ctx?.retry) return this.auth().then(() => this.fetch(path, init, { retry: true }))
    }
    return res
  }

  async auth() {
    const { Token } = await fetch(this.server + '/dna/system/api/v1/auth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Basic ' + btoa(this.cred.username + ':' + this.cred.password)
      },
    }).then(r => r.json())
    this.token = Token
  }
})
