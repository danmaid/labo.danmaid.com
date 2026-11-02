/**
 * <dm-credentials></dm-credentials> for login
 * <dm-credentials key="your-key"></dm-credentials> for view
 */
customElements.define('dm-credentials', class DmCredentials extends HTMLElement {
  static #vaultKey
  static storageKey = 'dm-credentials/'

  loginTemplate = `
    <div>
      <input type="text" placeholder="Vault Key" id="vaultKeyInput">
      <button id="loginButton">Login</button>
    </div>
  `
  viewTemplate = `
    <div>
      <p>Vault Key is set</p>
    </div>
  `
  editTemplate = `
    <div>
      <input type="text" placeholder="Vault Key" id="vaultKeyInput">
      <button id="editButton">Edit</button>
    </div>
  `

  connectedCallback() {
    const key = this.getAttribute('key')
    if (!key && !DmCredentials.#vaultKey) return this.openLogin()
  }

  openLogin() { }

  // Logics
  async loadKey(password) {
    if (typeof password !== 'string') throw Error('Password must be a string')
    const pw = new TextEncoder().encode(password.normalize('NFC'))
    const k1 = await crypto.subtle.importKey(
      "raw",
      pw,
      "PBKDF2",
      false,
      ["deriveKey"]
    )

    const vaultKey = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" },
      k1,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    )


    const meta = JSON.parse(localStorage.getItem(DmCredentials.storageKey + 'meta'))
    if (!meta) throw Error('Meta not found')
    DmCredentials.#vaultKey = vaultKey
    return true
  }
  async saveKey() {
    const vaultKey = DmCredentials.#vaultKey
    if (!vaultKey) throw Error('Vault key is not set')
  }

  async get(key) {
    let vaultKey = DmCredentials.#vaultKey
    if (!(await this.loadKey())) return null
    if (!vaultKey) throw Error('Vault key is not set')
    return localStorage.getItem(DmCredentials.storageKey + key)
  }
  async set(key, value) {
    if (!(await this.loadKey())) return
    localStorage.setItem(DmCredentials.storageKey + key, value)
  }
  async delete(key) {
    if (!(await this.loadKey())) return
    localStorage.removeItem(DmCredentials.storageKey + key)
  }
})
