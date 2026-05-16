// import { Terminal } from "xterm"
// import { FitAddon } from "xterm-fit"
// const cssUrl = new URL("./xterm.css", import.meta.url)
import { Terminal } from "https://cdn.jsdelivr.net/npm/@xterm/xterm@6.0.0/lib/xterm.mjs"
import { FitAddon } from "https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.11.0/lib/addon-fit.mjs"
const cssUrl = "https://cdn.jsdelivr.net/npm/@xterm/xterm@6.0.0/css/xterm.css"
const cssText = await fetch(cssUrl).then(r => r.text())

const xtermCss = new CSSStyleSheet()
await xtermCss.replace(cssText)

const defaultCss = new CSSStyleSheet()
await defaultCss.insertRule(`
      :host, .container {
        display: block;
        width: 100%;
        height: 100%;
      }`)

class DmSshTerminal extends HTMLElement {
  /** @type {TerminalView} */
  view
  /** @type {WebSocket | null} */
  ws = null

  constructor() {
    super()
    this.attachShadow({ mode: "open" })
    this.shadowRoot.adoptedStyleSheets = [...this.shadowRoot.adoptedStyleSheets, xtermCss, defaultCss]
    this.view = new TerminalView(this.shadowRoot)
  }

  static get observedAttributes() { return ["socket", "session", "role", "host", "broker"] }
  attributeChangedCallback(name, oldVal, newVal) {
    console.log("attr changed", { name, oldVal, newVal })
    if (newVal === oldVal || !newVal) return
    if (name === 'socket') return this.connect()
    if (name === 'session') return this.attach()
    // 以下はおまけ機能
    if (name === 'host') return new LoginController({
      view: this.view,
      broker: this.getAttribute('broker'),
      host: this.getAttribute('host'),
      port: this.getAttribute('port')
    }, ({ session_id }) => {
      this.view.write('success.\r\n')
      this.setAttribute('role', 'writer')
      this.setAttribute("session", session_id)
    })
  }

  connect() {
    const socket = this.getAttribute('socket')
    this.ws?.close()
    this.ws = new WebSocket(socket)
    this.ws.binaryType = "arraybuffer"
    this.ws.onmessage = e => this.view.write(
      e.data instanceof ArrayBuffer ? new Uint8Array(e.data) : e.data
    )
    this.view.onInput(data => this.ws.send(data))
  }

  async attach() {
    const broker = this.getAttribute('broker')
    const session = this.getAttribute('session')
    const mode = this.getAttribute('role')
    const res = await fetch(`${broker}/sessions/${session}/attach-tokens`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer dev-token", // MVP
      },
      body: JSON.stringify({ mode }),
    })

    if (!res.ok) {
      const err = await res.json()
      throw { status: res.status, error: err.error }
    }

    const { ws_url } = await res.json()
    this.setAttribute("socket", ws_url)
  }
}

class TerminalView {
  /** @type {Terminal} */
  term
  /** @type {FitAddon} */
  fit
  get cols() { return this.term.cols }
  get rows() { return this.term.rows }

  constructor(root) {
    const container = document.createElement("div")
    container.className = "container"
    root.appendChild(container)

    this.term = new Terminal({
      cursorBlink: true,
      scrollback: 3000,
    })
    this.fit = new FitAddon()

    this.term.loadAddon(this.fit)
    this.term.open(container)
    this.fit.fit()

    new ResizeObserver(() => this.fit.fit()).observe(container)
  }

  write(data) {
    this.term.write(data)
  }

  onInput(cb) {
    this._inputDisposable?.dispose()
    this._inputDisposable = this.term.onData(cb)
  }
}

class LoginController {
  state = "username"
  /** @type {{ username?: string, password?: string }} */
  buf = {}

  constructor({ view, broker, host, port }, onSubmit) {
    this.view = view
    this.broker = broker
    this.onSubmit = onSubmit
    this.host = host
    this.port = port
    this.view.write("Username: ")
    this.view.onInput(d => this.onInput(d))
  }

  async onInput(data) {
    if (data === "\r") {
      if (this.state === "username") {
        this.state = "password"
        this.view.write("\r\nPassword: ")
      } else {
        try {
          this.view.write("\r\nLogging in...\r\n")
          const result = await this.createSession(this.buf)
          this.onSubmit(result)
        } catch (e) {
          console.error('Login failed', e)
          this.view.write(`\r\nLogin failed (${e.status}) ${e.error}\r\nUsername: `)
          this.state = "username"
          this.buf = {}
        }
      }
      return
    }
    this.buf[this.state] = (this.buf[this.state] ?? "") + data
    if (this.state === "username") this.view.write(data)
  }

  async createSession({ username, password }) {
    const broker = this.broker
    const res = await fetch(`${broker}/sessions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer dev-token", // MVP
      },
      body: JSON.stringify({
        host: this.host,
        port: parseInt(this.port) || undefined,
        username,
        password,
        pty_cols: this.view.cols,
        pty_rows: this.view.rows,
      }),
    })

    if (!res.ok) {
      const err = await res.json()
      throw { status: res.status, error: err.error }
    }

    return res.json()
  }
}

customElements.define("dm-ssh-terminal", DmSshTerminal)
console.log("dm-ssh-terminal defined")