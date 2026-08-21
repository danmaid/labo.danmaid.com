import { Terminal } from "../vendor/xterm/xterm.mjs"
import { FitAddon } from "../vendor/xterm/addon-fit.mjs"
const cssUrl = '../vendor/xterm/xterm.css'
const css = new CSSStyleSheet()
await fetch(cssUrl).then(r => r.text()).then(t => css.replace(t))
css.insertRule(`dm-terminal { display: block; width: 100%; height: 100%; }`)
document.adoptedStyleSheets = [...document.adoptedStyleSheets, css]

customElements.define('dm-terminal', class DmTerminal extends HTMLElement {
  terminal = new Terminal({ cursorBlink: true })
  fit = new FitAddon()

  constructor() {
    super()
    this.terminal.loadAddon(this.fit)
  }

  #resizeObserver = new ResizeObserver(() => this.fit.fit())
  connectedCallback() {
    this.terminal.open(this)
    this.#resizeObserver.observe(this)
    this.fit.fit()
  }
  disconnectedCallback() {
    this.#resizeObserver.disconnect()
  }

  write = (data) => this.terminal.write(data)
  onData = (callback) => this.terminal.onData(callback)

  #encoder = new TextEncoder()
  get writable() {
    return new WritableStream({
      write: (chunk) => this.terminal.write(chunk)
    })
  }
  get readable() {
    let disposable = null
    return new ReadableStream({
      start: (controller) => {
        disposable = this.terminal.onData(data =>
          controller.enqueue(this.#encoder.encode(data)))
      },
      cancel: () => {
        disposable?.dispose()
        disposable = null
      }
    })
  }
})
