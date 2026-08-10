import { Terminal } from "../vendor/xterm/xterm.mjs"
import { FitAddon } from "../vendor/xterm/addon-fit.mjs"
const cssUrl = '../vendor/xterm/xterm.css'
const css = new CSSStyleSheet()
await fetch(cssUrl).then(r => r.text()).then(t => css.replace(t))
css.insertRule(`dm-terminal { display: block; width: 100%; height: 100%; }`)
document.adoptedStyleSheets = [...document.adoptedStyleSheets, css]

export class DmTerminal extends HTMLElement {
  terminal = new Terminal({ cursorBlink: true })
  fit = new FitAddon()

  constructor() {
    super()
    this.terminal.loadAddon(this.fit)
  }

  connectedCallback() {
    this.terminal.open(this)
    new ResizeObserver(() => this.fit.fit()).observe(this)
    this.fit.fit()
  }

  write = (data) => this.terminal.write(data)
  onData = (callback) => this.terminal.onData(callback)
}
customElements.define('dm-terminal', DmTerminal)
