customElements.define("dm-windows", class DmWindows extends HTMLElement {
  static css = new CSSStyleSheet()
  static {
    this.css.replace(`
      dm-windows {
        display: block;
        width: 100%;
        height: 100%;
        position: absolute;
        inset: 0;
        pointer-events: none;
        overflow: hidden;
        z-index: 1000;
      }
      dm-windows > dm-window > iframe {
        width: 100%;
        height: 100%;
        border: none;
        display: block;
      }
    `)
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, this.css]
  }

  constructor() {
    super()
    window.addEventListener('click', (ev) => {
      if (ev.target.target !== 'dm-windows') return
      ev.preventDefault()
      if (ev.target.tagName === 'A') {
        const iframe = document.createElement('iframe')
        iframe.src = ev.target.href
        this.open(iframe, { title: ev.target.textContent })
      }
    })
  }

  open(element, { title = 'Window' } = {}) {
    const doc = this.manager.ownerDocument
    const window = doc.createElement('dm-window')
    window.setAttribute('title', title)
    window.appendChild(element)
    return this.manager.appendChild(window)
  }

  get manager() {
    return window.top.document.querySelector('dm-windows') ?? this
  }
})

customElements.define('dm-window', class DmWindow extends HTMLElement {
  static z = 1;
  static css = new CSSStyleSheet()
  static template = document.createElement('template')
  static {
    this.template.innerHTML = `
      <div class="header">
        <slot name="title" class="title">Window</slot>
        <div class="controls">
          <button class="close">×</button>
        </div>
      </div>

      <div class="content">
        <slot></slot>
      </div>
      <dm-window-resize min-height="100" min-width="200"></dm-window-resize>
    `
    this.css.replace(`
      :host {
        display: flex;
        flex-direction: column;
        width: 320px;
        height: 240px;
        background: #22222222;
        border: 1px solid #666;
        box-shadow: 4px 4px 12px rgba(0,0,0,0.3);
        overflow: hidden;
        pointer-events: initial;
        position: absolute !important;
        box-sizing: border-box;
      }

      .header {
        background: #44444488;
        color: #fff;
        padding-left: 0.2em;
        cursor: move;
        display: flex;
        justify-content: space-between;
        align-items: center;
        user-select: none;
      }

      .title {
        font-size: 14px;
      }

      .controls button {
        margin-left: 6px;
        background: transparent;
        border: none;
        color: white;
        cursor: pointer;
      }

      .content {
        flex: 1;
        overflow: auto;
      }
    `)
  }

  constructor() {
    super()
    const shadow = this.attachShadow({ mode: 'open' })
    shadow.adoptedStyleSheets = [DmWindow.css]
    shadow.appendChild(DmWindow.template.content.cloneNode(true))
    const header = shadow.querySelector('.header')

    // ドラッグで移動
    header.addEventListener('pointerdown', (e) => this.setPointerCapture(e.pointerId))
    this.addEventListener('pointermove', (e) => {
      if (!this.hasPointerCapture(e.pointerId)) return
      this.style.left = (this.offsetLeft + e.movementX) + 'px'
      this.style.top = (this.offsetTop + e.movementY) + 'px'
    })
    // コントロールはドラッグの対象外
    const controls = shadow.querySelector('.controls')
    controls.addEventListener('pointerdown', (e) => e.stopPropagation())
    const close = shadow.querySelector('.close')
    close.addEventListener('click', () => this.remove())

    // 前面化
    this.addEventListener('pointerdown', () => this.style.zIndex = ++DmWindow.z)
  }

  static get observedAttributes() { return ['title'] }

  attributeChangedCallback(name, oldValue, newValue) {
    if (name === 'title') {
      this.shadowRoot.querySelector('.title').textContent = newValue
    }
  }
})

customElements.define('dm-window-resize', class DmWindowResize extends HTMLElement {
  static dirs = [
    'n', 's', 'e', 'w',
    'ne', 'nw', 'se', 'sw'
  ]
  static css = new CSSStyleSheet()
  static template = document.createElement('template')
  static {
    this.template.innerHTML = this.dirs
      .map(dir => `<div class="resize resize-${dir}" data-dir="${dir}"></div>`)
      .join('')

    this.css.replace(`
      :host {
        position: absolute;
        inset: 0;
        pointer-events: none;
        --hit: 8px;
      }
      .resize {
        position: absolute;
        pointer-events: auto;
      }
      ${Object.entries({
      n: `top:0;left:var(--hit);right:var(--hit);height:var(--hit);cursor:ns-resize;`,
      s: `bottom:0;left:var(--hit);right:var(--hit);height:var(--hit);cursor:ns-resize;`,
      e: `top:var(--hit);right:0;bottom:var(--hit);width:var(--hit);cursor:ew-resize;`,
      w: `top:var(--hit);left:0;bottom:var(--hit);width:var(--hit);cursor:ew-resize;`,

      ne: `top:0;right:0;width:var(--hit);height:var(--hit);cursor:nesw-resize;`,
      nw: `top:0;left:0;width:var(--hit);height:var(--hit);cursor:nwse-resize;`,
      se: `bottom:0;right:0;width:var(--hit);height:var(--hit);cursor:nwse-resize;`,
      sw: `bottom:0;left:0;width:var(--hit);height:var(--hit);cursor:nesw-resize;`,
    }).map(([dir, css]) => `.resize-${dir} { ${css} }`).join('\n')}
    `)
  }

  get target() { return this.getRootNode().host ?? this.parentElement }
  get minWidth() { return parseInt(this.getAttribute('min-width')) || 200 }
  get minHeight() { return parseInt(this.getAttribute('min-height')) || 100 }
  dir = null

  constructor() {
    super()
    const shadow = this.attachShadow({ mode: 'open' })
    shadow.adoptedStyleSheets = [DmWindowResize.css]
    shadow.append(DmWindowResize.template.content.cloneNode(true))

    for (const handle of shadow.querySelectorAll('.resize')) {
      handle.addEventListener('pointerdown', e => {
        e.stopPropagation()
        this.dir = handle.dataset.dir
        handle.setPointerCapture(e.pointerId)
      })

      handle.addEventListener('pointermove', e => {
        if (!this.dir) return
        const style = this.target.style
        const width = this.target.offsetWidth
        const height = this.target.offsetHeight
        const dx = e.movementX
        const dy = e.movementY

        if (this.dir.includes('e')) {
          style.width = `${Math.max(this.minWidth, width + dx)}px`
        }

        if (this.dir.includes('s')) {
          style.height = `${Math.max(this.minHeight, height + dy)}px`
        }

        if (this.dir.includes('w')) {
          const w = Math.max(this.minWidth, width - dx)
          style.width = `${w}px`
          // 位置補正
          style.left = `${this.target.offsetLeft + width - w}px`
        }

        if (this.dir.includes('n')) {
          const h = Math.max(this.minHeight, height - dy)
          style.height = `${h}px`
          // 位置補正
          style.top = `${this.target.offsetTop + height - h}px`
        }
      })

      const end = () => { this.dir = null }
      handle.addEventListener('pointerup', end)
      handle.addEventListener('pointercancel', end)
    }
  }
})