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
    `)
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, this.css]
  }

  constructor() {
    super()
    window.addEventListener('click', (ev) => {
      if (ev.target.target !== 'dm-windows') return
      ev.preventDefault()
      const window = document.createElement('dm-window')
      if (ev.target.tagName === 'A') {
        console.log('CATCH LINK', ev.target.href)
        const iframe = document.createElement('iframe')
        iframe.src = ev.target.href
        window.appendChild(iframe)
      }
      this.appendChild(window)
    })
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
        resize: both;
        overflow: hidden;
        pointer-events: initial;
        position: absolute !important;
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
