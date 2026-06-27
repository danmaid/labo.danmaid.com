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
      console.log('CATCH!!', ev.target)
      ev.preventDefault()
      if (ev.target.tagName === 'A') {
        console.log('CATCH LINK', ev.target.href)
        const iframe = document.createElement('iframe')
        iframe.src = ev.target.href
        this.appendChild(iframe)
      }
    })
  }
})
