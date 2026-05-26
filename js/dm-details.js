customElements.define('dm-details', class DmDetails extends HTMLElement {
  static css = new CSSStyleSheet().replaceSync(`
    textarea {
      font-family: monospace;
      white-space: pre;
    }
  `)
  static observedAttributes = ['input', 'regex']

  constructor() {
    super()
    const shadow = this.attachShadow({ mode: 'open' })
    shadow.adoptedStyleSheets = [DmDetails.css]
    shadow.innerHTML += `
      <details>
        <summary><span data-text="summary"></span></summary>
      </details>
    `
  }
})
