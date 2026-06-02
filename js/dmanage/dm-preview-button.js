customElements.define('dm-preview-button', class DmPreviewButton extends HTMLElement {
  static css = new CSSStyleSheet()
  static template = document.createElement('template')
  static {
    this.template.innerHTML = `<button disabled><slot>👀</slot></button>`
  }

  src
  button
  constructor() {
    super()
    const shadow = this.attachShadow({ mode: 'open' })
    shadow.adoptedStyleSheets = [DmPreviewButton.css]
    shadow.appendChild(DmPreviewButton.template.content.cloneNode(true))
    this.button = shadow.querySelector('button')

    this.addEventListener('click', () => {
      const src = this.src
      const editor = globalThis[this.getAttribute('target')]
      const model = editor?.getModel()
      if (!src || !model) return
      editor.updateOptions({ readOnly: true })
      const language = this.getAttribute('language')
      if (language) monaco.editor.setModelLanguage(model, language)
      const select = this.getAttribute('select')
      const text = select ? select.split('.').reduce((o, k) => o?.[k], src.raw) : src.raw
      const value = language === 'json' ? JSON.stringify(text, null, 2) : text
      model.setValue(value)
    })
  }

  connectedCallback() {
    const query = this.getAttribute('for')
    this.src = query
      ? document.querySelector(query)
      : this.parentElement.querySelector('dm-sdwan-load-button')
    this.src.addEventListener('change', () => {
      this.src.raw ? this.button.disabled = false : this.button.disabled = true
    })
  }
})
