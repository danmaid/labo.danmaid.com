class DmLoadButton extends HTMLElement {
  static observedAttributes = ['value', 'url']
  static css = new CSSStyleSheet()
  static template = document.createElement('template')
  static {
    this.template.innerHTML = `
          <button><slot></slot>
            <progress style="display: none;"></progress>
            <span></span>
          </button>  
        `
  }
  raw = null

  set value(v) { this.setAttribute('value', v) }
  get value() { return this.getAttribute('value') }

  set url(v) { this.setAttribute('url', v) }
  get url() {
    return this.getAttribute('url').includes('{value}')
      ? this.value && this.getAttribute('url').replace('{value}', this.value)
      : this.getAttribute('url')
  }

  constructor() {
    super()
    const shadow = this.attachShadow({ mode: 'open' })
    shadow.adoptedStyleSheets = [DmLoadButton.css]
    shadow.appendChild(DmLoadButton.template.content.cloneNode(true))
    this.button = shadow.querySelector('button')
    this.progress = shadow.querySelector('progress')
    this.result = shadow.querySelector('span')
    this.button.addEventListener('click', () => this.execute())
  }

  attributeChangedCallback(name, oldValue, newValue) {
    if (oldValue === newValue) return
    if (name === 'url' || name === 'value') return this.execute()
  }

  // 👉 差し替えポイント
  async fetch() {
    return fetch(this.url)
  }

  async execute() {
    if (!this.url) return
    try {
      this.progress.style.display = "initial"
      this.raw = await this.fetch()
      this.result.textContent = new Date().toLocaleTimeString()
      this.dispatchEvent(new Event('change', { bubbles: true }))
    } catch (error) {
      console.error(error)
      this.raw = null
      this.dispatchEvent(new ErrorEvent('error', { bubbles: true, error }))
    } finally {
      this.progress.style.display = "none"
    }
  }
}

customElements.define('dm-load-button', DmLoadButton)
