customElements.define('dm-regexp-filter', class DmRegexpFilter extends HTMLElement {
  get value() { return this.shadowRoot.querySelector('input').value }
  get key() { return this.getAttribute('data-key') }
  filter = (item) => new RegExp(this.value).test(item[this.key])

  constructor() {
    super()
    const shadow = this.attachShadow({ mode: 'open' })
    shadow.innerHTML = '<input type="text" placeholder="regex">'
  }
})
