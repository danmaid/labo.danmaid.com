customElements.define('dm-data-row', class DmDataRow extends HTMLElement {
  getTemplate(key) {
    if (typeof key === 'string') return this.querySelector(`:scope > template#${CSS.escape(key)}`)
    if (key >= 1) return this.querySelector(`:scope > template:nth-of-type(${key})`)
    return this.querySelector(':scope > template')
  }
  createRow(data, templateKey = undefined) {
    const template = this.getTemplate(templateKey)
    if (!template) throw new Error('template not found')
    const fragment = template.content.cloneNode(true)
    const tr = fragment.firstElementChild
    if (!tr) throw new Error('template root must be <tr>')
    tr.data = data
    tr.addEventListener('change', this.rowChangeListener)
    this.rowChangeListener.call(tr)
    return tr
  }

  /** @type {(this: HTMLTableRowElement & { data: unknown }) => void} */
  rowChangeListener() {
    const data = this.data
    if (!data) return
    for (const el of this.querySelectorAll('[data-bind]')) el.data = data
    for (const el of this.querySelectorAll('[data-text]')) {
      const key = el.getAttribute('data-text')
      if (data[key] != null) el.textContent = data[key]
    }
    for (const el of this.querySelectorAll('[data-attr]')) {
      const attr = el.getAttribute('data-attr')
      const [prop, key] = attr.split(':')
      if (data[key] != null) el[prop] = data[key]
    }
  }

  mergeRows(tbody, items, template, keyFn = v => v) {
    const map = new Map()
    for (const el of tbody.rows) el.data && map.set(keyFn(el.data), el)
    for (const data of items ?? []) {
      const key = keyFn(data)
      const el = map.get(key)
      el ? this.updateRow(el, data) : map.set(key, this.insertRow(tbody, data, template))
    }
  }
  insertRow(tbody, data, template) {
    return tbody.appendChild(this.createRow(data, template))
  }
  updateRow(el, data) {
    el.data = data
    el.dispatchEvent(new Event('change'))
  }
})
