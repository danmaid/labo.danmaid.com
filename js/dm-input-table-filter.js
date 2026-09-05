customElements.define('dm-input-table-filter', class DmInputTableFilter extends HTMLInputElement {
  static attachTable(table) {
    if (table.$filterable) return
    table.$filters ??= []
    table.$applyFilters ??= () => {
      const filters = table.$filters
      for (const row of table.querySelectorAll('tbody tr')) {
        if (filters.some((r, i) => r && !r.test(row.cells[i]?.textContent ?? ''))) {
          row.style.display = 'none'
          continue
        }
        row.style.display = ''
      }
    }
    table.$observer ??= new MutationObserver(() => {
      table.$applyScheduled ||= requestAnimationFrame(() => {
        table.$applyScheduled = null
        table.$applyFilters()
      })
    })
    table.$observer.observe(table, { childList: true, subtree: true })
    table.$filterable = true
  }

  table
  cellIndex

  constructor() {
    super()
    this.addEventListener('input', () => this.updateFilter())
  }

  connectedCallback() {
    const table = this.closest('table')
    if (!table) throw new Error('dm-input-table-filter must be inside a table')
    DmInputTableFilter.attachTable(table)
    this.table = table
    const cellIndex = this.closest('td, th')?.cellIndex
    if (!(cellIndex >= 0)) throw new Error('dm-input-table-filter must be inside a td or th')
    this.cellIndex = cellIndex
    this.updateFilter()
  }

  updateFilter() {
    this.table.$filters[this.cellIndex] = this.value ? new RegExp(this.value, 'i') : null
    this.table.$applyFilters()
  }
}, { extends: 'input' })
