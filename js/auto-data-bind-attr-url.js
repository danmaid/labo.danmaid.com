const params = new URLSearchParams(location.search)
for (const el of document.querySelectorAll('[data-bind-attr-url]')) {
  const keys = el.getAttribute('data-bind-attr-url').split(',').map(v => v.trim())
  for (const k of keys) {
    for (const v of params.getAll(k)) {
      v === '' ? el.toggleAttribute(k, true) : el.setAttribute(k, v)
    }
  }
  new MutationObserver(records => {
    for (const r of records) {
      if (r.type === 'attributes' && keys.includes(r.attributeName)) {
        const attr = r.attributeName
        const val = el.getAttribute(attr)
        if (val !== null) {
          params.set(attr, val)
        } else {
          params.delete(attr)
        }
      }
    }
    const newUrl = `${location.pathname}?${params.toString()}${location.hash}`
    history.replaceState(null, '', newUrl)
  }).observe(el, { attributes: true })
}
