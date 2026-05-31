import { runOnce } from '../run-once.mjs'
const styles = `
  dm-preview-button.previewing {
    position: relative;
  }

  dm-preview-button.previewing::after {
    content: "";
    position: absolute;
    inset: 0;

    border: 2px solid #4da3ff;
    background: rgba(77, 163, 255, 0.15);

    pointer-events: none;
    z-index: 9999;
  }
`
const css = new CSSStyleSheet()
css.replace(styles).then(() => document.adoptedStyleSheets = [...document.adoptedStyleSheets, css])

runOnce(attachListener)
new MutationObserver(() => runOnce(attachListener)).observe(document, { childList: true, subtree: true })

function attachListener() {
  for (const button of document.querySelectorAll('dm-preview-button')) {
    button.addEventListener('click', focusPreview)
  }
}

function focusPreview() {
  console.log('FOCUS', this)
  for (const btn of document.querySelectorAll('dm-preview-button.previewing'))
    btn.classList.remove('previewing')
  this.classList.add('previewing')
}
