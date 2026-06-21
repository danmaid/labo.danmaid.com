/**
 * Monaco Editor Web Component
 * <script src="vendor/vs/loader.js"></script>
 * <script>require.config({ paths: { vs: "vendor/vs" } })</script>
 * <script src="js/monaco-editor.js"></script>
 * 
 * <monaco-editor target="#xxx"></monaco-editor>
 * <monaco-editor target="#xxx" diff="#yyy"></monaco-editor>
 * <monaco-editor language="json"></monaco-editor>
 */
customElements.define("monaco-editor", class MonacoEditor extends HTMLElement {
  static config = Symbol('config')
  static css = new CSSStyleSheet()
  static {
    this.css.replace(`
      monaco-editor {
        display: block;
        width: 100%;
        height: 100%;
        position: relative;
      }
      .editor {
        display: block;
        width: 100%;
        height: 100%;
        position: absolute;
        inset: 0;
        visibility: hidden !important;
      }
      .editor.active {
        visibility: visible !important;
      }`)
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, this.css]
  }

  editors = Array.from({ length: 2 }, () => {
    const el = document.createElement('div')
    el.classList.add('editor')
    el.activate = () => {
      for (const editor of this.editors) {
        editor === el
          ? editor.classList.add('active')
          : editor.classList.remove('active')
      }
    }
    return el
  })
  editor
  diffEditor
  constructor() {
    super()
    if (!globalThis.require) throw Error("Monaco Editor is not loaded. Please include loader.js and configure require paths.")
    globalThis.require(['vs/editor/editor.main'], () => {
      this.initEditors()
      this.dispatchEvent(new Event("ready", { bubbles: true, composed: true }))
    })
    setTimeout(() => this.append(...this.editors), 0)
  }

  initEditors() {
    this.editor = monaco.editor.create(this.editors[0], {
      theme: "vs-dark",
      automaticLayout: true,
      tabSize: 2,
      insertSpaces: true,
    })
    this.diffEditor = monaco.editor.createDiffEditor(this.editors[1], {
      theme: "vs-dark",
      automaticLayout: true,
      tabSize: 2,
      insertSpaces: true,
      hideUnchangedRegions: { enabled: true },
    })
    this.editors[0].activate()
  }

  static observedAttributes = ['language', 'target', 'diff']
  async attributeChangedCallback(name, oldValue, newValue) {
    await this.editorReady
    if (name === 'language') {
      monaco.editor.setModelLanguage(this.editor.getModel(), newValue)
      return
    }
    if (name === 'target') {
      const target = document.querySelector(newValue)
      if (!target) throw Error(`Target element not found: ${newValue}`)
      let config = target[MonacoEditor.config]
      if (!config) config = target[MonacoEditor.config] = {}
      let language = config.language
      let model = config.model
      if (!model) model = config.model = monaco.editor.createModel(target.value, language)
      if (!language) language = config.language = model.getLanguageId()
      this.editor.setModel(model)

      let viewState = config.viewState
      if (viewState) this.editor.restoreViewState(viewState)
      this.editors[0].activate()
      return
    }
    if (name === 'diff') {
      if (!this.getAttribute('diff')) return this.editors[0].activate()
      this.editors[1].activate()
      console.log('diff attribute changed:', newValue)
      // 後はここだけ。。。
      return
    }
  }

  get value() { return this.editor?.getValue() ?? "" }
  set value(value) { this.editor?.setValue(value ?? "") }
  get language() { return this.getAttribute("language") }
  set language(value) {
    value == null
      ? this.removeAttribute("language")
      : this.setAttribute("language", value)
  }
})
