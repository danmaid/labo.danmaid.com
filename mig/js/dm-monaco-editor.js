/**
 * Monaco Editor Web Component
 * <script src="vendor/vs/loader.js"></script>
 * <script>require.config({ paths: { vs: "vendor/vs" } })</script>
 * <script src="js/monaco-editor.js"></script>
 * 
 * <dm-monaco-editor target="#xxx"></dm-monaco-editor>
 * <dm-monaco-editor target="#xxx" diff="#yyy"></dm-monaco-editor>
 */
customElements.define("dm-monaco-editor", class DmMonacoEditor extends HTMLElement {
  static config = Symbol('config')
  static css = new CSSStyleSheet()
  static {
    this.css.replace(`
      dm-monaco-editor {
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
      }
      .editor.inactive {
        pointer-events: none;
        opacity: 0;
      }
    `)
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, this.css]
  }

  editors = Array.from({ length: 2 }, () => {
    const el = document.createElement('div')
    el.classList.add('editor')
    el.activate = () => {
      for (const editor of this.editors) {
        editor !== el
          ? editor.classList.add('inactive')
          : editor.classList.remove('inactive')
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

  static observedAttributes = ['target', 'diff']
  async attributeChangedCallback(name, oldValue, newValue) {
    await this.editorReady
    if (name === 'target') {
      const { model, viewState } = this.getConfig()
      this.editor.setModel(model)
      if (viewState) this.editor.restoreViewState(viewState)
      this.editors[0].activate()
      return
    }
    if (name === 'diff') {
      if (!this.getAttribute('diff')) return this.editors[0].activate()
      const { model: original } = this.getConfig(this.getAttribute('target'))
      const { model: modified } = this.getConfig(this.getAttribute('diff'))
      this.diffEditor.setModel({ original, modified })
      const { viewState } = this.getConfig(this.getAttribute('config'))
      if (viewState) this.diffEditor.restoreViewState(viewState)
      this.editors[1].activate()
      return
    }
  }

  getConfig(query = this.getAttribute('config') || this.getAttribute('target')) {
    const el = document.querySelector(query)
    if (!el) throw Error(`Config element not found: ${query}`)
    const config = el[DmMonacoEditor.config] ??= {}
    config.model ??= monaco.editor.createModel(el.value)
    return config
  }
})
