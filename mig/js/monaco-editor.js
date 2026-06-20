// 共通
class MonacoElement extends HTMLElement {
  static ready = new Promise((r) => globalThis.require(['vs/editor/editor.main'], r))

  editorReady
  editor
  constructor() {
    super()
    if (!globalThis.require) throw Error("Monaco Editor is not loaded. Please include loader.js and configure require paths.")
    this.editorReady = MonacoElement.ready
      .then(() => this.initialize())
      .then(() => this.dispatchEvent(new Event("ready", { bubbles: true, composed: true })))
  }

  async initialize() { }
}

/**
 * Monaco Editor Web Component
 * <script src="vendor/vs/loader.js"></script>
 * <script>require.config({ paths: { vs: "vendor/vs" } })</script>
 * <script src="js/monaco-editor.js"></script>
 * 
 * <monaco-editor></monaco-editor>
 * <monaco-editor language="json"></monaco-editor>
 */
customElements.define("monaco-editor", class MonacoEditor extends MonacoElement {
  async initialize() {
    this.editor = monaco.editor.create(this, {
      theme: "vs-dark",
      automaticLayout: true,
      tabSize: 2,
      insertSpaces: true,
    })
  }

  static observedAttributes = ["language"]
  async attributeChangedCallback(name, oldValue, newValue) {
    await this.editorReady
    monaco.editor.setModelLanguage(this.editor.getModel(), newValue)
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

/**
 * Monaco Diff Editor Web Component
 * <script src="vendor/vs/loader.js"></script>
 * <script>require.config({ paths: { vs: "vendor/vs" } })</script>
 * <script src="js/monaco-editor.js"></script>
 * 
 * <monaco-diff-editor></monaco-diff-editor>
 * <monaco-diff-editor language="json"></monaco-diff-editor>
 */
customElements.define("monaco-diff-editor", class MonacoDiffEditor extends MonacoElement {
  async initialize() {
    this.editor = monaco.editor.createDiffEditor(this, {
      theme: "vs-dark",
      automaticLayout: true,
      tabSize: 2,
      insertSpaces: true,
      hideUnchangedRegions: { enabled: true },
    })
  }
})
