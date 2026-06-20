/**
 * Monaco Editor Web Component
 * <script src="vendor/vs/loader.js"></script>
 * <script>require.config({ paths: { vs: "vendor/vs" } })</script>
 * <script src="js/monaco-editor.js"></script>
 * 
 * <monaco-editor></monaco-editor>
 * <monaco-editor language="json"></monaco-editor>
 */
class MonacoEditor extends HTMLElement {
  static ready = new Promise((r) => require(['vs/editor/editor.main'], r))

  editorReady
  editor
  constructor() {
    super()
    if (!require) throw Error("Monaco Editor is not loaded. Please include loader.js and configure require paths.")
    this.editorReady = MonacoEditor.ready.then(() => {
      this.editor = monaco.editor.create(this, {
        theme: "vs-dark",
        automaticLayout: true,
        tabSize: 2,
        insertSpaces: true,
      })
      this.dispatchEvent(new Event("ready", { bubbles: true, composed: true }))
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
}

customElements.define("monaco-editor", MonacoEditor)
