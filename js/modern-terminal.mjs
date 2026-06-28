import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';

class TerminalConnector {
  constructor() {
    this.readable = new ReadableStream({
      start: controller => { this._controller = controller; }
    });

    this.writable = new WritableStream({
      write: chunk => this.send(chunk)
    });
  }

  push(data) {
    this._controller.enqueue(data);
  }

  // 下位クラスで実装
  send(_chunk) {
    throw new Error('send() not implemented');
  }

  start() {
    throw new Error('start() not implemented');
  }
}

class ShellInABoxConnector extends TerminalConnector {
  constructor(baseUrl) {
    super();
    this.baseUrl = baseUrl;
    this.session = null;
  }

  async start() {
    this.session = await this.createSession();
    this.poll();
  }

  async createSession() {
    const payload = new URLSearchParams();
    payload.set('width', 98);
    payload.set('height', 30);
    payload.set('rooturl', location.href);

    const res = await fetch(`${this.baseUrl}/shell/?`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: payload.toString()
    });

    const json = await res.json();
    return json.session;
  }

  async poll() {
    while (true) {
      try {
        const payload = new URLSearchParams();
        payload.set('session', this.session);
        payload.set('poll', '1');

        const res = await fetch(`${this.baseUrl}/shell/${this.session}/?`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: payload.toString()
        });

        const json = await res.json();
        if (json.data) this.push(json.data);
      } catch {
        await new Promise(r => setTimeout(r, 100));
      }
    }
  }

  async send(data) {
    const payload = new URLSearchParams();
    payload.set('session', this.session);
    payload.set('keys', encodeKeysToHex(data));

    await fetch(`${this.baseUrl}/shell/${this.session}/?`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: payload.toString()
    });
  }
}

function encodeKeysToHex(data) {
  let hex = '';
  for (let i = 0; i < data.length; i++) {
    hex += data.charCodeAt(i).toString(16).toUpperCase().padStart(2, '0');
  }
  return hex;
}

class WebSocketConnector extends TerminalConnector {
  constructor(url) {
    super();
    this.ws = new WebSocket(url);
  }

  start() {
    this.ws.onmessage = e => this.push(e.data);
  }

  send(chunk) {
    this.ws.send(chunk);
  }
}

class LogPlugin {
  constructor() {
    this.buffer = '';
    this.stream = new TransformStream({
      transform: (chunk, controller) => {
        this.buffer += chunk;
        controller.enqueue(chunk);
      }
    });
  }

  getLog() {
    return this.buffer;
  }
}

class ModernTerminal extends HTMLElement {
  constructor() {
    super();
    this.term = new Terminal({
      convertEol: true,
      fontFamily: 'monospace',
      fontSize: 14,
    });
    this.fitAddon = new FitAddon();
    this.plugins = [];
    this.connector = null;
  }

  connectedCallback() {
    this.term.loadAddon(this.fitAddon);
    this.term.open(this);
    this.fitAddon.fit();
  }

  addPlugin(plugin) {
    this.plugins.push(plugin);
  }

  async setConnector(connector) {
    this.connector = connector;

    // Terminal → connector (Writable)
    const writer = connector.writable.getWriter();
    this.term.onData(data => writer.write(data));

    // connector.readable → plugins → Terminal
    let stream = connector.readable;

    for (const plugin of this.plugins) {
      stream = stream.pipeThrough(plugin.stream);
    }

    const reader = stream.getReader();
    (async () => {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        this.term.write(value);
      }
    })();

    await connector.start();
  }
}

customElements.define('modern-terminal', ModernTerminal);


// 使い方例
const el = document.querySelector('modern-terminal');

// ShellInABox
const shellConnector = new ShellInABoxConnector('/');
const logPlugin = new LogPlugin();

el.addPlugin(logPlugin);
el.setConnector(shellConnector);

// WebSocket に切り替えたい場合
// const wsConnector = new WebSocketConnector('wss://example.com/tty');
// el.setConnector(wsConnector);
