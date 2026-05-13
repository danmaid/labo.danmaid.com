import { ZatsuMap } from './ZatsuMap.mjs'

console.log('terminals.worker.js loaded.')
const clients = new ZatsuMap()

addEventListener('connect', (/** @type {MessageEvent} */ ev) => {
  console.log('connect', ev)
  const port = ev.ports[0]
  clients.set(crypto.randomUUID(), port)
  port.addEventListener('message', (ev) => {
    if ('id' in ev.data) return handleRPC(ev, port)
    if ('event' in ev.data) return handleEvent(ev, port)
  })
  port.start()
  console.log(clients)
})

function handleRPC(/** @type {MessageEvent} */ ev, from) {
  console.log('Received RPC message from client', ev)
  const req = ev.data
  if ('method' in req) try {
    if (req.method === 'get.terminals') {
      return from.postMessage({ id: req.id, result: Array.from(clients.keys()) })
    }
    if (req.method === 'delete.terminals') {
      const targets = req.params?.targets || clients.keys()
      for (const target of targets) {
        const port = clients.get(target)
        if (port === from) continue
        if (port) port.postMessage({ event: 'close' })
      }
      return from.postMessage({ id: req.id, result: 'ok' })
    }
    throw Error('not implemented.')
  } catch (error) {
    console.error('Error handling RPC message', error)
    from.postMessage({ id: req.id, error })
  }
}

function handleEvent(/** @type {MessageEvent} */ ev, from) {
  console.log('Received event message from client', ev.data)
  const targets = ev.data.targets || clients.keys()
  for (const target of targets) {
    const clientPort = clients.get(target)
    if (clientPort) clientPort.postMessage(ev.data)
  }
}

/**
 * @typedef {{event: 'close', targets?: string[]}} CloseEvent
 * @typedef {CloseEvent} EventMessage
 * 
 * @typedef {{method: string, params?: any}} Request
 * @typedef {{result?: any, error?: any}} Response
 * @typedef {{id: string} & (Request | Response)} RPCMessage
 * 
 * @param {MessageEvent<EventMessage | RPCMessage>} event 
 */
function handleMessage(event) {
  console.log('Received message from client', event.data)
  if (event.data.event === 'close') {
  }
  for (const clientPort of clients.values()) {
    clientPort.postMessage(event.data)
  }
}
