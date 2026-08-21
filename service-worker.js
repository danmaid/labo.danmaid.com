const CACHE_NAME = 'dm-terminal-v1'

const FILES = [
  '/',
  '/serial.html',

  '/css/full-screen.css',

  '/js/dm-terminal.mjs',

  '/vendor/xterm/xterm.mjs',
  '/vendor/xterm/addon-fit.mjs',
  '/vendor/xterm/xterm.css',
]

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(FILES))
  )
})

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => response || fetch(event.request))
  )
})
