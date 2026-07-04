// FIPS180-4 SHA-256
const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0
const Ch = (x, y, z) => ((x & y) ^ (~x & z)) >>> 0
const Maj = (x, y, z) => ((x & y) ^ (x & z) ^ (y & z)) >>> 0
const Sigma0 = (x) => (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)) >>> 0
const Sigma1 = (x) => (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)) >>> 0
const sigma0 = (x) => (rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) >>> 0
const sigma1 = (x) => (rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10)) >>> 0
const INITIAL_H = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
])
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
])

/**
 * 6.2.2 SHA-256 Hash Computation 
 * Mutates H in place.
 * 
 * @param {Uint32Array} M 16 words (512 bits block) to process
 * @param {Uint32Array} H 8 words (256 bits state) to use as initial state, defaults to SHA-256 initial hash value
 * @param {Uint32Array} [W_] 64 words (512 bits) temporary workspace, optional
 */
function compute(M, H, W_ = new Uint32Array(64)) {
  // 1. Prepare the message schedule, {Wt}: 
  const W = W_
  for (let t = 0; t < 16; t++) W[t] = M[t]
  for (let t = 16; t < 64; t++)
    W[t] = (sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16]) >>> 0

  // 2. Initialize the eight working variables, a, b, c, d, e, f, g, and h, with the (i-1)st hash value: 
  let [a, b, c, d, e, f, g, h] = H

  // 3. For t=0 to 63:
  for (let t = 0; t < 64; t++) {
    const T1 = (h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t]) >>> 0
    const T2 = (Sigma0(a) + Maj(a, b, c)) >>> 0
    h = g
    g = f
    f = e
    e = (d + T1) >>> 0
    d = c
    c = b
    b = a
    a = (T1 + T2) >>> 0
  }

  // 4. Compute the (i)th intermediate hash value H(i):
  H[0] = (H[0] + a) >>> 0
  H[1] = (H[1] + b) >>> 0
  H[2] = (H[2] + c) >>> 0
  H[3] = (H[3] + d) >>> 0
  H[4] = (H[4] + e) >>> 0
  H[5] = (H[5] + f) >>> 0
  H[6] = (H[6] + g) >>> 0
  H[7] = (H[7] + h) >>> 0
}

function toWords(bytes, M = new Uint32Array(16)) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, 64)
  for (let i = 0; i < 16; i++) M[i] = view.getUint32(i * 4, false)
  return M
}

function stateToBytes(H) {
  const out = new Uint8Array(32)
  const view = new DataView(out.buffer)
  for (let i = 0; i < 8; i++) view.setUint32(i * 4, H[i], false)
  return out
}

export class SHA256DigestStream extends TransformStream {
  constructor() {
    let H = new Uint32Array(INITIAL_H)
    let W = new Uint32Array(64)
    let M = new Uint32Array(16)
    let buffer = new Uint8Array(0)
    let totalBytes = 0n

    super({
      transform(chunk, controller) {
        if (!(chunk instanceof Uint8Array)) throw new TypeError("Expected Uint8Array")
        totalBytes += BigInt(chunk.length)
        const merged = new Uint8Array(buffer.length + chunk.length)
        merged.set(buffer)
        merged.set(chunk, buffer.length)
        buffer = merged
        let offset = 0
        while (offset + 64 <= buffer.length) {
          const block = toWords(buffer.subarray(offset, offset + 64), M)
          compute(block, H, W)
          offset += 64
        }
        buffer = buffer.slice(offset)
      },

      flush(controller) {
        const bitLength = totalBytes * 8n
        const paddingLength = buffer.length < 56
          ? (56 - buffer.length)
          : (120 - buffer.length)
        const padded = new Uint8Array(buffer.length + paddingLength + 8)
        padded.set(buffer)
        padded[buffer.length] = 0x80
        const view = new DataView(padded.buffer)
        view.setBigUint64(padded.length - 8, bitLength, false)
        for (let offset = 0; offset < padded.length; offset += 64) {
          const block = toWords(padded.subarray(offset, offset + 64), M)
          compute(block, H, W)
        }
        controller.enqueue(stateToBytes(H))
      }
    })
  }
}
