import helpers from './helpers'

const crypto = window.crypto

const pbkdf2Algo = {
  name: 'PBKDF2'
}

// module.exports = {
export default {
  // salt = simple string
  async deriveKey({plainText, salt, length = 256}) {
    const key = await crypto.subtle.importKey('raw', helpers.textToArrayBuffer(plainText), pbkdf2Algo, false, ['deriveKey'])
    const params = {
      name: pbkdf2Algo.name,
      salt: helpers.textToArrayBuffer(salt),
      iterations: 10000,
      hash: 'SHA-256'
    }
    const aesAlgo = {
      name: 'AES-GCM',
      length  // desired key parameters (32 bytes = 256 bits)
    }
    const result = await crypto.subtle.deriveKey(params, key, aesAlgo, true, ['encrypt', 'decrypt'])
    const exported = await crypto.subtle.exportKey('raw', result)
    return helpers.arrayBufferToHex(new Uint8Array(exported))
  }
}
