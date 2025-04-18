import helpers from './helpers'

const crypto = window.crypto

const defaultKeySize = 2048
const rsaAlgo = {
  name: 'RSA-OAEP',
  modulusLength: defaultKeySize,
  publicExponent: new Uint8Array([1, 0, 1]),
  extractable: true,
  hash: {
    name: 'SHA-256'
  }
}

export default class Rsa {
  async generateKeyPair (args = {}) {
    rsaAlgo.modulusLength = args.size || defaultKeySize
    const keys = await crypto.subtle.generateKey(rsaAlgo, true, ['encrypt', 'decrypt'])
    const spki = await crypto.subtle.exportKey('spki', keys.publicKey)
    const expK = await crypto.subtle.exportKey('pkcs8', keys.privateKey)
    const publicKey = helpers.binaryToPem(spki, 'RSA PUBLIC KEY')
    const privateKey = helpers.binaryToPem(expK, 'RSA PRIVATE KEY')
    return {
      publicKey: {
        pem: publicKey,
        base64: helpers.strToBase64(publicKey)
      },
      privateKey: {
        pem: privateKey,
        base64: helpers.strToBase64(privateKey)
      }
    }
  }

  async encrypt (args) {
    rsaAlgo.modulusLength = args.size || defaultKeySize
    const key = await crypto.subtle.importKey('spki', helpers.pemToBinary(args.publicKey), rsaAlgo, false, ['encrypt'])
    const encrypted = await crypto.subtle.encrypt(rsaAlgo, key, helpers.textToArrayBuffer(args.plainText))
    return helpers.arrayBufferToBase64(encrypted)
  }

  async decrypt (args) {
    rsaAlgo.modulusLength = args.size || defaultKeySize
    const key = await crypto.subtle.importKey('pkcs8', helpers.pemToBinary(args.privateKey), rsaAlgo, false, ['decrypt'])
    const decoded = await crypto.subtle.decrypt(rsaAlgo, key, helpers.base64ToArrayBuffer(args.cipherText))
    return helpers.arrayBufferToText(decoded)
  }
}
