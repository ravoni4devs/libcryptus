import Aes from './aes'
import pbkdf2 from './pbkdf2'
import argon2 from './argon2'
import Rsa from './rsa'
import helpers from './helpers'

export default class Cryptus {
  constructor() {
    this.aesCipher = new Aes()
    this.rsaCipher = new Rsa()
  }

  generateNonce({ length = 16, hex = false }) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    let nonce = '';
    for (let i = 0; i < length; i++) {
      nonce += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    if (hex) {
      return this.toHex(nonce);
    }
    return nonce;
  }

  toHex(val) {
    return helpers.strToHex(val);
  }

  async encryptAes(args) {
    return await this.aesCipher.encrypt(args)
  }

  async decryptAes(args) {
    return await this.aesCipher.decrypt(args)
  }

  async pbkdf2(args) {
    return await pbkdf2.deriveKey(args)
  }

  async argon2(args) {
    return await argon2.deriveKey(args)
  }

  async generateRsaKeyPair(args) {
    return await this.rsaCipher.generateKeyPair(args)
  }

  async encryptRsa(args) {
    return await this.rsaCipher.encrypt(args)
  }

  async decryptRsa(args) {
    return await this.rsaCipher.decrypt(args)
  }

  async sha256(value) {
    const encoded = new TextEncoder().encode(value)
    const buffer = await crypto.subtle.digest('SHA-256', encoded)
    const hashArray = Array.from(new Uint8Array(buffer))
    const hashHex = hashArray.map(b => ('00' + b.toString(16)).slice(-2)).join('')
    return hashHex
  }
}

// module.exports = Cryptus;
// export default Cryptus
