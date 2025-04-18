import helpers from './helpers'

const crypto = window.crypto

const importKeyFromRaw = async (passwordHex) => {
  try {
    const keyData = helpers.hexToArrayBuffer(passwordHex) // max 32 bytes
    const key = await crypto.subtle.importKey('raw', keyData, 'AES-GCM', false, ['encrypt', 'decrypt'])
    return key
  } catch (err) {
    throw new Error('Failed to import key from hash.', err)
  }
}

class Aes {
  // nonceHex should be a 8 lenght string in hex
  // passwordHex = pbkdf2 hash in hex format
  async encrypt({plainText, passwordHex, nonceHex}) {
    const key = await importKeyFromRaw(passwordHex)
    const algo = {
      name: 'AES-GCM',
      iv: helpers.hexToArrayBuffer(nonceHex)
    }
    const encrypted = await crypto.subtle.encrypt(algo, key, helpers.textToArrayBuffer(plainText))
    return helpers.arrayBufferToHex(encrypted)
  }

  // secretKey = pbkdf2 hash
  // cipherText and nonce = hex strings
  async decrypt({cipherText, passwordHex, nonceHex}) {
    const key = await importKeyFromRaw(passwordHex)
    const iv = helpers.hexToArrayBuffer(nonceHex)
    const cipherBytes = helpers.hexToArrayBuffer(cipherText)
    const algo = {name: 'AES-GCM', iv}
    const decrypted = await crypto.subtle.decrypt(algo, key, cipherBytes)
    return helpers.arrayBufferToText(decrypted)
  }
}

// module.exports = Aes;
export default Aes
