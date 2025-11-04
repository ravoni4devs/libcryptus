const helpers = require("./helpers");
const aes = require("./aes");
const chacha = require("./chacha20");
const { pbkdf2Hex } = require("./pbkdf2");
const { argon2Hex } = require("./argon2");
const rsa = require("./rsa");

class Cryptus {
  constructor() {}

  async GenerateNonceBytes(n) {
    return helpers.randomBytes(n);
  }
  async GenerateNonceHex(n) {
    return helpers.arrayBufferToHex(helpers.randomBytes(n));
  }
  async GenerateNonceB64URL(n) {
    return helpers.b64urlFromBytes(helpers.randomBytes(n));
  }

  // Hash helper
  async Sha256Hex(value) {
    const crypto = helpers.getCrypto();
    const buf = await crypto.subtle.digest("SHA-256", helpers.textToArrayBuffer(value));
    return helpers.arrayBufferToHex(buf);
  }

  // Constant-time hex compare
  CompareHashHex(aHex, bHex) {
    if (typeof aHex !== "string" || typeof bHex !== "string") return false;
    if (aHex.length !== bHex.length) {
      // keep timing similar
      let acc = 0;
      for (let i = 0; i < aHex.length; i++) acc |= (aHex.charCodeAt(i) ^ 0);
      return false && acc === 0;
    }
    let diff = 0;
    for (let i = 0; i < aHex.length; i++) diff |= (aHex.charCodeAt(i) ^ bHex.charCodeAt(i));
    return diff === 0;
  }

  // PBKDF2 -> hex
  async Pbkdf2(plainText, salt, opts = {}) {
    const iterations = Number.isInteger(opts.iterations) ? opts.iterations : 10000;
    const length = Number.isInteger(opts.length) ? opts.length : 16;
    return pbkdf2Hex(plainText, salt, iterations, length);
  }

  // Argon2id -> hex
  async Argon2Hex(plainText, salt, opts = {}) {
    const length = Number.isInteger(opts.length) ? opts.length : 32;
    const iterations = Number.isInteger(opts.iterations) ? opts.iterations : 3;
    const memory = Number.isInteger(opts.memory) ? opts.memory : 65536;
    const threads = Number.isInteger(opts.threads) ? opts.threads : 1;
    return argon2Hex(plainText, salt, length, iterations, memory, threads);
  }

  // AES-GCM (hex IO)
  async EncryptAESGCMHex(plainText, passwordHex, nonceHex) {
    return aes.encryptAESGCMHex(plainText, passwordHex, nonceHex);
  }
  async DecryptAESGCMHex(cipherHex, passwordHex, nonceHex) {
    return aes.decryptAESGCMHex(cipherHex, passwordHex, nonceHex);
  }

  // ChaCha20-Poly1305 (hex IO) - requires libsodium
  async EncryptChaCha20Hex(plainText, keyHex, nonceHex) {
    return chacha.encryptChaCha20Hex(plainText, keyHex, nonceHex);
  }
  async DecryptChaCha20Hex(cipherHex, keyHex, nonceHex) {
    return chacha.decryptChaCha20Hex(cipherHex, keyHex, nonceHex);
  }

  // RSA-OAEP (SHA-256) with Base64 URL-safe
  async GenerateRsaKeyPair(size = 2048) {
    const { privateKey, publicKey } = await rsa.generateRsaKeyPair(size);
    return { privateKey, publicKey };
  }
  async EncryptRsaOAEPB64(plainText, publicKeyPEM) {
    return rsa.encryptRsaOAEPB64(plainText, publicKeyPEM);
  }
  async DecryptRsaOAEPB64(cipherB64, privateKeyPEM) {
    return rsa.decryptRsaOAEPB64(cipherB64, privateKeyPEM);
  }
}

module.exports = Cryptus;
