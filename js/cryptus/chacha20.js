// ChaCha20-Poly1305 support via libsodium if available in browser (window.sodium)
// Falls back to error when not present.

const helpers = require("./helpers");

function getSodium() {
  if (typeof window !== "undefined" && window.sodium && window.sodium.ready) {
    return window.sodium;
  }
  throw new Error("ChaCha20-Poly1305 not available (libsodium not found)");
}

async function encryptChaCha20Hex(plainText, keyHex, nonceHex) {
  const sodium = getSodium();
  await sodium.ready;
  const key = helpers.hexToArrayBuffer(keyHex);
  const nonce = helpers.hexToArrayBuffer(nonceHex);
  if (key.length !== sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES) {
    throw new Error("ChaCha20 key must be 32 bytes");
  }
  if (nonce.length !== sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES) {
    throw new Error("ChaCha20 nonce must be 12 bytes");
  }
  const msg = helpers.textToArrayBuffer(plainText);
  const ad = new Uint8Array(0);
  const ct = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(msg, ad, null, nonce, key);
  return helpers.arrayBufferToHex(ct);
}

async function decryptChaCha20Hex(cipherHex, keyHex, nonceHex) {
  const sodium = getSodium();
  await sodium.ready;
  const key = helpers.hexToArrayBuffer(keyHex);
  const nonce = helpers.hexToArrayBuffer(nonceHex);
  const ct = helpers.hexToArrayBuffer(cipherHex);
  const ad = new Uint8Array(0);
  const pt = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, ct, ad, nonce, key);
  return helpers.arrayBufferToText(pt);
}

module.exports = {
  encryptChaCha20Hex,
  decryptChaCha20Hex,
};
