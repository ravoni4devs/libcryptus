const helpers = require("./helpers");

async function importAesKeyFromHex(passwordHex) {
  const crypto = helpers.getCrypto();
  const keyBytes = helpers.hexToArrayBuffer(passwordHex);
  if (![16, 24, 32].includes(keyBytes.length)) {
    throw new Error("AES key must be 16/24/32 bytes");
  }
  return crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function encryptAESGCMHex(plainText, passwordHex, nonceHex) {
  const crypto = helpers.getCrypto();
  const key = await importAesKeyFromHex(passwordHex);
  const iv = helpers.hexToArrayBuffer(nonceHex);
  if (iv.length !== 12) throw new Error("AES-GCM nonce must be 12 bytes");
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, helpers.textToArrayBuffer(plainText));
  return helpers.arrayBufferToHex(ct);
}

async function decryptAESGCMHex(cipherHex, passwordHex, nonceHex) {
  const crypto = helpers.getCrypto();
  const key = await importAesKeyFromHex(passwordHex);
  const iv = helpers.hexToArrayBuffer(nonceHex);
  if (iv.length !== 12) throw new Error("AES-GCM nonce must be 12 bytes");
  const ct = helpers.hexToArrayBuffer(cipherHex);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return helpers.arrayBufferToText(pt);
}

module.exports = {
  encryptAESGCMHex,
  decryptAESGCMHex,
};
