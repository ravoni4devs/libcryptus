const helpers = require("./helpers");

async function pbkdf2Hex(plainText, salt, iterations = 10000, lengthBytes = 16) {
  const crypto = helpers.getCrypto();
  const key = await crypto.subtle.importKey("raw", helpers.textToArrayBuffer(plainText), { name: "PBKDF2" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: helpers.textToArrayBuffer(salt), iterations, hash: "SHA-256" },
    key,
    lengthBytes * 8
  );
  return helpers.arrayBufferToHex(bits);
}

module.exports = { pbkdf2Hex };
