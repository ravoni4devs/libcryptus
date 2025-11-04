// Argon2id via argon2-browser (window.argon2). Returns hex.
const helpers = require("./helpers");

async function argon2Hex(plainText, salt, lengthBytes = 32, iterations = 3, memoryKiB = 65536, threads = 1) {
  if (typeof window === "undefined" || !window.argon2 || !window.argon2.hash) {
    throw new Error("Argon2 is not available in this environment (expecting argon2-browser)");
  }
  const a2 = window.argon2;
  const res = await a2.hash({
    pass: plainText instanceof Uint8Array ? plainText : helpers.textToArrayBuffer(plainText),
    salt: salt instanceof Uint8Array ? salt : helpers.textToArrayBuffer(salt),
    type: a2.ArgonType.Argon2id,
    hashLen: lengthBytes,
    time: iterations,
    mem: memoryKiB,
    parallelism: threads,
    version: 0x13,
  });
  return res.hashHex;
}

module.exports = { argon2Hex };
