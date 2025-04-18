import helpers from './helpers'

export default {
  async deriveKey({plainText, salt, length = 16, iterations = 3, memory = 65536, threads = 2}) {
    if (!window || !window.argon2) {
      throw new Error('Please install argon2-browser')
    }
    const { argon2 } = window
    const hash = await argon2.hash({
      pass: plainText,
      salt: helpers.textToArrayBuffer(salt),
      type: argon2.ArgonType.Argon2id,
      hashLen: length,
      time: iterations,
      mem: memory,
      parallelism: threads,
      version: 0x13
    });
    return hash.hashHex;
  }
}
