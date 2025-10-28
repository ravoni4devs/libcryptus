import helpers from './helpers';

export default {
  async deriveKey({
    plainText = '',
    salt = '',
    length = 16,
    iterations = 3,
    memory = 65536,
    threads = 2,
  } = {}) {
    if (typeof window === 'undefined' || !window.argon2) {
      console.warn('Argon2 not available in Node.js environment');
      return 'argon2_not_available_in_nodejs';
    }
    const { argon2 } = window;
    const hash = await argon2.hash({
      pass: plainText,
      salt: helpers.textToArrayBuffer(salt),
      type: argon2.ArgonType.Argon2id,
      hashLen: length,
      time: iterations,
      mem: memory,
      parallelism: threads,
      version: 0x13,
    });
    return hash.hashHex;
  },
};
