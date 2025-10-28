import helpers from './helpers';

const pbkdf2Algo = {
  name: 'PBKDF2',
};

export default {
  async deriveKey({ plainText = '', salt = '', iterations = 10000, length = 256 } = {}) {
    const cryptoInstance = helpers.getCrypto();
    const key = await cryptoInstance.subtle.importKey(
      'raw',
      helpers.textToArrayBuffer(plainText),
      pbkdf2Algo,
      false,
      ['deriveKey']
    );
    const params = {
      name: pbkdf2Algo.name,
      salt: helpers.textToArrayBuffer(salt),
      iterations,
      hash: 'SHA-256',
    };
    const aesAlgo = {
      name: 'AES-GCM',
      length,
    };
    const result = await cryptoInstance.subtle.deriveKey(params, key, aesAlgo, true, [
      'encrypt',
      'decrypt',
    ]);
    const exported = await cryptoInstance.subtle.exportKey('raw', result);
    return helpers.arrayBufferToHex(exported);
  },

  async deriveBits({ plainText = '', salt = '', length = 256, iterations = 10000 } = {}) {
    const cryptoInstance = helpers.getCrypto();
    const key = await cryptoInstance.subtle.importKey(
      'raw',
      helpers.textToArrayBuffer(plainText),
      pbkdf2Algo,
      false,
      ['deriveBits']
    );
    const params = {
      name: pbkdf2Algo.name,
      salt: helpers.textToArrayBuffer(salt),
      iterations,
      hash: 'SHA-256',
    };
    const derived = await cryptoInstance.subtle.deriveBits(params, key, length);
    return helpers.arrayBufferToHex(derived);
  },
};
