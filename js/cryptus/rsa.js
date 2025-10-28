import helpers from './helpers';

const defaultKeySize = 2048;

const rsaAlgo = {
  name: 'RSA-OAEP',
  modulusLength: defaultKeySize,
  publicExponent: new Uint8Array([1, 0, 1]),
  extractable: true,
  hash: {
    name: 'SHA-256',
  },
};

export default class Rsa {
  async generateKeyPair(args = {}) {
    const cryptoInstance = helpers.getCrypto();
    const algo = { ...rsaAlgo, modulusLength: args.size || defaultKeySize };
    const keyPair = await cryptoInstance.subtle.generateKey(algo, true, ['encrypt', 'decrypt']);
    const spki = await cryptoInstance.subtle.exportKey('spki', keyPair.publicKey);
    const pkcs8 = await cryptoInstance.subtle.exportKey('pkcs8', keyPair.privateKey);
    const publicKey = helpers.binaryToPem(spki, 'RSA PUBLIC KEY');
    const privateKey = helpers.binaryToPem(pkcs8, 'RSA PRIVATE KEY');
    return {
      publicKey: {
        pem: publicKey,
        base64: helpers.strToBase64(publicKey),
      },
      privateKey: {
        pem: privateKey,
        base64: helpers.strToBase64(privateKey),
      },
    };
  }

  async encrypt(args) {
    const cryptoInstance = helpers.getCrypto();
    const algo = { ...rsaAlgo, modulusLength: args.size || defaultKeySize };
    const key = await cryptoInstance.subtle.importKey(
      'spki',
      helpers.pemToBinary(args.publicKey),
      algo,
      false,
      ['encrypt']
    );
    const encrypted = await cryptoInstance.subtle.encrypt(
      algo,
      key,
      helpers.textToArrayBuffer(args.plainText)
    );
    return helpers.arrayBufferToBase64(encrypted);
  }

  async decrypt(args) {
    const cryptoInstance = helpers.getCrypto();
    const algo = { ...rsaAlgo, modulusLength: args.size || defaultKeySize };
    const key = await cryptoInstance.subtle.importKey(
      'pkcs8',
      helpers.pemToBinary(args.privateKey),
      algo,
      false,
      ['decrypt']
    );
    const decoded = await cryptoInstance.subtle.decrypt(
      algo,
      key,
      helpers.base64ToArrayBuffer(args.cipherText)
    );
    return helpers.arrayBufferToText(decoded);
  }
}
