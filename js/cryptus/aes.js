import helpers from './helpers';

const importKeyFromRaw = async (passwordHex) => {
  try {
    const cryptoInstance = helpers.getCrypto();
    const keyData = helpers.hexToArrayBuffer(passwordHex);
    const key = await cryptoInstance.subtle.importKey(
      'raw', 
      keyData, 
      'AES-GCM', 
      false, 
      ['encrypt', 'decrypt']
    );
    return key;
  } catch (err) {
    throw new Error('Failed to import key from hash: ' + err.message);
  }
};

class Aes {
  async encrypt({ plainText, passwordHex, nonceHex }) {
    if (nonceHex && nonceHex.length < 24) {
      throw Error('Nonce '+nonceHex+ 'is too short')
    }
    const cryptoInstance = helpers.getCrypto();
    const key = await importKeyFromRaw(passwordHex);
    const algo = {
      name: 'AES-GCM',
      iv: helpers.hexToArrayBuffer(nonceHex),
    };
    const encrypted = await cryptoInstance.subtle.encrypt(
      algo,
      key,
      helpers.textToArrayBuffer(plainText)
    );
    return helpers.arrayBufferToHex(encrypted);
  }

  async decrypt({ cipherText, passwordHex, nonceHex }) {
    const cryptoInstance = helpers.getCrypto();
    const key = await importKeyFromRaw(passwordHex);
    const iv = helpers.hexToArrayBuffer(nonceHex);
    const cipherBytes = helpers.hexToArrayBuffer(cipherText);
    const algo = { name: 'AES-GCM', iv };
    const decrypted = await cryptoInstance.subtle.decrypt(algo, key, cipherBytes);
    return helpers.arrayBufferToText(decrypted);
  }
}

export default Aes;
