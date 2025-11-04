const helpers = require("./helpers");

const DEFAULT_KEY_SIZE = 2048;

async function generateRsaKeyPair(size = DEFAULT_KEY_SIZE) {
  const crypto = helpers.getCrypto();
  const algo = {
    name: "RSA-OAEP",
    modulusLength: size,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: "SHA-256",
  };
  const kp = await crypto.subtle.generateKey(algo, true, ["encrypt", "decrypt"]);
  const spki = await crypto.subtle.exportKey("spki", kp.publicKey);
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", kp.privateKey);
  const publicKeyPEM = helpers.binaryToPem(spki, "PUBLIC KEY");
  const privateKeyPEM = helpers.binaryToPem(pkcs8, "PRIVATE KEY");
  return { privateKey: privateKeyPEM, publicKey: publicKeyPEM };
}

async function importPublicKeyPEM(pem) {
  const crypto = helpers.getCrypto();
  const der = helpers.pemToBinary(pem);
  return crypto.subtle.importKey("spki", der, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
}

async function importPrivateKeyPEM(pem) {
  const crypto = helpers.getCrypto();
  const der = helpers.pemToBinary(pem);
  return crypto.subtle.importKey("pkcs8", der, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
}

async function encryptRsaOAEPB64(plainText, publicKeyPEM) {
  const crypto = helpers.getCrypto();
  const pub = await importPublicKeyPEM(publicKeyPEM);
  const ct = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, helpers.textToArrayBuffer(plainText));
  return helpers.b64urlFromBytes(new Uint8Array(ct));
}

async function decryptRsaOAEPB64(cipherB64, privateKeyPEM) {
  const crypto = helpers.getCrypto();
  const priv = await importPrivateKeyPEM(privateKeyPEM);
  const ct = helpers.bytesFromB64url(cipherB64);
  const pt = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, ct);
  return helpers.arrayBufferToText(pt);
}

module.exports = {
  generateRsaKeyPair,
  encryptRsaOAEPB64,
  decryptRsaOAEPB64,
};
