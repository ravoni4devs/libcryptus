const getCrypto = () => {
  if (typeof window !== 'undefined' && window.crypto) {
    return window.crypto;
  }
  if (typeof global !== 'undefined' && global.crypto) {
    return global.crypto;
  }
  return crypto;
};

const arrayBufferToBase64 = (buf) => {
  const byteArray = new Uint8Array(buf);
  let byteString = '';
  for (let i = 0; i < byteArray.byteLength; i++) {
    byteString += String.fromCharCode(byteArray[i]);
  }
  return btoa(byteString);
};

const base64ToArrayBuffer = (b64str) => {
  const byteStr = atob(b64str);
  const bytes = new Uint8Array(byteStr.length);
  for (let i = 0; i < byteStr.length; i++) {
    bytes[i] = byteStr.charCodeAt(i);
  }
  return bytes.buffer;
};

const arrayBufferToText = (buf) => {
  return new TextDecoder().decode(buf);
};

const textToArrayBuffer = (str) => {
  return new TextEncoder().encode(str);
};

const binaryToPem = (binaryData, label) => {
  const base64Cert = arrayBufferToBase64(binaryData);
  let pemCert = '-----BEGIN ' + label + '-----\r\n';
  let nextIndex = 0;
  while (nextIndex < base64Cert.length) {
    if (nextIndex + 64 <= base64Cert.length) {
      pemCert += base64Cert.substring(nextIndex, nextIndex + 64) + '\r\n';
    } else {
      pemCert += base64Cert.substring(nextIndex) + '\r\n';
    }
    nextIndex += 64;
  }
  pemCert += '-----END ' + label + '-----\r\n';
  return pemCert;
};

const pemToBinary = (pem = '') => {
  const lines = pem.split('\n');
  let encoded = '';
  for (let i = 0; i < lines.length; i++) {
    if (
      lines[i].trim().length > 0 &&
      lines[i].indexOf('-BEGIN') < 0 &&
      lines[i].indexOf('-END') < 0
    ) {
      encoded += lines[i].trim();
    }
  }
  return base64ToArrayBuffer(encoded);
};

const hexToArrayBuffer = (hexString) => {
  if (hexString.length % 2 !== 0) {
    throw new Error('Invalid hexString.');
  }
  const arrayBuffer = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < hexString.length; i += 2) {
    const byteValue = parseInt(hexString.substring(i, i + 2), 16);
    if (isNaN(byteValue)) {
      throw new Error('Byte value is not a number.');
    }
    arrayBuffer[i / 2] = byteValue;
  }
  return arrayBuffer;
};

const arrayBufferToHex = (b) => {
  if (!b) {
    throw new Error('No bytes to convert to Hex');
  }
  const bytes = new Uint8Array(b);
  const hexBytes = [];
  for (let i = 0; i < bytes.length; ++i) {
    let byteString = bytes[i].toString(16);
    if (byteString.length < 2) {
      byteString = `0${byteString}`;
    }
    hexBytes.push(byteString);
  }
  return hexBytes.join('');
};

const strToBase64 = (str) => {
  return btoa(str);
};

const base64ToStr = (b64) => {
  return atob(b64);
};

const strToUtf16Bytes = (str) => {
  const bytes = [];
  for (let ii = 0; ii < str.length; ii++) {
    const code = str.charCodeAt(ii);
    bytes.push(code & 255, code >> 8);
  }
  return bytes;
};

const strToHex = (str) => {
  const stringBytes = new TextEncoder().encode(str);
  return Array.from(stringBytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
};

const randomIv = (size) => {
  const bytes = crypto.getRandomValues(new Uint8Array(size / 2));
  const hexBytes = [];
  for (let i = 0; i < bytes.length; ++i) {
    let byteString = bytes[i].toString(16);
    if (byteString.length < 2) {
      byteString = `0${byteString}`;
    }
    hexBytes.push(byteString);
  }
  return hexBytes.join('');
};

export default {
  arrayBufferToBase64,
  base64ToArrayBuffer,
  arrayBufferToText,
  textToArrayBuffer,
  binaryToPem,
  pemToBinary,
  hexToArrayBuffer,
  arrayBufferToHex,
  strToBase64,
  base64ToStr,
  strToUtf16Bytes,
  strToHex,
  randomIv,
  getCrypto,
};
