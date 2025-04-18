// const crypto = require('crypto').webcrypto
// const { subtle, getRandomValues } = crypto
// const { importKey, exportKey, deriveKey } = subtle
const util = require('util');
const { TextEncoder, TextDecoder } = util;
const { Crypto } = require('@peculiar/webcrypto');

global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

const cryptoModule = new Crypto();
global.crypto = cryptoModule;
Object.defineProperty(window, 'crypto', {
  get(){
    return cryptoModule
  }
});
// global.crypto = {
//   subtle: {
//     importKey,
//     exportKey,
//     deriveKey
//   },
//   getRandomValues
// }
