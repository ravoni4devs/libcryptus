const { TextEncoder, TextDecoder } = require('util');
const { webcrypto } = require('crypto');

global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

global.crypto = webcrypto;

global.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
global.atob = (b64) => Buffer.from(b64, 'base64').toString('binary');

global.window = {
  crypto: webcrypto,
};

Object.defineProperty(global, 'crypto', {
  value: webcrypto,
  writable: false,
});
