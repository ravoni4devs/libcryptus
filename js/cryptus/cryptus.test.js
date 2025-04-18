/**
 * @jest-environment jsdom
 */

import Cryptus from './cryptus';
import helpers from './helpers';

describe('encryptAes', () => {
  it('should encrypt plaintext using cryptus AES', async () => {
    const plainText = 'strongpass';
    const cryptus = new Cryptus();
    const passwordHex = await cryptus.pbkdf2({
      plainText: '123456',
      salt: '123456',
      length: 128  // 128 = 32 bits = max length supported to aes-gcm
    })
    expect(passwordHex).toEqual('1498cccb3cab5e895d6912d78aef6ab2');

    const nonceHex = helpers.strToHex('12345678');
    expect(nonceHex).toEqual('3132333435363738');

    const cipherText = await cryptus.encryptAes({plainText, nonceHex, passwordHex});
    expect(cipherText).toEqual('fd1ceaa8d7f03be768d410f07c017f3f7e62c8af6c9061cbaa0d');
  });
});

describe('decryptAes', () => {
  it('should decrypt plaintext using cryptus AES', async () => {
    const cryptus = new Cryptus();
    const passwordHex = await cryptus.pbkdf2({
      plainText: '123456',
      salt: '123456',
      length: 128  // 128 = 32 bits = max length supported to aes-gcm
    })
    const cipherText = 'fd1ceaa8d7f03be768d410f07c017f3f7e62c8af6c9061cbaa0d';
    const nonceHex = '3132333435363738';
    const plainText = await cryptus.decryptAes({cipherText, nonceHex, passwordHex});
    expect(plainText).toEqual('strongpass');
  });
});

describe('argon2', () => {
  it('should generate a argon2id hash', async () => {
    const cryptus = new Cryptus();
    const hash = await cryptus.argon2({plainText: 'strongpass', salt: '1234567812345678'})
    expect(hash).toEqual('05f0bc661b67a007dbb3eea521b58edc');
  });
});

describe('rsa', () => {
  it('should encrypt and decrypt using cryptus RSA', async () => {
    const cryptus = new Cryptus();
    const keyPair = await cryptus.generateRsaKeyPair()
    const publicKey = keyPair.publicKey.pem
    const privateKey = keyPair.privateKey.pem

    const plainText = 'strongpass';
    const encrypted = await cryptus.encryptRsa({publicKey, plainText})
    const decrypted = await cryptus.decryptRsa({privateKey, cipherText: encrypted})

    expect(decrypted).toEqual(plainText);
  });
});

describe('sha256', () => {
  it('should generate sha256 hash', async () => {
    const cryptus = new Cryptus();
    const hash = await cryptus.sha256('test')
    expect(hash).toEqual('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');
  });
})
