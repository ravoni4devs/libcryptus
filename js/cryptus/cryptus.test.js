import Cryptus from './cryptus';
import helpers from './helpers';

describe('pbkdf2HashPassword', () => {
  it('should generate pbkdf2 hash password from plaintext', async () => {
    const cryptus = new Cryptus();
    const salt = '1e3414eb437d1d9e'
    const plainText = 'strongpass'
    const passwordHex = await cryptus.pbkdf2HashPassword({
      salt,
      plainText,
      length: 256, // 256 bits = 32 bytes
      iterations: 10000
    })
    const want = '41be1253a55b95acf136bbeabce9facc05a5ac1cb2a9f4b5267eac38176aca4f'
    expect(passwordHex).toEqual(want);
  })
})

describe('encryptAes', () => {
  it('should encrypt plaintext using cryptus AES', async () => {
    const cryptus = new Cryptus();
    const passwordHex = await cryptus.pbkdf2({
      plainText: 'my-secret-password',
      salt: 'salt1234',
      length: 256  // 32 bits = max length supported to aes-gcm
    })
    expect(passwordHex).toEqual('e9bad40745902f93ddf383aa368634f4684b30c05f8df45bdba0f39155262bed');
    expect(passwordHex).toHaveLength(64); // 32 bytes in hex = 64 chars

    const nonce = '3fpjg9gKn9yz'; 
    const nonceHex = helpers.strToHex(nonce); // 24 chars = 12 bytes is default recommended for AES-GCM 
    expect(nonceHex).toEqual('3366706a6739674b6e39797a');

    const cipherText = await cryptus.encryptAes({plainText: 'some secret', nonceHex, passwordHex});
    expect(cipherText).toEqual('cccfeaa1937ca6c3500fcd8072ad6f8da4abdebaab0026ad5df390');
  });
});

describe('decryptAes', () => {
  it('should decrypt plaintext using cryptus AES', async () => {
    const cryptus = new Cryptus();
    const passwordHex = await cryptus.pbkdf2({
      plainText: 'my-secret-password',
      salt: 'salt1234',
      length: 256  // 32 bits = max length supported to aes-gcm
    })
    const cipherText = 'cccfeaa1937ca6c3500fcd8072ad6f8da4abdebaab0026ad5df390';
    const nonceHex = '3366706a6739674b6e39797a';
    const plainText = await cryptus.decryptAes({cipherText, nonceHex, passwordHex});
    expect(plainText).toEqual('some secret');
  });
});

// describe('argon2', () => {
//   it('should generate a argon2id hash', async () => {
//     const cryptus = new Cryptus();
//     const hash = await cryptus.argon2({plainText: 'strongpass', salt: '1234567812345678'})
//     expect(hash).toEqual('05f0bc661b67a007dbb3eea521b58edc');
//   });
// });

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
