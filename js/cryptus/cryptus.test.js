const Cryptus = require('./cryptus');
const helpers = require('./helpers');

describe('Pbkdf2 (hex)', () => {
  it('should generate pbkdf2 hash password from plaintext', async () => {
    const cryptus = new Cryptus();
    const salt = '1e3414eb437d1d9e';
    const plainText = 'strongpass';

    // length in BYTES (32 bytes = 256 bits)
    const passwordHex = await cryptus.Pbkdf2(plainText, salt, {
      iterations: 10000,
      length: 32,
    });

    const want = '41be1253a55b95acf136bbeabce9facc05a5ac1cb2a9f4b5267eac38176aca4f';
    expect(passwordHex).toEqual(want);
  });
});

describe('EncryptAESGCMHex', () => {
  it('should encrypt plaintext using cryptus AES-GCM (hex IO)', async () => {
    const cryptus = new Cryptus();

    // PBKDF2 -> 32 bytes (AES-256)
    const passwordHex = await cryptus.Pbkdf2('my-secret-password', 'salt1234', {
      length: 32,         // BYTES (32 bytes = 256 bits)
      iterations: 10000,
    });
    expect(passwordHex).toEqual('e9bad40745902f93ddf383aa368634f4684b30c05f8df45bdba0f39155262bed');
    expect(passwordHex).toHaveLength(64); // 32 bytes in hex

    // Nonce: 12 bytes (24 hex chars)
    const nonce = '3fpjg9gKn9yz';
    const nonceHex = helpers.strToHex(nonce);
    expect(nonceHex).toEqual('3366706a6739674b6e39797a');

    const cipherHex = await cryptus.EncryptAESGCMHex('some secret', passwordHex, nonceHex);
    expect(cipherHex).toEqual('cccfeaa1937ca6c3500fcd8072ad6f8da4abdebaab0026ad5df390');
  });
});

describe('DecryptAESGCMHex', () => {
  it('should decrypt ciphertext using cryptus AES-GCM (hex IO)', async () => {
    const cryptus = new Cryptus();

    const passwordHex = await cryptus.Pbkdf2('my-secret-password', 'salt1234', {
      length: 32,         // BYTES
      iterations: 10000,
    });
    const cipherHex = 'cccfeaa1937ca6c3500fcd8072ad6f8da4abdebaab0026ad5df390';
    const nonceHex  = '3366706a6739674b6e39797a';

    const plainText = await cryptus.DecryptAESGCMHex(cipherHex, passwordHex, nonceHex);
    expect(plainText).toEqual('some secret');
  });
});

describe('RSA-OAEP (SHA-256) B64url', () => {
  it('should encrypt and decrypt using cryptus RSA helpers', async () => {
    const cryptus = new Cryptus();
    const { publicKey, privateKey } = await cryptus.GenerateRsaKeyPair(2048);

    const plainText = 'strongpass';
    const encryptedB64url = await cryptus.EncryptRsaOAEPB64(plainText, publicKey);
    const decrypted = await cryptus.DecryptRsaOAEPB64(encryptedB64url, privateKey);

    expect(decrypted).toEqual(plainText);
  });
});

describe('Sha256Hex', () => {
  it('should generate sha256 hash (hex)', async () => {
    const cryptus = new Cryptus();
    const hashHex = await cryptus.Sha256Hex('test');
    expect(hashHex).toEqual('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');
  });
});
