import Aes from './aes';
import pbkdf2 from './pbkdf2';
import argon2 from './argon2';
import Rsa from './rsa';
import helpers from './helpers';

/**
 * Cryptus class provides cryptographic utilities for encryption, decryption, key derivation, and hashing.
 */
export default class Cryptus {
  constructor() {
    this.aesCipher = new Aes();
    this.rsaCipher = new Rsa();
  }

  /**
   * Gets the crypto instance (works in both browser and Node.js)
   * @private
   */
  _getCrypto() {
    return helpers.getCrypto()
  }

  /**
   * Generates a random nonce of the specified length.
   * @param {Object} options - The options for nonce generation.
   * @param {number} [options.length=16] - The length of the nonce in characters.
   * @param {boolean} [options.hex=false] - Whether to convert the nonce to a hex string.
   * @returns {string} A random nonce, optionally hex-encoded.
   */
  // generateNonce({ length = 16, hex = false } = {}) {
  //   const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  //   const charactersLength = characters.length;
  //   const cryptoInstance = helpers._getCrypto();
  //   const randomValues = cryptoInstance.getRandomValues(new Uint32Array(length));
  //   let nonce = '';
  //   for (let i = 0; i < length; i++) {
  //     nonce += characters.charAt(randomValues[i] % charactersLength);
  //   }
  //   if (hex) {
  //     return this.toHex(nonce);
  //   }
  //   return nonce;
  // }
  /**
   * Generates a random nonce of the specified length in bytes.
   * @param {Object} options - The options for nonce generation.
   * @param {number} [options.length=12] - The length of the nonce in bytes (12 bytes recommended for AES-GCM).
   * @param {boolean} [options.hex=true] - Whether to return the nonce as a hex string (default) or as a base64 string.
   * @returns {string} A random nonce as hex string or base64 string.
   */
  generateNonce({ length = 12, hex = true } = {}) {
    const cryptoInstance = this._getCrypto();
    const randomBytes = cryptoInstance.getRandomValues(new Uint8Array(length));
    if (hex) {
      return helpers.arrayBufferToHex(randomBytes)
    }
    return helpers.arrayBufferToBase64(randomBytes)
  }

  /**
   * Converts a string to its hexadecimal representation.
   * @param {string} val - The string to convert.
   * @returns {string} The hexadecimal representation of the string.
   */
  toHex(val) {
    return helpers.strToHex(val);
  }

  /**
   * Encrypts the given data using the AES algorithm.
   * @param {Object} args - The encryption arguments.
   * @param {string} args.plainText - The plaintext to encrypt.
   * @param {string} args.passwordHex - The password in hexadecimal format.
   * @param {string} args.nonceHex - The nonce in hexadecimal format.
   * @returns {Promise<string>} The encrypted data as a string.
   */
  async encryptAes(args) {
    return await this.aesCipher.encrypt(args);
  }

  /**
   * Decrypts the given data using the AES algorithm.
   * @param {Object} args - The decryption arguments.
   * @param {string} args.cipherText - The encrypted text to decrypt.
   * @param {string} args.passwordHex - The password in hexadecimal format.
   * @param {string} args.nonceHex - The nonce in hexadecimal format.
   * @returns {Promise<string>} The decrypted data as a string.
   */
  async decryptAes(args) {
    return await this.aesCipher.decrypt(args);
  }

  /**
   * Derives a key using the PBKDF2 algorithm.
   * @param {Object} args - The key derivation arguments.
   * @param {string} args.plainText - The plaintext password.
   * @param {string} args.salt - The salt value.
   * @param {number} [args.iterations=10000] - The number of iterations.
   * @param {number} [args.length=256] - The desired key length in bits.
   * @returns {Promise<string>} The derived key as a hexadecimal string.
   */
  async pbkdf2(args) {
    return await pbkdf2.deriveKey(args);
  }

  /**
   * Derives a hash password using the PBKDF2 algorithm.
   * @param {Object} args - The key derivation arguments.
   * @param {string} args.plainText - The plaintext password.
   * @param {string} args.salt - The salt value.
   * @param {number} [args.iterations=10000] - The number of iterations.
   * @param {number} [args.length=256] - The desired hash length in bits.
   * @returns {Promise<string>} The derived hash as a hexadecimal string.
   */
  async pbkdf2HashPassword(args) {
    return await pbkdf2.deriveBits(args);
  }

  /**
   * Derives a key using the Argon2 algorithm.
   * @param {Object} args - The key derivation arguments.
   * @param {string} args.plainText - The plaintext password.
   * @param {string} args.salt - The salt value.
   * @param {number} [args.length=16] - The desired hash length in bytes.
   * @param {number} [args.iterations=3] - The number of iterations.
   * @param {number} [args.memory=65536] - Memory cost in KiB.
   * @param {number} [args.threads=2] - Parallelism factor.
   * @returns {Promise<string>} The derived key as a hexadecimal string.
   */
  async argon2(args) {
    return await argon2.deriveKey(args);
  }

  /**
   * Generates an RSA key pair.
   * @param {Object} [args] - The key generation arguments.
   * @param {number} [args.size=2048] - The key size in bits.
   * @returns {Promise<{ publicKey: { pem: string, base64: string }, privateKey: { pem: string, base64: string } }>} The generated RSA key pair.
   */
  async generateRsaKeyPair(args) {
    return await this.rsaCipher.generateKeyPair(args);
  }

  /**
   * Encrypts data using the RSA algorithm.
   * @param {Object} args - The encryption arguments.
   * @param {string} args.publicKey - The public key in PEM format.
   * @param {string} args.plainText - The plaintext to encrypt.
   * @param {number} [args.size=2048] - The key size in bits.
   * @returns {Promise<string>} The encrypted data as a base64 string.
   */
  async encryptRsa(args) {
    return await this.rsaCipher.encrypt(args);
  }

  /**
   * Decrypts data using the RSA algorithm.
   * @param {Object} args - The decryption arguments.
   * @param {string} args.privateKey - The private key in PEM format.
   * @param {string} args.cipherText - The encrypted text in base64 format.
   * @param {number} [args.size=2048] - The key size in bits.
   * @returns {Promise<string>} The decrypted data as a string.
   */
  async decryptRsa(args) {
    return await this.rsaCipher.decrypt(args);
  }

  /**
   * Computes the SHA-256 hash of the given value.
   * @param {string} value - The value to hash.
   * @returns {Promise<string>} The SHA-256 hash as a hexadecimal string.
   */
  async sha256(value) {
    const cryptoInstance = this._getCrypto();
    const encoded = new TextEncoder().encode(value);
    const buffer = await cryptoInstance.subtle.digest('SHA-256', encoded);
    const hashArray = Array.from(new Uint8Array(buffer));
    const hashHex = hashArray.map((b) => ('00' + b.toString(16)).slice(-2)).join('');
    return hashHex;
  }
}
