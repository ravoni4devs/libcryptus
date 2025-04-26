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
   * Generates a random nonce of the specified length.
   * @param {Object} options - The options for nonce generation.
   * @param {number} [options.length=16] - The length of the nonce in characters.
   * @param {boolean} [options.hex=false] - Whether to convert the nonce to a hex string.
   * @returns {string} A random nonce, optionally hex-encoded.
   */
  generateNonce({ length = 16, hex = false }) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    let nonce = '';
    for (let i = 0; i < length; i++) {
      nonce += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    if (hex) {
      return this.toHex(nonce);
    }
    return nonce;
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
   * @returns {Promise<string>} The derived key as a string.
   */
  async pbkdf2(args) {
    return await pbkdf2.deriveKey(args);
  }

  /**
   * Derives a key using the Argon2 algorithm.
   * @param {Object} args - The key derivation arguments.
   * @returns {Promise<string>} The derived key as a string.
   */
  async argon2(args) {
    return await argon2.deriveKey(args);
  }

  /**
   * Generates an RSA key pair.
   * @param {Object} args - The key generation arguments.
   * @returns {Promise<{ publicKey: { pem: string, base64: string }, privateKey: { pem: string, base64: string } }>} The generated RSA key pair, with public and private keys in PEM and Base64 formats.
   */
  async generateRsaKeyPair(args) {
    return await this.rsaCipher.generateKeyPair(args);
  }

  /**
   * Encrypts data using the RSA algorithm.
   * @param {Object} args - The encryption arguments.
   * @returns {Promise<string>} The encrypted data as a string.
   */
  async encryptRsa(args) {
    return await this.rsaCipher.encrypt(args);
  }

  /**
   * Decrypts data using the RSA algorithm.
   * @param {Object} args - The decryption arguments.
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
    const encoded = new TextEncoder().encode(value);
    const buffer = await crypto.subtle.digest('SHA-256', encoded);
    const hashArray = Array.from(new Uint8Array(buffer));
    const hashHex = hashArray.map(b => ('00' + b.toString(16)).slice(-2)).join('');
    return hashHex;
  }
}
