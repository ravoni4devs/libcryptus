/**
 * Cryptus class provides cryptographic utilities for encryption, decryption, key derivation, and hashing.
 */
export default class Cryptus {
    aesCipher: Aes;
    rsaCipher: Rsa;
    /**
     * Generates a random nonce of the specified length.
     * @param {Object} options - The options for nonce generation.
     * @param {number} [options.length=16] - The length of the nonce in characters.
     * @param {boolean} [options.hex=false] - Whether to convert the nonce to a hex string.
     * @returns {string} A random nonce, optionally hex-encoded.
     */
    generateNonce({ length, hex }: {
        length?: number;
        hex?: boolean;
    }): string;
    /**
     * Converts a string to its hexadecimal representation.
     * @param {string} val - The string to convert.
     * @returns {string} The hexadecimal representation of the string.
     */
    toHex(val: string): string;
    /**
     * Encrypts the given data using the AES algorithm.
     * @param {Object} args - The encryption arguments.
     * @param {string} args.plainText - The plaintext to encrypt.
     * @param {string} args.passwordHex - The password in hexadecimal format.
     * @param {string} args.nonceHex - The nonce in hexadecimal format.
     * @returns {Promise<string>} The encrypted data as a string.
     */
    encryptAes(args: {
        plainText: string;
        passwordHex: string;
        nonceHex: string;
    }): Promise<string>;
    /**
     * Decrypts the given data using the AES algorithm.
     * @param {Object} args - The decryption arguments.
     * @param {string} args.cipherText - The encrypted text to decrypt.
     * @param {string} args.passwordHex - The password in hexadecimal format.
     * @param {string} args.nonceHex - The nonce in hexadecimal format.
     * @returns {Promise<string>} The decrypted data as a string.
     */
    decryptAes(args: {
        cipherText: string;
        passwordHex: string;
        nonceHex: string;
    }): Promise<string>;
    /**
     * Derives a key using the PBKDF2 algorithm.
     * @param {Object} args - The key derivation arguments.
     * @returns {Promise<string>} The derived key as a string.
     */
    pbkdf2(args: any): Promise<string>;
    /**
     * Derives a key using the Argon2 algorithm.
     * @param {Object} args - The key derivation arguments.
     * @returns {Promise<string>} The derived key as a string.
     */
    argon2(args: any): Promise<string>;
    /**
     * Generates an RSA key pair.
     * @param {Object} args - The key generation arguments.
     * @returns {Promise<{ publicKey: { pem: string, base64: string }, privateKey: { pem: string, base64: string } }>} The generated RSA key pair, with public and private keys in PEM and Base64 formats.
     */
    generateRsaKeyPair(args: any): Promise<{
        publicKey: {
            pem: string;
            base64: string;
        };
        privateKey: {
            pem: string;
            base64: string;
        };
    }>;
    /**
     * Encrypts data using the RSA algorithm.
     * @param {Object} args - The encryption arguments.
     * @returns {Promise<string>} The encrypted data as a string.
     */
    encryptRsa(args: any): Promise<string>;
    /**
     * Decrypts data using the RSA algorithm.
     * @param {Object} args - The decryption arguments.
     * @returns {Promise<string>} The decrypted data as a string.
     */
    decryptRsa(args: any): Promise<string>;
    /**
     * Computes the SHA-256 hash of the given value.
     * @param {string} value - The value to hash.
     * @returns {Promise<string>} The SHA-256 hash as a hexadecimal string.
     */
    sha256(value: string): Promise<string>;
}
import Aes from './aes';
import Rsa from './rsa';
