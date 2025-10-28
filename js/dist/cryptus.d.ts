/**
 * Cryptus class provides cryptographic utilities for encryption, decryption, key derivation, and hashing.
 */
export default class Cryptus {
    aesCipher: Aes;
    rsaCipher: Rsa;
    /**
     * Gets the crypto instance (works in both browser and Node.js)
     * @private
     */
    private _getCrypto;
    /**
     * Generates a random nonce of the specified length.
     * @param {Object} options - The options for nonce generation.
     * @param {number} [options.length=16] - The length of the nonce in characters.
     * @param {boolean} [options.hex=false] - Whether to convert the nonce to a hex string.
     * @returns {string} A random nonce, optionally hex-encoded.
     */
    /**
     * Generates a random nonce of the specified length in bytes.
     * @param {Object} options - The options for nonce generation.
     * @param {number} [options.length=12] - The length of the nonce in bytes (12 bytes recommended for AES-GCM).
     * @param {boolean} [options.hex=true] - Whether to return the nonce as a hex string (default) or as a base64 string.
     * @returns {string} A random nonce as hex string or base64 string.
     */
    generateNonce({ length, hex }?: {
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
     * @param {string} args.plainText - The plaintext password.
     * @param {string} args.salt - The salt value.
     * @param {number} [args.iterations=10000] - The number of iterations.
     * @param {number} [args.length=256] - The desired key length in bits.
     * @returns {Promise<string>} The derived key as a hexadecimal string.
     */
    pbkdf2(args: {
        plainText: string;
        salt: string;
        iterations?: number;
        length?: number;
    }): Promise<string>;
    /**
     * Derives a hash password using the PBKDF2 algorithm.
     * @param {Object} args - The key derivation arguments.
     * @param {string} args.plainText - The plaintext password.
     * @param {string} args.salt - The salt value.
     * @param {number} [args.iterations=10000] - The number of iterations.
     * @param {number} [args.length=256] - The desired hash length in bits.
     * @returns {Promise<string>} The derived hash as a hexadecimal string.
     */
    pbkdf2HashPassword(args: {
        plainText: string;
        salt: string;
        iterations?: number;
        length?: number;
    }): Promise<string>;
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
    argon2(args: {
        plainText: string;
        salt: string;
        length?: number;
        iterations?: number;
        memory?: number;
        threads?: number;
    }): Promise<string>;
    /**
     * Generates an RSA key pair.
     * @param {Object} [args] - The key generation arguments.
     * @param {number} [args.size=2048] - The key size in bits.
     * @returns {Promise<{ publicKey: { pem: string, base64: string }, privateKey: { pem: string, base64: string } }>} The generated RSA key pair.
     */
    generateRsaKeyPair(args?: {
        size?: number;
    }): Promise<{
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
     * @param {string} args.publicKey - The public key in PEM format.
     * @param {string} args.plainText - The plaintext to encrypt.
     * @param {number} [args.size=2048] - The key size in bits.
     * @returns {Promise<string>} The encrypted data as a base64 string.
     */
    encryptRsa(args: {
        publicKey: string;
        plainText: string;
        size?: number;
    }): Promise<string>;
    /**
     * Decrypts data using the RSA algorithm.
     * @param {Object} args - The decryption arguments.
     * @param {string} args.privateKey - The private key in PEM format.
     * @param {string} args.cipherText - The encrypted text in base64 format.
     * @param {number} [args.size=2048] - The key size in bits.
     * @returns {Promise<string>} The decrypted data as a string.
     */
    decryptRsa(args: {
        privateKey: string;
        cipherText: string;
        size?: number;
    }): Promise<string>;
    /**
     * Computes the SHA-256 hash of the given value.
     * @param {string} value - The value to hash.
     * @returns {Promise<string>} The SHA-256 hash as a hexadecimal string.
     */
    sha256(value: string): Promise<string>;
}
import Aes from './aes';
import Rsa from './rsa';
