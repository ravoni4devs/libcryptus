/**
 * Type definitions for argon2-browser.
 * Inferred from usage in libcryptus.
 */
declare global {
    interface Window {
        argon2: Argon2Browser;
    }
}

interface Argon2Browser {
    /**
     * Hashes the input using Argon2.
     * @param options - The hashing options.
     * @returns A promise resolving to the hash result.
     */
    hash(options: {
        pass: string;
        salt: Uint8Array;
        type: number;
        hashLen: number;
        time: number;
        mem: number;
        parallelism: number;
        version: number;
    }): Promise<{ hashHex: string }>;

    /**
     * Argon2 type constants.
     */
    ArgonType: {
        Argon2id: number;
    };
}

export {};
