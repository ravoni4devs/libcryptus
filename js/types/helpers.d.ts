/**
 * Type definitions for the helpers module in libcryptus.
 */

/**
 * Namespace for helper functions used in libcryptus.
 */
declare namespace helpers {
    /**
     * Converts an ArrayBuffer to a Base64 string.
     * @param buf - The ArrayBuffer to convert.
     * @returns The Base64 string.
     */
    function arrayBufferToBase64(buf: ArrayBuffer): string;

    /**
     * Converts a Base64 string to an ArrayBuffer.
     * @param b64str - The Base64 string to convert.
     * @returns The ArrayBuffer.
     */
    function base64ToArrayBuffer(b64str: string): ArrayBuffer;

    /**
     * Converts an ArrayBuffer to a text string.
     * @param buf - The ArrayBuffer to convert.
     * @returns The text string.
     */
    function arrayBufferToText(buf: ArrayBuffer): string;

    /**
     * Converts a text string to an ArrayBuffer.
     * @param str - The text string to convert.
     * @returns The ArrayBuffer.
     */
    function textToArrayBuffer(str: string): ArrayBuffer;

    /**
     * Converts binary data to a PEM-encoded string.
     * @param binaryData - The binary data to convert.
     * @param label - The PEM label (e.g., "RSA PRIVATE KEY").
     * @returns The PEM-encoded string.
     */
    function binaryToPem(binaryData: ArrayBuffer, label: string): string;

    /**
     * Converts a PEM-encoded string to binary data.
     * @param pem - The PEM-encoded string.
     * @returns The binary data as an ArrayBuffer.
     */
    function pemToBinary(pem?: string): ArrayBuffer;

    /**
     * Converts a hexadecimal string to an ArrayBuffer.
     * @param hexString - The hexadecimal string to convert.
     * @returns The ArrayBuffer.
     * @throws If the hex string is invalid.
     */
    function hexToArrayBuffer(hexString: string): Uint8Array;

    /**
     * Converts an ArrayBuffer to a hexadecimal string.
     * @param b - The ArrayBuffer to convert.
     * @returns The hexadecimal string.
     * @throws If the input is invalid.
     */
    function arrayBufferToHex(b: ArrayBuffer): string;

    /**
     * Converts a string to a Base64 string.
     * @param str - The string to convert.
     * @returns The Base64 string.
     */
    function strToBase64(str: string): string;

    /**
     * Converts a Base64 string to a regular string.
     * @param b64 - The Base64 string to convert.
     * @returns The decoded string.
     */
    function base64ToStr(b64: string): string;

    /**
     * Converts a string to UTF-16 bytes.
     * @param str - The string to convert.
     * @returns An array of bytes.
     */
    function strToUtf16Bytes(str: string): number[];

    /**
     * Converts a string to a hexadecimal string.
     * @param str - The string to convert.
     * @returns The hexadecimal string.
     */
    function strToHex(str: string): string;

    /**
     * Generates a random initialization vector (IV) as a hexadecimal string.
     * @param size - The size of the IV in bytes.
     * @returns The IV as a hexadecimal string.
     */
    function randomIv(size: number): string;
}

// Map the namespace to the default export
export = helpers;