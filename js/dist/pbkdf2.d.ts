declare namespace _default {
    function deriveKey({ plainText, salt, iterations, length }?: {
        plainText?: string;
        salt?: string;
        iterations?: number;
        length?: number;
    }): Promise<string>;
    function deriveBits({ plainText, salt, length, iterations }?: {
        plainText?: string;
        salt?: string;
        length?: number;
        iterations?: number;
    }): Promise<string>;
}
export default _default;
