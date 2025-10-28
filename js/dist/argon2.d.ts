declare namespace _default {
    function deriveKey({ plainText, salt, length, iterations, memory, threads, }?: {
        plainText?: string;
        salt?: string;
        length?: number;
        iterations?: number;
        memory?: number;
        threads?: number;
    }): Promise<string>;
}
export default _default;
