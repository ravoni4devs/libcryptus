declare namespace _default {
    function deriveKey({ plainText, salt, length, iterations, memory, threads }: {
        plainText: any;
        salt: any;
        length?: number;
        iterations?: number;
        memory?: number;
        threads?: number;
    }): Promise<string>;
}
export default _default;
