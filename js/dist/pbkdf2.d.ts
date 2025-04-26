declare namespace _default {
    function deriveKey({ plainText, salt, length }: {
        plainText: any;
        salt: any;
        length?: number;
    }): Promise<string>;
}
export default _default;
