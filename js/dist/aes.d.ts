export default Aes;
declare class Aes {
    encrypt({ plainText, passwordHex, nonceHex }: {
        plainText: any;
        passwordHex: any;
        nonceHex: any;
    }): Promise<string>;
    decrypt({ cipherText, passwordHex, nonceHex }: {
        cipherText: any;
        passwordHex: any;
        nonceHex: any;
    }): Promise<string>;
}
