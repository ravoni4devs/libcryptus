export default class Rsa {
    generateKeyPair(args?: {}): Promise<{
        publicKey: {
            pem: string;
            base64: string;
        };
        privateKey: {
            pem: string;
            base64: string;
        };
    }>;
    encrypt(args: any): Promise<string>;
    decrypt(args: any): Promise<string>;
}
