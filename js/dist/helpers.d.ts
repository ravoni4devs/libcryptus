declare namespace _default {
    export { arrayBufferToBase64 };
    export { base64ToArrayBuffer };
    export { arrayBufferToText };
    export { textToArrayBuffer };
    export { binaryToPem };
    export { pemToBinary };
    export { hexToArrayBuffer };
    export { arrayBufferToHex };
    export { strToBase64 };
    export { base64ToStr };
    export { strToUtf16Bytes };
    export { strToHex };
    export { randomIv };
}
export default _default;
declare function arrayBufferToBase64(buf: any): string;
declare function base64ToArrayBuffer(b64str: any): ArrayBuffer;
declare function arrayBufferToText(buf: any): string;
declare function textToArrayBuffer(str: any): Uint8Array<ArrayBuffer>;
declare function binaryToPem(binaryData: any, label: any): string;
declare function pemToBinary(pem?: string): ArrayBuffer;
declare function hexToArrayBuffer(hexString: any): Uint8Array<ArrayBuffer>;
declare function arrayBufferToHex(b: any): string;
declare function strToBase64(str: any): string;
declare function base64ToStr(b64: any): string;
declare function strToUtf16Bytes(str: any): number[];
declare function strToHex(str: any): string;
declare function randomIv(size: any): string;
