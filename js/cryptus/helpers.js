// minimal, framework-agnostic utilities

function getCrypto() {
  if (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.subtle) {
    return globalThis.crypto;
  }
  try {
    // Node.js >= 16
    const { webcrypto } = require("crypto");
    if (webcrypto && webcrypto.subtle) return webcrypto;
  } catch (_) {}
  throw new Error("WebCrypto is not available in this environment");
}

function arrayBufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return typeof btoa === "function" ? btoa(s) : Buffer.from(s, "binary").toString("base64");
}

function base64ToArrayBuffer(b64) {
  const bin = typeof atob === "function" ? atob(b64) : Buffer.from(b64, "base64").toString("binary");
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function b64urlFromBytes(bytes) {
  let s = arrayBufferToBase64(bytes);
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function bytesFromB64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 ? 4 - (s.length % 4) : 0;
  return base64ToArrayBuffer(s + "=".repeat(pad));
}

function arrayBufferToText(buf) {
  return new TextDecoder().decode(buf);
}

function textToArrayBuffer(str) {
  return new TextEncoder().encode(str);
}

function hexToArrayBuffer(hex) {
  if (!hex || hex.length % 2 !== 0) throw new Error("invalid hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function arrayBufferToHex(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
  return s;
}

function binaryToPem(binaryData, label) {
  const b64 = arrayBufferToBase64(binaryData);
  let pem = "-----BEGIN " + label + "-----\n";
  for (let i = 0; i < b64.length; i += 64) pem += b64.slice(i, i + 64) + "\n";
  pem += "-----END " + label + "-----\n";
  return pem;
}

function pemToBinary(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  return base64ToArrayBuffer(b64);
}

function strToHex(str) {
  const bytes = new TextEncoder().encode(str);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
  return s;
}

function randomBytes(n) {
  const c = getCrypto();
  const b = new Uint8Array(n);
  c.getRandomValues(b);
  return b;
}

module.exports = {
  getCrypto,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  b64urlFromBytes,
  bytesFromB64url,
  arrayBufferToText,
  textToArrayBuffer,
  hexToArrayBuffer,
  arrayBufferToHex,
  binaryToPem,
  pemToBinary,
  strToHex,
  randomBytes,
};
