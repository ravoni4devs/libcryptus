# Cryptus

**Cryptus** is a lightweight, cross‑language cryptography library and CLI tool that provides a unified interface for encryption, decryption, key derivation, and hashing — both in Go and JavaScript.

---

## 🚀 Features

- **Symmetric Encryption:** AES‑GCM and ChaCha20‑Poly1305  
- **Asymmetric Encryption:** RSA‑OAEP key generation and encryption  
- **Key Derivation:** Argon2id and PBKDF2 (HMAC‑SHA256)  
- **Hashing:** SHA‑256 with constant‑time comparison  
- **Nonces & Random:** Built‑in utilities for secure random generation  
- **CLI + Library:** Use directly in Go, Node.js, or browser environments

---

## 🔐 Supported Algorithms

| Category | Algorithms |
|-----------|-------------|
| **Encryption** | AES‑GCM (256‑bit), ChaCha20‑Poly1305 |
| **Key Derivation** | Argon2id (default), PBKDF2 (HMAC‑SHA256) |
| **Hashing** | SHA‑256 |
| **Asymmetric** | RSA‑OAEP (2048/4096 bits) |

---

## 📦 Installation

### For JavaScript (Node or Browser)

```bash
npm i @ravoni4devs/libcryptus
```

To add **Argon2** support in browsers:

```bash
npm i argon2-browser
```

Then include it in your HTML before using Cryptus:

```html
<script src="node_modules/argon2-browser/dist/argon2-bundled.js"></script>
```

---

## 🧠 Quick Usage (ESM)

### AES‑GCM Example

```js
import Cryptus from '@ravoni4devs/libcryptus';

const c = new Cryptus();

// Derive a key using PBKDF2 (32 bytes → AES‑256)
const keyHex = await c.pbkdf2('my‑password', 'mysalt', { iterations: 100000, length: 32 });

// Generate a random 12‑byte nonce
const nonceHex = await c.generateNonceHex(12);

// Encrypt / Decrypt text using AES‑GCM
const cipherHex = await c.encryptAESGCMHex('hello world', keyHex, nonceHex);
const plainText = await c.decryptAESGCMHex(cipherHex, keyHex, nonceHex);

console.log({ keyHex, nonceHex, cipherHex, plainText });
```

### RSA‑OAEP Example

```js
import Cryptus from '@ravoni4devs/libcryptus';

const c = new Cryptus();
const { publicKey, privateKey } = await c.generateRsaKeyPair(2048);

const encrypted = await c.encryptRsaOAEPB64('secret message', publicKey);
const decrypted = await c.decryptRsaOAEPB64(encrypted, privateKey);

console.log({ encrypted, decrypted });
```

---

## 🧰 CommonJS / Browser Example

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <script src="node_modules/@ravoni4devs/libcryptus/dist/libcryptus-cjs.js"></script>
</head>
<body>
  <div>Generated Nonce: <span id="nonce"></span></div>
  <div>PBKDF2: plainText=<b>strongpass</b> => hash=<span id="hash"></span></div>
  <script>
    var cryptus = new Cryptus();
    cryptus.generateNonceHex(12).then(function (nonce) {
      console.log('nonce:', nonce)
      document.querySelector('#nonce').innerHTML = nonce;
      cryptus.pbkdf2('strongpass', nonce).then(function (hash) {
        document.querySelector('#hash').innerHTML = hash;
      })
    })
  </script>
</body>
</html>
```

