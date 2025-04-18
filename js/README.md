# Cryptus

**Cryptus** is a multi-language cryptography and hashing library designed to provide a simple
and consistent interface for developers working with cryptographic operations across
different programming languages.

## Features

- **Encryption & Decryption**: Simplify data protection with straightforward functions.
- **Key Derivation & Generation**: Generate strong keys with Argon2 and PBKDF2.
- **Hashing & Secure Storage**: Hash passwords and securely store sensitive data.
- **Modular Design**: Use only what you need to keep your project lean.

## Supported Algorithms

Cryptus currently supports the following cryptographic algorithms:

- **RSA** – Asymmetric encryption and key generation  
- **Argon2** – Memory-hard password hashing (Argon2id)  
- **PBKDF2** – Password-based key derivation  
- **AES** – Symmetric encryption (AES-256)  
- **Sha256** – Cryptographic hash function producing 256-bit fixed-size output

## Installation

To install Cryptus, run:

```bash
npm i @ravoni4devs/libcryptus
```

To add Argon2 support:

```sh
npm i argon2-browser

# Then add this script to your HTML
<script src="node_modules/argon2-browser/dist/argon2-bundled.js"></script>
```

## Usage

### ES6 module

Here’s a simple AES encryption example:

```js
import Cryptus from '@ravoni4devs/libcryptus'

const plainText = 'strongpass';
const cryptus = new Cryptus();
const passwordHex = await cryptus.pbkdf2({
  plainText: plainText,
  salt: '123456',
  length: 128  // 128 = 32 bits = max length supported to aes-gcm
})
console.log(passwordHex)  // 1498cccb3cab5e895d6912d78aef6ab2

const nonceHex = helpers.strToHex('12345678');
console.log(nonceHex)    // 3132333435363738

const cipherText = await cryptus.encryptAes({plainText, nonceHex, passwordHex});
console.log(cipherText)  // fd1ceaa8d7f03be768d410f07c017f3f7e62c8af6c9061cbaa0d

const decryptedText = await cryptus.decryptAes({cipherText, nonceHex, passwordHex});
console.log(decryptedText)
```

### Common JS old fashion style

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <script src="node_modules/@ravoni4devs/libcryptus/dist/libcryptus-cjs.js"></script>
</head>
<body>
  <div>Generated Nonce: <span id="nonce"></span></div>
  <script>
    var cryptus = new Cryptus();
    var nonce = cryptus.generateNonce(16);
    document.querySelector('#nonce').innerHTML = nonce;
  </script>
</body>
```

## Documentation

More examples in `*.test.js` files.

## Contributing

1. Open an issue and describe your pain
2. Fork the repo
3. Create a new branch: git checkout -b feature/my-feature
4. Commit your changes
5. Push and open a PR

Please follow the project’s coding style and include tests when possible.

## License

MIT License. See the [LICENSE](LICENSE) file for details.
