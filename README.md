# Cryptus

**Cryptus** is a lightweight cryptography library and CLI tool that makes encryption,
decryption, and key derivation simple and consistent.

---

## 🚀 Features

- **Symmetric encryption:** AES-GCM and ChaCha20-Poly1305  
- **Asymmetric encryption:** RSA key pair and message encryption  
- **Key derivation:** Argon2id and PBKDF2  
- **Hashing:** SHA-256 helper  
- **Nonce and random generation** utilities  
- **CLI or library use** — your choice

---

## 🔐 Supported Algorithms

| Category | Algorithms |
|-----------|-------------|
| **Encryption** | AES-GCM (256-bit), ChaCha20-Poly1305 |
| **Key Derivation** | Argon2id (default), PBKDF2 |
| **Hashing** | SHA-256 |
| **Asymmetric** | RSA-2048/4096 |

---

## 📦 Installation

### CLI (optional)

```bash
go install github.com/ravoni4devs/libcryptus/cmd/cryptus@latest
```

### Library (for Go projects)

```bash
go get github.com/ravoni4devs/libcryptus
```

---

## 🧰 CLI Usage

### Encrypt

```bash
# Encrypt a string using AES + Argon2id (defaults)
cryptus encrypt -text "hello world"

# Encrypt file (auto-saves .nonce)
cryptus encrypt -file wallet.txt

# Use ChaCha20 instead of AES
cryptus encrypt -text "hello" -algo chacha20

# Use PBKDF2 instead of Argon2id
cryptus encrypt -file wallet.txt -kdf pbkdf2
```

### Decrypt

```bash
# Decrypt a string
cryptus decrypt -text "ab12cd..." -nonce mynonce

# Decrypt a file (auto-loads .nonce)
cryptus decrypt -file wallet.txt.enc
```

**Options:**

| Flag | Description |
|------|--------------|
| `-i, -input, -file, -text` | Input string or file path |
| `-a, -algo` | Cipher algorithm (`aes` or `chacha20`) |
| `-k, -kdf` | Key derivation (`argon2id` or `pbkdf2`) |
| `-nonce, -salt` | Nonce (hex) — auto-generated if omitted |
| `-o, -out, -output` | Output file path |
| `-chunk` | Chunk size for file encryption (default: 1MB) |

---

## 💻 Go Library Example

### AES Encryption Example

```go
package main

import (
    "encoding/hex"
    "fmt"
    "github.com/ravoni4devs/libcryptus/cryptus"
)

func main() {
    c := cryptus.New()
    password := "mypassword"
    salt := "mysalt"

    keyHex := c.Pbkdf2(password, salt)
    nonceHex := hex.EncodeToString([]byte("123456789012")) // 12 bytes nonce
    cipherText, _ := c.EncryptAESGCMHex("hello world", keyHex, nonceHex)

    fmt.Println("Cipher:", cipherText)

    plainText, _ := c.DecryptAESGCMHex(cipherText, keyHex, nonceHex)
    fmt.Println("Plain:", plainText)
}
```

### RSA Example

```go
package main

import (
    "fmt"
    "github.com/ravoni4devs/libcryptus/cryptus"
)

func main() {
    c := cryptus.New()
    priv, pub, _ := c.GenerateRsaKeyPair(2048)

    text := "super secret"
    enc, _ := c.EncryptRsaOAEPB64(text, pub)
    dec, _ := c.DecryptRsaOAEPB64(enc, priv)

    fmt.Println("Encrypted:", enc)
    fmt.Println("Decrypted:", dec)
}
```

---

## 🧪 Benchmarks

On Apple M4 (10 cores):

| Algorithm | Speed | Notes |
|------------|--------|-------|
| AES-GCM | ~8.3 GB/s | Uses hardware AES acceleration |
| ChaCha20 | ~1.4 GB/s | Slower but consistent across platforms |

Run your own benchmarks:

```bash
go test -bench=Encrypt1GB -benchmem -benchtime=1x
```

---

## 📚 More Examples

Check the `*_test.go` files for working examples of AES, ChaCha20, Argon2id, PBKDF2, and RSA.

---

## 🤝 Contributing

1. Open an issue describing your use case or problem  
2. Fork the repo and create a branch  
3. Add your feature or fix (with tests)  
4. Open a PR 🚀  

---

## ⚖️ License

MIT License — see [LICENSE](LICENSE)
