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
- **ChaCha20** – Fast stream cipher encryption  

## Installation

### CLI (Optional)

```bash
go install github.com/ravoni4devs/libcryptus/cmd/cryptus@latest
```

### Lib (for Go projects)

```bash
go get github.com/ravoni4devs/libcryptus
```

## Usage

### CLI

```bash
# Encrypt string
cryptus encrypt -i "hello world"

# Encrypt file
cryptus encrypt --input wallet.txt

# Decrypt string
cryptus decrypt -i "ab12cd..." -nonce mynonce

# Decrypt file (auto load wallet.txt.nonce)
cryptus decrypt -i wallet.txt.enc
```

### Go Lib

Here’s a simple AES encryption example:

```go
package main

import (
	"encoding/hex"
	"fmt"
	"github.com/ravoni4devs/libcryptus"
)

func main() {
	crypto := cryptus.New()
	plainText := "strongpass"
	passwordHex := crypto.Pbkdf2("123456", "123456")
	nonceHex := hex.EncodeToString([]byte("12345678"))
	cipherText, err := crypto.EncryptAes(plainText, passwordHex, nonceHex)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(passwordHex) // 1498cccb3cab5e895d6912d78aef6ab2
	fmt.Println(nonceHex)    // 3132333435363738
	fmt.Println(cipherText)  // fd1ceaa8d7f03be768d410f07c017f3f7e62c8af6c9061cbaa0d

	cipherText = "fd1ceaa8d7f03be768d410f07c017f3f7e62c8af6c9061cbaa0d"
	plainText, err = crypto.DecryptAes(cipherText, passwordHex, nonceHex)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(plainText)   // strongpass
}
```

And a RSA encryption example:

```go
package main

import (
	"fmt"
	"github.com/ravoni4devs/libcryptus"
)

func main() {
	var plainText = "strongpass"
	crypto := cryptus.New()
	privateKey, publicKey, _ := crypto.GenerateRsaKeyPair(2048)
	encrypted, _ := crypto.EncryptRsa(plainText, publicKey)
	fmt.Println(encrypted)
	decrypted, _ := crypto.DecryptRsa(encrypted, privateKey)
	fmt.Println(decrypted)
}
```

## Documentation

More examples in `*_test.go` files.

## Contributing

1. Open an issue and describe your pain
2. Fork the repo
3. Create a new branch: git checkout -b feature/my-feature
4. Commit your changes
5. Push and open a PR

Please follow the project’s coding style and include tests when possible.

## License

MIT License. See the [LICENSE](LICENSE) file for details.
