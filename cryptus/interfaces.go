package cryptus

type Cryptus interface {
	RandomSixDigits() string

	GenerateNonceBytes(n int) ([]byte, error)
	GenerateNonceHex(n int) (string, error)
	GenerateNonceB64URL(n int) (string, error)

	Sha256Hex(s string) string

	Pbkdf2(plainText, salt string, extra ...KdfConfig) string

	Argon2Hex(plain, salt []byte, extra ...KdfConfig) (string, error)
	CompareHashHex(aHex, bHex string) bool
	Argon2(plain, salt string, extra ...KdfConfig) (string, error)
	CompareArgon2(password, encoded string) bool

	EncryptAESGCMHex(plainText, keyHex, nonceHex string) (string, error)
	DecryptAESGCMHex(cipherHex, keyHex, nonceHex string) (string, error)

	EncryptChaCha20Hex(plainText, keyHex, nonceHex string) (string, error)
	DecryptChaCha20Hex(cipherHex, keyHex, nonceHex string) (string, error)

	GenerateRsaKeyPair(size int) (privPEM, pubPEM string, err error)
	EncryptRsaOAEPB64(plainText, publicKeyPEM string) (string, error)
	DecryptRsaOAEPB64(cipherB64, privateKeyPEM string) (string, error)
}
