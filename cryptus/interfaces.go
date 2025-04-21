package cryptus

import (
	"crypto/rsa"
)

type Cryptus interface {
	RandomSixDigits() string
	GenerateNonce(size int) ([]byte, error)
	GenerateNonceString(size int) string
	Pbkdf2(plainText, salt string, extra ...KdfConfig) string
	Argon2(plainText, salt string, extra ...KdfConfig) string
	EncryptAes(plainText, secret, nonce string) (string, error)
	DecryptAes(cipherText, secret, nonce string) (string, error)
	EncryptChacha20(plainText, secret, nonce string) (string, error)
	DecryptChacha20(cipherText, secret, nonce string) (string, error)
	GenerateRsaKeyPair(size int) (string, string, error)
	EncryptRsa(plainText, publicKey string) (string, error)
	DecryptRsa(cipherText, privateKey string) (string, error)
	ParseRSAPublicKeyFromPEM(publicKeyPEM string) (*rsa.PublicKey, error)
	ParseRSAPrivateKeyFromPEM(privateKeyPEM string) (*rsa.PrivateKey, error)
	Sha256(value string) string
}
