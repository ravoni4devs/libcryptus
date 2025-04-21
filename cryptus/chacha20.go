package cryptus

import (
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

func (c *cryptus) EncryptChacha20(plainText, password, nonceHex string) (string, error) {
	salt, err := hex.DecodeString(nonceHex)
	if err != nil || len(salt) != chacha20poly1305.NonceSize {
		return "", fmt.Errorf("expected nonce length %d but got length %d", chacha20poly1305.NonceSize, len(salt))
	}
	cipher, err := c.getChacha20Cipher(password)
	if err != nil {
		return "", err
	}
	ciphertextBytes := cipher.Seal(nil, salt, []byte(plainText), nil)
	return hex.EncodeToString(ciphertextBytes), nil
}

func (c *cryptus) DecryptChacha20(cipherText, password, nonceHex string) (string, error) {
	salt, err := hex.DecodeString(nonceHex)
	if err != nil || len(salt) != chacha20poly1305.NonceSize {
		return "", fmt.Errorf("expected nonce length %d but got length %d", chacha20poly1305.NonceSize, len(salt))
	}
	cipher, err := c.getChacha20Cipher(password)
	if err != nil {
		return "", err
	}
	cipherBytes, err := hex.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	plainText, err := cipher.Open(nil, salt, cipherBytes, nil)
	if err != nil {
		return "", err
	}
	return string(plainText), nil
}

func (c *cryptus) getChacha20Cipher(password string) (cipher.AEAD, error) {
	key := []byte(password)
	cipher, err := chacha20poly1305.New(key)
	if err != nil && strings.ContainsAny(err.Error(), "bad key") {
		return nil, fmt.Errorf("expected key size length %d but got %d", chacha20poly1305.KeySize, len(key))
	}
	return cipher, nil
}
