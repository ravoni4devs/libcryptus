package cryptus

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
)

func (c *cryptus) EncryptAes(plainText, passwordHex, nonceHex string) (string, error) {
	salt, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", err
	}
	cipher, err := c.getAesCipher(passwordHex, len(salt))
	if err != nil {
		return "", err
	}
	ciphertextBytes := cipher.Seal(nil, salt, []byte(plainText), nil)
	return hex.EncodeToString(ciphertextBytes), nil
}

func (c *cryptus) DecryptAes(cipherText, passwordHex, nonceHex string) (string, error) {
	salt, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", err
	}
	cipher, err := c.getAesCipher(passwordHex, len(salt))
	if err != nil {
		return "", err
	}
	raw, err := hex.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	plainText, err := cipher.Open(nil, salt, raw, nil)
	if err != nil {
		return "", err
	}
	return string(plainText), nil
}

func (c *cryptus) getAesCipher(passwordHex string, aesGcm256NonceSize int) (cipher.AEAD, error) {
	key, err := hex.DecodeString(passwordHex)
	if err != nil {
		return nil, fmt.Errorf("secretKey is not a hex string: %s.", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithNonceSize(block, aesGcm256NonceSize) // default nonce size is 12
}
