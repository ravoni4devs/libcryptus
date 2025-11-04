package cryptus

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
)

const aesGcmNonceSize = 12 // default GCM

func (c *cryptus) EncryptAESGCMHex(plainText, keyHex, nonceHex string) (string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("invalid key hex: %w", err)
	}
	if l := len(key); l != 16 && l != 24 && l != 32 {
		return "", errors.New("AES key must be 16, 24, or 32 bytes")
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", fmt.Errorf("invalid nonce hex: %w", err)
	}
	if len(nonce) != aesGcmNonceSize {
		return "", fmt.Errorf("AES-GCM nonce must be %d bytes", aesGcmNonceSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, aesGcmNonceSize)
	if err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, []byte(plainText), nil)
	return hex.EncodeToString(ct), nil
}

func (c *cryptus) DecryptAESGCMHex(cipherHex, keyHex, nonceHex string) (string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("invalid key hex: %w", err)
	}
	if l := len(key); l != 16 && l != 24 && l != 32 {
		return "", errors.New("AES key must be 16, 24, or 32 bytes")
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", fmt.Errorf("invalid nonce hex: %w", err)
	}
	if len(nonce) != aesGcmNonceSize {
		return "", fmt.Errorf("AES-GCM nonce must be %d bytes", aesGcmNonceSize)
	}
	raw, err := hex.DecodeString(cipherHex)
	if err != nil {
		return "", fmt.Errorf("invalid cipher hex: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, aesGcmNonceSize)
	if err != nil {
		return "", err
	}
	pt, err := gcm.Open(nil, nonce, raw, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
