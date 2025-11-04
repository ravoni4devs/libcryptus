package cryptus

import (
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

func NewChacha20Poly1305Key(key []byte) (cipher.AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("ChaCha20-Poly1305 key must be %d bytes; got %d", chacha20poly1305.KeySize, len(key))
	}
	return chacha20poly1305.New(key)
}

func (c *cryptus) EncryptChaCha20Hex(plainText, keyHex, nonceHex string) (string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("invalid key hex: %w", err)
	}
	if len(key) != chacha20poly1305.KeySize {
		return "", fmt.Errorf("ChaCha20-Poly1305 key must be %d bytes", chacha20poly1305.KeySize)
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", fmt.Errorf("invalid nonce hex: %w", err)
	}
	if len(nonce) != chacha20poly1305.NonceSize {
		return "", fmt.Errorf("nonce must be %d bytes", chacha20poly1305.NonceSize)
	}
	aead, err := c.getChacha20Cipher(key)
	if err != nil {
		return "", err
	}
	ct := aead.Seal(nil, nonce, []byte(plainText), nil)
	return hex.EncodeToString(ct), nil
}

func (c *cryptus) DecryptChaCha20Hex(cipherHex, keyHex, nonceHex string) (string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("invalid key hex: %w", err)
	}
	if len(key) != chacha20poly1305.KeySize {
		return "", fmt.Errorf("ChaCha20-Poly1305 key must be %d bytes", chacha20poly1305.KeySize)
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", fmt.Errorf("invalid nonce hex: %w", err)
	}
	if len(nonce) != chacha20poly1305.NonceSize {
		return "", fmt.Errorf("nonce must be %d bytes", chacha20poly1305.NonceSize)
	}
	aead, err := c.getChacha20Cipher(key)
	if err != nil {
		return "", err
	}
	raw, err := hex.DecodeString(cipherHex)
	if err != nil {
		return "", fmt.Errorf("invalid cipher hex: %w", err)
	}
	pt, err := aead.Open(nil, nonce, raw, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func (c *cryptus) getChacha20Cipher(key []byte) (cipher.AEAD, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, errors.New("failed to init chacha20-poly1305")
	}
	return aead, nil
}
