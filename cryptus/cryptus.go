package cryptus

import (
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

type cryptus struct{}

func New() Cryptus { return &cryptus{} }

func (c *cryptus) RandomSixDigits() string {
	var b [4]byte
	if _, err := io.ReadFull(crand.Reader, b[:]); err != nil {
		// fallback
		return "000000"
	}
	// 0..999999
	n := (uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])) % 1000000
	return fmt.Sprintf("%06d", n)
}

func (c *cryptus) GenerateNonceBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("nonce size must be > 0")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(crand.Reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (c *cryptus) GenerateNonceHex(n int) (string, error) {
	b, err := c.GenerateNonceBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (c *cryptus) GenerateNonceB64URL(n int) (string, error) {
	b, err := c.GenerateNonceBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
