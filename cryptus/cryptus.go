package cryptus

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"time"
)

type cryptus struct{}

func New() Cryptus {
	return &cryptus{}
}

func (c *cryptus) RandomSixDigits() string {
	rand.New(rand.NewSource(time.Now().UnixNano()))
	min := 100000
	max := 999999
	code := min + rand.Intn(max-min)
	return strconv.Itoa(code)
}

func (c *cryptus) GenerateNonceHex(size int) string {
	nonceBytes := make([]byte, size)
	_, err := crand.Read(nonceBytes)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(nonceBytes)
}

func (c *cryptus) GenerateNonce(size int) ([]byte, error) {
	nonceBytes := make([]byte, size)
	_, err := crand.Read(nonceBytes)
	if err != nil {
		return nonceBytes, errors.New("could not generate nonce")
	}

	res := base64.URLEncoding.EncodeToString(nonceBytes)
	return []byte(res), nil
}

func (c *cryptus) GenerateNonceString(size int) string {
	b, err := c.GenerateNonce(size)
	if err != nil {
		return ""
	}
	return string(b)
}

func (c *cryptus) Sha256(value string) string {
	h := sha256.New()
	h.Write([]byte(value))
	return fmt.Sprintf("%x", h.Sum(nil))
}
