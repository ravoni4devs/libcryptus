package cryptus

import (
	"crypto/sha256"
	"encoding/hex"
)

func (c *cryptus) Sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

