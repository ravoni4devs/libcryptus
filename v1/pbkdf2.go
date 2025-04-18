package cryptus

import (
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/pbkdf2"
)

func (c *cryptus) Pbkdf2(plainText, salt string, extra ...KdfConfig) string {
	iter := 10000
	length := 16
	if len(extra) > 0 {
		opts := extra[0]
		iter = int(opts.Iterations())
		length = int(opts.Length())
	}
	hash := pbkdf2.Key([]byte(plainText), []byte(salt), iter, length, sha256.New)
	return hex.EncodeToString(hash)
}
