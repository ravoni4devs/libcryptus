package cryptus

import (
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/pbkdf2"
)

func (c *cryptus) Pbkdf2(plainText, salt string, extra ...KdfConfig) string {
	iter := 10000
	length := 16 // bytes

	if len(extra) > 0 {
		opts := extra[0]

		if v := int(opts.Iterations()); v > 0 {
			iter = v
		}
		if v := int(opts.Length()); v > 0 {
			length = v
		}
	}

	key := pbkdf2.Key([]byte(plainText), []byte(salt), iter, length, sha256.New)
	return hex.EncodeToString(key)
}
