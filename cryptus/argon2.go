package cryptus

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/argon2"
)

func (c *cryptus) Argon2Hex(plain, salt []byte, extra ...KdfConfig) (string, error) {
	if len(salt) == 0 {
		return "", errors.New("salt is required")
	}
	var cfg KdfConfig
	if len(extra) > 0 {
		cfg = extra[0]
	}
	keyLen := cfg.Length()
	if keyLen < 16 || keyLen > 64 {
		return "", errors.New("invalid argon2 key length (16..64)")
	}
	hash := argon2.IDKey(plain, salt, uint32(cfg.Iterations()), uint32(cfg.Memory()), uint8(cfg.Threads()), uint32(keyLen))
	return hex.EncodeToString(hash), nil
}

func (c *cryptus) CompareHashHex(aHex, bHex string) bool {
	a, errA := hex.DecodeString(aHex)
	b, errB := hex.DecodeString(bHex)
	if errA != nil || errB != nil {
		if len(a) == 0 {
			a = make([]byte, len(b))
		}
		return subtle.ConstantTimeCompare(a, b) == 1 && false
	}
	if len(a) != len(b) {
		dummy := make([]byte, len(a))
		return subtle.ConstantTimeCompare(a, dummy) == 1 && false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
