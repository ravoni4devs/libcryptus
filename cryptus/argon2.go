package cryptus

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

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

// Argon2 return string in OWASP format:
// $argon2id$v=19$m=<memory>,t=<iterations>,p=<threads>$<salt_b64>$<hash_b64>
func (c *cryptus) Argon2(password, salt string, extra ...KdfConfig) (string, error) {
	var cfg KdfConfig
	if len(extra) > 0 {
		cfg = extra[0]
	}

	saltBytes := []byte(salt)
	if isHexString(salt) && len(salt)%2 == 0 {
		if b, err := hex.DecodeString(salt); err == nil {
			saltBytes = b
		}
	}

	hashHex, err := c.Argon2Hex([]byte(password), saltBytes, cfg)
	if err != nil {
		return "", err
	}

	m := int(cfg.Memory())
	t := int(cfg.Iterations())
	p := int(cfg.Threads())

	saltB64 := base64.RawStdEncoding.EncodeToString(saltBytes)
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return "", err
	}
	hashB64 := base64.RawStdEncoding.EncodeToString(hashBytes)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", m, t, p, saltB64, hashB64), nil
}

// CompareArgon2 compare password and OWASP hash ($argon2id$...)
func (c *cryptus) CompareArgon2(password, encoded string) bool {
	if !strings.HasPrefix(encoded, "$argon2id$") {
		return false
	}

	parts := strings.Split(encoded, "$")
	if len(parts) < 6 {
		return false
	}

	// example:
	// [ "", "argon2id", "v=19", "m=65536,t=3,p=2", "<salt_b64>", "<hash_b64>" ]
	var memory, time, threads int
	fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)

	saltB64 := parts[4]
	hashB64 := parts[5]

	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil {
		return false
	}
	storedHash, err := base64.RawStdEncoding.DecodeString(hashB64)
	if err != nil {
		return false
	}

	newHashHex, err := c.Argon2Hex([]byte(password), salt, NewKdfConfig(
		WithIterations(time),
		WithMemory(memory),
		WithThreads(threads),
		WithLength(len(storedHash)),
	))
	if err != nil {
		return false
	}
	newHash, _ := hex.DecodeString(newHashHex)

	if len(storedHash) != len(newHash) {
		return false
	}
	diff := 0
	for i := range storedHash {
		diff |= int(storedHash[i] ^ newHash[i])
	}
	return diff == 0
}

// isHexString return true if it has only [0-9a-fA-F]
func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return false
		}
	}
	return true
}
