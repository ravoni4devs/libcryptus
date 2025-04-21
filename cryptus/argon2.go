package cryptus

import (
	"encoding/hex"

	"golang.org/x/crypto/argon2"
)

func (c *cryptus) Argon2(plainText, salt string, extra ...KdfConfig) string {
	var opts KdfConfig
	if len(extra) > 0 {
		opts = extra[0]
	}
	keySize := uint32(opts.Length() / 2) // KeySize is 32 bytes (256 bits).
	keyTime := uint32(opts.Iterations())
	keyMemory := uint32(opts.Memory()) // KeyMemory in KiB. here, 64 MiB.
	keyThreads := uint8(opts.Threads())
	hash := argon2.IDKey([]byte(plainText), []byte(salt), keyTime, keyMemory, keyThreads, keySize) // 32 bits
	return hex.EncodeToString(hash)
}
