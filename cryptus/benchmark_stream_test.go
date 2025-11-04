package cryptus

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// File size 1 GB with 1 MB chunk
const (
	totalSize  = int64(1 << 30) // 1 GiB
	chunkSize  = 1 << 20        // 1 MiB
	nonceBytes = 12             // Nonce AEAD (GCM/ChaCha) = 12 bytes
)

func BenchmarkAESGCM_Encrypt1GB(b *testing.B) {
	aead := mustAESGCM(b, 32) // AES-256
	baseNonce := mustRand(b, nonceBytes)

	benchEncrypt1GB(b, aead, baseNonce)
}

func BenchmarkChaCha20_Encrypt1GB(b *testing.B) {
	aead := mustChaCha20(b)
	baseNonce := mustRand(b, nonceBytes)

	benchEncrypt1GB(b, aead, baseNonce)
}

func benchEncrypt1GB(b *testing.B, aead cipher.AEAD, baseNonce []byte) {
	b.Helper()
	if aead.NonceSize() != nonceBytes {
		b.Fatalf("unexpected AEAD nonce size: got %d, want %d", aead.NonceSize(), nonceBytes)
	}
	buf := make([]byte, chunkSize)
	dst := make([]byte, 0, chunkSize+aead.Overhead())
	b.ReportAllocs()
	b.SetBytes(totalSize)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var idx uint64
		remaining := totalSize

		for remaining > 0 {
			n := chunkSize
			if int64(n) > remaining {
				n = int(remaining)
			}
			nonce := deriveChunkNonceBench(baseNonce, idx, aead.NonceSize())
			// Reuse same slice to avoid alloc
			dst = dst[:0]
			dst = aead.Seal(dst, nonce, buf[:n], nil)
			remaining -= int64(n)
			idx++
		}
	}
}

func mustAESGCM(b *testing.B, keyLen int) cipher.AEAD {
	b.Helper()
	key := mustRand(b, keyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		b.Fatalf("aes.NewCipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		b.Fatalf("cipher.NewGCM: %v", err)
	}
	return aead
}

func mustChaCha20(b *testing.B) cipher.AEAD {
	b.Helper()
	key := mustRand(b, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		b.Fatalf("chacha20poly1305.New: %v", err)
	}
	return aead
}

func mustRand(b *testing.B, n int) []byte {
	b.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		b.Fatalf("rand.Read: %v", err)
	}
	return buf
}

func deriveChunkNonceBench(base []byte, index uint64, size int) []byte {
	var idx [8]byte
	idx[0] = byte(index >> 56)
	idx[1] = byte(index >> 48)
	idx[2] = byte(index >> 40)
	idx[3] = byte(index >> 32)
	idx[4] = byte(index >> 24)
	idx[5] = byte(index >> 16)
	idx[6] = byte(index >> 8)
	idx[7] = byte(index)

	h := sha256.New()
	h.Write(base)
	h.Write(idx[:])
	sum := h.Sum(nil)
	return sum[:size]
}
