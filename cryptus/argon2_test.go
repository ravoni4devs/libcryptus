package cryptus

import (
	"encoding/hex"
	"testing"
)

func TestArgon2_HashAndCompare(t *testing.T) {
	c := New()

	password := []byte("S3cure-P@ssw0rd!")
	salt := []byte("fixed-salt-for-test") // fixed for determinism

	cfg := NewKdfConfig(
		WithIterations(3),
		WithThreads(1),
		WithMemory(1024*64), // 64 MiB
		WithLength(32),      // 32 bytes => 64 chars hex
	)

	hashHex1, err := c.Argon2Hex(password, salt, cfg)
	if err != nil {
		t.Fatalf("Argon2Hex error: %v", err)
	}
	if len(hashHex1) != 64 { // 32 bytes -> 64 hex
		t.Fatalf("unexpected hex length: got %d", len(hashHex1))
	}

	hashHex2, err := c.Argon2Hex(password, salt, cfg)
	if err != nil {
		t.Fatalf("Argon2Hex error: %v", err)
	}

	// Comparing in constant time (hex)
	if !c.CompareHashHex(hashHex1, hashHex2) {
		t.Fatal("hashes should be equal")
	}

	hashHex3, err := c.Argon2Hex(password, []byte("other-salt"), cfg)
	if err != nil {
		t.Fatalf("Argon2Hex error: %v", err)
	}
	if c.CompareHashHex(hashHex1, hashHex3) {
		t.Fatal("hashes should differ when salt differs")
	}

	h1, _ := hex.DecodeString(hashHex1)
	h2, _ := hex.DecodeString(hashHex2)
	if len(h1) != len(h2) {
		t.Fatal("decoded lengths mismatch")
	}
}
