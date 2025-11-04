package cryptus

import "testing"

func TestPBKDF2_HashAndCompare(t *testing.T) {
	c := New()

	password := "S3cure-P@ssw0rd!"
	salt := "email@example.com"

	// === 1) Using defaults (iterations: 10000, length: 16 bytes) ===
	hashHexDefault := c.Pbkdf2(password, salt)
	if len(hashHexDefault) != 32 { // 16 bytes => 32 hex chars
		t.Fatalf("PBKDF2 default hex length mismatch: got %d, want 32", len(hashHexDefault))
	}

	cfg := NewKdfConfig(
		WithIterations(100_000),
		WithLength(32), // 32 bytes => 64 hex chars
	)
	hashHexCustom := c.Pbkdf2(password, salt, cfg)
	if len(hashHexCustom) != 64 {
		t.Fatalf("PBKDF2 custom hex length mismatch: got %d, want 64", len(hashHexCustom))
	}

	hashHexCustom2 := c.Pbkdf2(password, salt, cfg)
	if !c.CompareHashHex(hashHexCustom, hashHexCustom2) {
		t.Fatal("PBKDF2: same inputs should produce identical hashes")
	}

	hashHexOtherSalt := c.Pbkdf2(password, "other@example.com", cfg)
	if c.CompareHashHex(hashHexCustom, hashHexOtherSalt) {
		t.Fatal("PBKDF2: different salt should produce different hashes")
	}

	cfgWeaker := NewKdfConfig(
		WithIterations(20_000),
		WithLength(32),
	)
	hashHexWeaker := c.Pbkdf2(password, salt, cfgWeaker)
	if c.CompareHashHex(hashHexCustom, hashHexWeaker) {
		t.Fatal("PBKDF2: different iterations should produce different hashes")
	}

	if !c.CompareHashHex(hashHexDefault, hashHexDefault) {
		t.Fatal("PBKDF2: constant-time compare failed for identical values")
	}
}
