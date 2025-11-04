package cryptus

import (
	"encoding/hex"
	"testing"
)

func TestRandomSixDigits(t *testing.T) {
	c := New()
	code := c.RandomSixDigits()
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}
}

func TestGenerateNonceHexAndB64(t *testing.T) {
	c := New()

	// HEX
	hexStr, err := c.GenerateNonceHex(12) // 12 bytes => 24 chars hex
	if err != nil {
		t.Fatalf("GenerateNonceHex error: %v", err)
	}
	if len(hexStr) != 24 {
		t.Fatalf("unexpected hex length: got %d, want 24", len(hexStr))
	}
	if _, err := hex.DecodeString(hexStr); err != nil {
		t.Fatalf("invalid hex: %v", err)
	}

	// Base64 URL-safe
	b64, err := c.GenerateNonceB64URL(16)
	if err != nil {
		t.Fatalf("GenerateNonceB64URL error: %v", err)
	}
	if b64 == "" {
		t.Fatal("b64url should not be empty")
	}
}
