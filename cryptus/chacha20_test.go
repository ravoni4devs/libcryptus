package cryptus

import "testing"

func TestChaCha20_EncryptDecrypt(t *testing.T) {
	c := New()

	// ChaCha20-Poly1305 key 32 bytes in HEX
	keyHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	// Nonce 12 bytes in HEX
	nonceHex := "0a0b0c0d0e0f101112131415"

	plain := "hello, chacha20-poly1305!"

	ctHex, err := c.EncryptChaCha20Hex(plain, keyHex, nonceHex)
	if err != nil {
		t.Fatalf("EncryptChaCha20Hex error: %v", err)
	}

	pt, err := c.DecryptChaCha20Hex(ctHex, keyHex, nonceHex)
	if err != nil {
		t.Fatalf("DecryptChaCha20Hex error: %v", err)
	}

	if pt != plain {
		t.Fatalf("decrypted text mismatch: got %q, want %q", pt, plain)
	}
}
