package cryptus

import "testing"

func TestAESGCM_EncryptDecrypt(t *testing.T) {
	c := New()

	// Example:
	// - AES keys 32 bytes (256 bits) in HEX
	// - Nonce GCM 12 bytes in HEX
	keyHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	nonceHex := "00112233445566778899aabb"

	plain := "hello, aes-gcm!"

	ctHex, err := c.EncryptAESGCMHex(plain, keyHex, nonceHex)
	if err != nil {
		t.Fatalf("EncryptAESGCMHex error: %v", err)
	}

	pt, err := c.DecryptAESGCMHex(ctHex, keyHex, nonceHex)
	if err != nil {
		t.Fatalf("DecryptAESGCMHex error: %v", err)
	}

	if pt != plain {
		t.Fatalf("decrypted text mismatch: got %q, want %q", pt, plain)
	}
}
