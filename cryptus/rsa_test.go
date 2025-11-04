package cryptus

import "testing"

func TestRSA_OAEP_EncryptDecrypt(t *testing.T) {
	c := New()

	privPEM, pubPEM, err := c.GenerateRsaKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRsaKeyPair: %v", err)
	}

	plain := "hello, rsa-oaep!"

	// Base64 URL-safe
	ctB64, err := c.EncryptRsaOAEPB64(plain, pubPEM)
	if err != nil {
		t.Fatalf("EncryptRsaOAEPB64: %v", err)
	}

	pt, err := c.DecryptRsaOAEPB64(ctB64, privPEM)
	if err != nil {
		t.Fatalf("DecryptRsaOAEPB64: %v", err)
	}

	if pt != plain {
		t.Fatalf("decrypted text mismatch: got %q, want %q", pt, plain)
	}
}
