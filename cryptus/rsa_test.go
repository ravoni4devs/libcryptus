package cryptus

import "testing"

func TestEncryptAndDecryptRsa(t *testing.T) {
	var plainText = "strongpass"
	crypto := New()
	privateKey, publicKey, _ := crypto.GenerateRsaKeyPair(2048)
	encrypted, _ := crypto.EncryptRsa(plainText, publicKey)
	decrypted, _ := crypto.DecryptRsa(encrypted, privateKey)
	assertEqual(t, plainText, decrypted)
}
