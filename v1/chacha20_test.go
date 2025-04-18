package cryptus

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestEncryptChacha20(t *testing.T) {
	crypto := New()
	password := crypto.Argon2("strongpass", "123456", NewKdfConfig(
		WithLength(32),
	))
	plainText := "my secret content"
	nonceHex := hex.EncodeToString([]byte("12345678910-"))
	cipherText, err := crypto.EncryptChacha20(plainText, password, nonceHex)
	if err != nil {
		fmt.Println(err)
	}
	assertEqual(t, cipherText, "a28a3960a612ed83d207ac59c67a2c51948992334263533d32997b895cb120be88")
}

func TestDecryptChacha20(t *testing.T) {
	cipherText := "a28a3960a612ed83d207ac59c67a2c51948992334263533d32997b895cb120be88"
	password := "cea63ce08c5fcf2a33a0311f1e68c048" // argon2 strongpass 123456
	nonceHex := hex.EncodeToString([]byte("12345678910-"))
	crypto := New()
	plainText, err := crypto.DecryptChacha20(cipherText, password, nonceHex)
	if err != nil {
		fmt.Println(err)
	}
	assertEqual(t, plainText, "my secret content")
}
