package cryptus

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestEncryptAes(t *testing.T) {
	crypto := New()
	plainText := "strongpass"
	passwordHex := crypto.Pbkdf2("123456", "123456")
	nonceHex := hex.EncodeToString([]byte("12345678"))
	cipherText, err := crypto.EncryptAes(plainText, passwordHex, nonceHex)
	if err != nil {
		fmt.Println(err)
	}
	assertEqual(t, passwordHex, "1498cccb3cab5e895d6912d78aef6ab2")
	assertEqual(t, nonceHex, "3132333435363738")
	assertEqual(t, cipherText, "fd1ceaa8d7f03be768d410f07c017f3f7e62c8af6c9061cbaa0d")
}

func TestDecryptAes(t *testing.T) {
	crypto := New()
	cipherText := "fd1ceaa8d7f03be768d410f07c017f3f7e62c8af6c9061cbaa0d"
	passwordHex := crypto.Pbkdf2("123456", "123456")
	nonceHex := hex.EncodeToString([]byte("12345678"))
	plainText, err := crypto.DecryptAes(cipherText, passwordHex, nonceHex)
	if err != nil {
		fmt.Println(err)
	}
	assertEqual(t, plainText, "strongpass")
}
