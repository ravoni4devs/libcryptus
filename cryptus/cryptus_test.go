package cryptus

import (
	"fmt"
	"testing"
)

func TestGenerateNonceHex(t *testing.T) {
	salt := New().GenerateNonceString(12)
	fmt.Println(salt)
	assertEqual(t, len(salt), 16)
}

func assertEqual(t *testing.T, got, expected any) {
	if expected != got {
		t.Fatalf("\nExpected=\t%s\nGot=\t\t%s", expected, got)
	}
}
