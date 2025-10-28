package cryptus

import (
	"testing"
)

func TestPbkdf2(t *testing.T) {
	crypto := New()
	opts := NewKdfConfig(
		WithIterations(10000),
		WithLength(32),
	)

	salt := "1e3414eb437d1d9e"
	hash := crypto.Pbkdf2("strongpass", salt, opts)
	assertEqual(t, hash, "41be1253a55b95acf136bbeabce9facc05a5ac1cb2a9f4b5267eac38176aca4f")
}
