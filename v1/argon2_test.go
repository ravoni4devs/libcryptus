package cryptus

import "testing"

func TestArgon2(t *testing.T) {
	crypto := New()
	hash16bits := crypto.Argon2("strongpass", "1234567812345678")
	assertEqual(t, hash16bits, "6ba6432460a5a8ae")

	opts := NewKdfConfig(
		WithLength(32),
	)
	hash32bits := crypto.Argon2("strongpass", "1234567812345678", opts)
	assertEqual(t, hash32bits, "05f0bc661b67a007dbb3eea521b58edc")
}
