package cryptus

import "testing"

func TestPbkdf2(t *testing.T) {
	crypto := New()
	opts := NewKdfConfig(
		WithIterations(10000),
	)
	hash := crypto.Pbkdf2("strongpass", "1234567812345678", opts)
	assertEqual(t, hash, "9b369f0254b8e21c0e4409af5e24b509")
}
