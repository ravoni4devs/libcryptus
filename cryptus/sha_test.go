package cryptus

import "testing"

func TestSHA256Hex(t *testing.T) {
	c := New()

	sum := c.Sha256Hex("hello")
	// SHA-256("hello") = 2cf24dba5fb0a...
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if sum != want {
		t.Fatalf("Sha256Hex mismatch:\n got:  %s\n want: %s", sum, want)
	}
}
