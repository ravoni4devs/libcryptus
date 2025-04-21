package cryptus

import "testing"

func assertEqual(t *testing.T, got, expected string) {
	if expected != got {
		t.Fatalf("\nExpected=\t%s\nGot=\t\t%s", expected, got)
	}
}
