package password

import "testing"

func TestBug5StrengthAtSixtyIsStrong(t *testing.T) {
	if got := Strength(60); got != "强" {
		t.Fatalf("Strength(60) = %q, want %q", got, "强")
	}
}
