package idna_test

import (
	"strings"
	"testing"

	"routeproxy/internal/idna"
)

func TestToASCIIPunycode(t *testing.T) {
	ascii, err := idna.ToASCII("пример.рф")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ascii, "xn--") || !strings.HasSuffix(ascii, ".xn--p1ai") {
		t.Fatalf("%q", ascii)
	}
}
