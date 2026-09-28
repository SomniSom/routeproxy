package generate_test

import (
	"os"
	"path/filepath"
	"testing"

	"routeproxy/internal/generate"
)

func TestParseWGQuick(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Sweden.conf")
	body := `[Interface]
PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
Address = 10.8.0.2/32, fd00::2/128
MTU = 1280
# comment
[Peer]
PublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=
PresharedKey = ccccccccccccccccccccccccccccccccccccccccccc=
Endpoint = wg.example.com:51820
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	q, err := generate.ParseWGQuick(path)
	if err != nil {
		t.Fatal(err)
	}
	if q.PrivateKey == "" || q.PublicKey == "" || q.Endpoint != "wg.example.com:51820" || q.MTU != 1280 {
		t.Fatalf("%+v", q)
	}
	if len(q.Address) != 2 || q.PresharedKey == "" {
		t.Fatalf("addrs %+v psk %q", q.Address, q.PresharedKey)
	}
}

func TestParseWGQuickMissing(t *testing.T) {
	if _, err := generate.ParseWGQuick(filepath.Join(t.TempDir(), "nope.conf")); err == nil {
		t.Fatal("expected error")
	}
}
