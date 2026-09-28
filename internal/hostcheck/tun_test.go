package hostcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"routeproxy/internal/config"
)

func TestNoWarnWithoutWireGuard(t *testing.T) {
	if w := WireGuardWarnings(&config.Config{}); len(w) != 0 {
		t.Fatalf("%v", w)
	}
}

func TestWarnWhenTunMissing(t *testing.T) {
	oldTun, oldSt := tunDevice, statusFile
	t.Cleanup(func() { tunDevice, statusFile = oldTun, oldSt })
	dir := t.TempDir()
	tunDevice = filepath.Join(dir, "no-tun")
	statusFile = filepath.Join(dir, "status")
	if err := os.WriteFile(statusFile, []byte("CapEff:\t0000000000000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	en := true
	cfg := &config.Config{Proxies: []config.Proxy{{Name: "wg", Type: "wireguard", Enabled: &en}}}
	w := WireGuardWarnings(cfg)
	if len(w) < 2 {
		t.Fatalf("want tun+cap warnings, got %v", w)
	}
	joined := strings.Join(w, "\n")
	if !strings.Contains(joined, "modprobe tun") || !strings.Contains(joined, "CAP_NET_ADMIN") {
		t.Fatal(joined)
	}
	if !strings.Contains(joined, "Чекеру") {
		t.Fatal("expected checker note")
	}
	if !strings.Contains(joined, "--privileged не требуется") {
		t.Fatal(joined)
	}
}

func TestCapEffBit(t *testing.T) {
	oldSt := statusFile
	t.Cleanup(func() { statusFile = oldSt })
	dir := t.TempDir()
	statusFile = filepath.Join(dir, "status")
	// bit 12 set: 0x1000
	if err := os.WriteFile(statusFile, []byte("CapEff:\t0000000000001000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ok, err := hasCapNetAdmin()
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}
